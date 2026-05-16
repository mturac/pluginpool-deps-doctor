#!/usr/bin/env python3
"""Run dependency health audits across supported ecosystems."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"low": 0, "moderate": 1, "medium": 1, "high": 2, "critical": 3}
COMMANDS = {
    "npm": ["npm", "audit", "--json"],
    "pip": ["pip-audit", "--format=json"],
    "cargo": ["cargo", "audit", "--json"],
    "go": ["govulncheck", "-json", "./..."],
}


_MARKERS = {
    "npm": ("package.json",),
    "pip": ("requirements.txt", "pyproject.toml"),
    "cargo": ("Cargo.toml",),
    "go": ("go.mod",),
}

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "target", "dist", "build",
    "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
})


def detect_ecosystems(root: Path = Path("."), *, recursive: bool = False,
                       max_depth: int = 3) -> list[str]:
    """Detect ecosystem marker files. When ``recursive`` is true, descend up
    to ``max_depth`` levels under ``root`` so monorepos with ``/frontend``,
    ``/backend`` subdirectories surface every nested ecosystem.

    Order of returned names is stable: npm, pip, cargo, go.
    """
    found: set[str] = set()

    def _scan(path: Path, depth: int) -> None:
        try:
            entries = list(path.iterdir())
        except (OSError, PermissionError):
            return
        for entry in entries:
            if entry.is_file():
                for eco, markers in _MARKERS.items():
                    if entry.name in markers:
                        found.add(eco)
            elif recursive and entry.is_dir() and entry.name not in _SKIP_DIRS and depth < max_depth:
                _scan(entry, depth + 1)

    _scan(root, 0)
    return [eco for eco in _MARKERS if eco in found]


def run_audit(name: str) -> tuple[str | None, str | None]:
    command = COMMANDS[name]
    if shutil.which(command[0]) is None:
        return None, "skipped: tool not installed"
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.stdout:
        return result.stdout, None
    if result.returncode != 0:
        return None, result.stderr.strip() or f"{name} audit failed"
    return "{}", None


def normalize_severity(value: Any) -> str:
    text = str(value or "unknown").lower()
    return "moderate" if text == "medium" else text


def fixed_in(value: Any) -> list[str]:
    if value in (None, False):
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, dict):
        version = value.get("version")
        if version:
            return [str(version)]
    return []


def npm_advisories(payload: dict[str, Any]) -> list[dict[str, Any]]:
    advisories: list[dict[str, Any]] = []
    for package, vuln in payload.get("vulnerabilities", {}).items():
        via = vuln.get("via", [])
        source = next((item for item in via if isinstance(item, dict)), {})
        advisories.append({
            "id": str(source.get("source") or source.get("url") or vuln.get("name") or package),
            "severity": normalize_severity(vuln.get("severity") or source.get("severity")),
            "package": package,
            "version": ",".join(vuln.get("nodes", [])) or "",
            "fixed_in": fixed_in(vuln.get("fixAvailable")),
        })
    for advisory in payload.get("advisories", {}).values():
        advisories.append({
            "id": str(advisory.get("id") or advisory.get("url") or advisory.get("module_name")),
            "severity": normalize_severity(advisory.get("severity")),
            "package": advisory.get("module_name", ""),
            "version": advisory.get("vulnerable_versions", ""),
            "fixed_in": fixed_in(advisory.get("patched_versions")),
        })
    return advisories


def pip_advisories(payload: dict[str, Any]) -> list[dict[str, Any]]:
    advisories: list[dict[str, Any]] = []
    for dep in payload.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            advisories.append({
                "id": str(vuln.get("id") or vuln.get("aliases", [""])[0]),
                "severity": normalize_severity(vuln.get("severity")),
                "package": dep.get("name", ""),
                "version": dep.get("version", ""),
                "fixed_in": fixed_in(vuln.get("fix_versions")),
            })
    return advisories


def cargo_advisories(payload: dict[str, Any]) -> list[dict[str, Any]]:
    advisories: list[dict[str, Any]] = []
    for item in payload.get("vulnerabilities", {}).get("list", []):
        advisory = item.get("advisory", {})
        package = item.get("package", {})
        versions = item.get("versions", {})
        advisories.append({
            "id": str(advisory.get("id", "")),
            "severity": normalize_severity(advisory.get("severity")),
            "package": package.get("name", ""),
            "version": package.get("version", ""),
            "fixed_in": fixed_in(versions.get("patched")),
        })
    return advisories


def _osv_fixed_versions(affected: Any) -> list[str]:
    """Extract patched version strings from an OSV ``affected`` block.

    govulncheck's payload nests them under ``ranges[].events[].fixed``. The
    earlier ``fixed_in()`` helper just stringified the whole list, which is
    useless to the operator. Returns sorted unique semver strings.
    """
    out: set[str] = set()
    if not isinstance(affected, list):
        return []
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        for rng in entry.get("ranges", []) or []:
            for event in (rng or {}).get("events", []) or []:
                if isinstance(event, dict) and event.get("fixed"):
                    out.add(str(event["fixed"]))
    return sorted(out)


def go_advisories(output: str) -> list[dict[str, Any]]:
    advisories: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        finding = event.get("finding") or event.get("vulnerability") or {}
        osv = finding.get("osv") or finding
        if not osv:
            continue
        # Walk the OSV ``affected`` ranges to pull the real ``fixed`` strings
        # (e.g. ``0.0.0-20231228152506-xxx``) instead of leaking the raw dict.
        fixed = _osv_fixed_versions(osv.get("affected", []))
        # ``finding.trace`` (when present) often points to the offending package
        # version that triggered the alert — surface that as ``version`` so the
        # operator does not see an empty cell.
        trace = finding.get("trace") or []
        package = finding.get("package") or ""
        version = ""
        if isinstance(trace, list) and trace:
            first = trace[0]
            if isinstance(first, dict):
                package = package or first.get("module") or first.get("package") or ""
                version = str(first.get("version") or "")
        advisories.append({
            "id": str(osv.get("id", "")),
            "severity": normalize_severity(osv.get("database_specific", {}).get("severity")),
            "package": package,
            "version": version,
            "fixed_in": fixed,
        })
    return advisories


class ParseFailed(Exception):
    """Raised when an audit tool emitted output that we could not parse.

    Surfacing this explicitly is the difference between a real "no advisories"
    result and a silent failure — we never want a misformatted error blob to
    be reported as a clean repository.
    """


def parse_advisories(name: str, output: str) -> list[dict[str, Any]]:
    """Parse ``output`` produced by ``name``'s audit command into advisories.

    Raises ``ParseFailed`` when the tool produced non-empty output that does
    not parse as the expected format. The audit function catches that and
    surfaces it on the per-ecosystem record so the run is not "silently
    green" (review finding).
    """
    if name == "go":
        return go_advisories(output)
    if not output.strip():
        return []
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ParseFailed(f"{name} audit produced non-JSON output ({exc})") from exc
    if name == "npm":
        return npm_advisories(payload)
    if name == "pip":
        return pip_advisories(payload)
    if name == "cargo":
        return cargo_advisories(payload)
    return []


def severity_allowed(advisory: dict[str, Any], minimum: str) -> bool:
    return SEVERITY_ORDER.get(advisory.get("severity", "unknown"), -1) >= SEVERITY_ORDER[minimum]


def audit(ecosystems: list[str], minimum: str = "low") -> dict[str, list[dict[str, Any]]]:
    results: list[dict[str, Any]] = []
    for name in ecosystems:
        output, skipped = run_audit(name)
        if output is None:
            advisories: list[dict[str, Any]] = []
            parse_error: str | None = None
        else:
            try:
                parsed = parse_advisories(name, output)
            except ParseFailed as exc:
                advisories, parse_error = [], str(exc)
            else:
                advisories = [item for item in parsed if severity_allowed(item, minimum)]
                parse_error = None
        record: dict[str, Any] = {
            "name": name,
            "advisories": advisories,
            "outdated_count": 0,
            "license_warnings": [],
        }
        if skipped:
            record["skipped"] = skipped
        if parse_error:
            record["parse_error"] = parse_error
        results.append(record)
    return {"ecosystems": results}


def markdown(result: dict[str, list[dict[str, Any]]]) -> str:
    grouped: dict[str, list[tuple[str, dict[str, Any]]]] = {key: [] for key in ("critical", "high", "moderate", "low", "unknown")}
    skipped: list[str] = []
    for eco in result["ecosystems"]:
        if eco.get("skipped"):
            skipped.append(f"- {eco['name']}: {eco['skipped']}")
        for advisory in eco["advisories"]:
            grouped.setdefault(advisory.get("severity", "unknown"), []).append((eco["name"], advisory))

    lines = ["# Dependency Doctor"]
    for severity in ("critical", "high", "moderate", "low", "unknown"):
        items = grouped.get(severity, [])
        if not items:
            continue
        lines.extend([f"## {severity.title()}", "| Ecosystem | ID | Package | Version | Fixed In |", "| --- | --- | --- | --- | --- |"])
        for ecosystem, advisory in items:
            lines.append(
                f"| {ecosystem} | {advisory['id']} | {advisory['package']} | "
                f"{advisory['version']} | {','.join(advisory['fixed_in']) or '-'} |"
            )
    if skipped:
        lines.append("## Skipped")
        lines.extend(skipped)
    if len(lines) == 1:
        lines.append("No advisories found.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run dependency health audits across ecosystems.")
    parser.add_argument("--format", choices=("json", "md"), default="json")
    parser.add_argument("--severity", choices=("low", "moderate", "high", "critical"), default="low")
    parser.add_argument("--ecosystem", help="Comma-separated ecosystem filter, e.g. npm,pip.")
    parser.add_argument("--recursive", action="store_true",
                        help="Recurse into subdirectories to find ecosystem marker files.")
    parser.add_argument("--max-depth", type=int, default=3,
                        help="Maximum directory depth when --recursive is set.")
    args = parser.parse_args(argv)

    detected = detect_ecosystems(recursive=args.recursive, max_depth=args.max_depth)
    if args.ecosystem:
        allowed = {item.strip() for item in args.ecosystem.split(",") if item.strip()}
        detected = [item for item in detected if item in allowed]
    result = audit(detected, args.severity)
    print(markdown(result) if args.format == "md" else json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
