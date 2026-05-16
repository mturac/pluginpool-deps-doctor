import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import doctor


def test_ecosystem_detection(tmp_path):
    for name in ("package.json", "requirements.txt", "Cargo.toml", "go.mod"):
        (tmp_path / name).write_text("", encoding="utf-8")
    assert doctor.detect_ecosystems(tmp_path) == ["npm", "pip", "cargo", "go"]


def test_missing_tool_is_graceful(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda _: None)
    output, skipped = doctor.run_audit("npm")
    assert output is None
    assert skipped == "skipped: tool not installed"


def test_npm_audit_json_parser():
    payload = {
        "vulnerabilities": {
            "left-pad": {
                "name": "left-pad",
                "severity": "high",
                "nodes": ["node_modules/left-pad"],
                "fixAvailable": {"version": "1.3.1"},
                "via": [{"source": 123, "severity": "high"}],
            }
        }
    }
    assert doctor.npm_advisories(payload) == [{
        "id": "123",
        "severity": "high",
        "package": "left-pad",
        "version": "node_modules/left-pad",
        "fixed_in": ["1.3.1"],
    }]


def test_severity_filter(monkeypatch):
    monkeypatch.setattr(doctor, "run_audit", lambda name: (json.dumps({
        "vulnerabilities": {
            "a": {"severity": "low", "via": [], "nodes": [], "fixAvailable": False},
            "b": {"severity": "critical", "via": [], "nodes": [], "fixAvailable": False},
        }
    }), None))
    result = doctor.audit(["npm"], "high")
    assert [item["package"] for item in result["ecosystems"][0]["advisories"]] == ["b"]


def test_markdown_rendering_groups_by_severity():
    rendered = doctor.markdown({
        "ecosystems": [{
            "name": "npm",
            "advisories": [{"id": "A", "severity": "critical", "package": "pkg", "version": "1", "fixed_in": ["2"]}],
            "outdated_count": 0,
            "license_warnings": [],
        }]
    })
    assert "## Critical" in rendered
    assert "| npm | A | pkg | 1 | 2 |" in rendered


def test_ecosystem_constraint(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    detected = doctor.detect_ecosystems()
    selected = [item for item in detected if item in {"pip"}]
    assert selected == ["pip"]


def test_missing_tool_appears_in_markdown(monkeypatch):
    monkeypatch.setattr(doctor, "run_audit", lambda name: (None, "skipped: tool not installed"))
    rendered = doctor.markdown(doctor.audit(["pip"], "low"))
    assert "## Skipped" in rendered
    assert "pip: skipped: tool not installed" in rendered


def test_go_govulncheck_ndjson_parser_via_route():
    """govulncheck emits NDJSON (one JSON object per line). parse_advisories must
    route 'go' to the line-aware parser BEFORE attempting json.loads on the blob."""
    ndjson = "\n".join([
        '{"finding": {"osv": {"id": "GO-2024-0001", "database_specific": {"severity": "high"}}, "package": "golang.org/x/net"}}',
        '{"progress": {"message": "scanning"}}',
        '{"finding": {"osv": {"id": "GO-2024-0002", "database_specific": {"severity": "moderate"}}, "package": "rsc.io/x"}}',
    ])
    result = doctor.parse_advisories("go", ndjson)
    ids = sorted(a["id"] for a in result)
    assert ids == ["GO-2024-0001", "GO-2024-0002"]
    sevs = {a["package"]: a["severity"] for a in result}
    assert sevs["golang.org/x/net"] == "high"
