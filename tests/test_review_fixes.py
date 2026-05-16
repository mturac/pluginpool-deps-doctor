"""Regression tests for deps-doctor review findings."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "scripts"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import doctor  # noqa: E402


def test_recursive_detection_finds_subdirectory_ecosystems(tmp_path):
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text("{}")
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "pyproject.toml").write_text("")
    (tmp_path / "service").mkdir()
    (tmp_path / "service" / "go.mod").write_text("module x\n")
    found = doctor.detect_ecosystems(tmp_path, recursive=True)
    assert set(found) == {"npm", "pip", "go"}


def test_non_recursive_only_scans_root(tmp_path):
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text("{}")
    found = doctor.detect_ecosystems(tmp_path, recursive=False)
    assert found == []


def test_parse_failure_is_surfaced_not_silenced():
    """A tool emitting non-JSON output must trigger ParseFailed, not an
    empty advisories list (which would look like a clean repo)."""
    import pytest
    with pytest.raises(doctor.ParseFailed):
        doctor.parse_advisories("npm", "this is not json at all")


def test_audit_records_parse_error_field(monkeypatch):
    """audit() must report ``parse_error`` so downstream layers can refuse
    to consider the result green."""
    def fake_run(name):
        return "garbage non-json output", None

    monkeypatch.setattr(doctor, "run_audit", fake_run)
    out = doctor.audit(["npm"])
    npm = out["ecosystems"][0]
    assert npm["advisories"] == []
    assert "parse_error" in npm
    assert "non-JSON" in npm["parse_error"]


def test_go_fixed_in_extracts_real_versions():
    """govulncheck OSV payload nests fixed versions under ranges/events/fixed.
    The parser must walk that structure, not stringify the dict."""
    line = json.dumps({
        "finding": {
            "osv": {
                "id": "GO-2024-12345",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "ranges": [
                            {"events": [{"introduced": "0.0.0"}, {"fixed": "1.2.3"}]},
                        ],
                    }
                ],
            },
            "trace": [{"module": "github.com/x/y", "version": "1.0.0", "package": "github.com/x/y/sub"}],
        }
    })
    out = doctor.go_advisories(line + "\n")
    assert len(out) == 1
    assert out[0]["fixed_in"] == ["1.2.3"]
    assert out[0]["id"] == "GO-2024-12345"
    assert out[0]["version"] == "1.0.0"


def test_empty_output_is_not_a_parse_failure():
    assert doctor.parse_advisories("npm", "") == []
    assert doctor.parse_advisories("npm", "   \n  ") == []
