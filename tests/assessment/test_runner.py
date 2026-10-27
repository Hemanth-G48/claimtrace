# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from claimtrace import detonation_staging
from claimtrace.assessment import runner, store
from claimtrace.detonate.client import LocalAssessmentResult


class FakeClient:
    def __init__(self, *, independent: bool):
        self.independent = independent

    def assess_local_sync(self, **kwargs):
        ev = {"status": "failed", "missing_raw_event_ids": ["r1"]}
        if self.independent:
            ev["independent_evidence_ids"] = ["r1"]
        return LocalAssessmentResult(
            status="completed",
            request=kwargs,
            phases={"install": {"status": "started_completed"}, "entry": {"status": "failed"},
                    "import": {"status": "started_completed"}},
            raw_events=[{
                "raw_event_id": "r1", "phase": "entry", "category": "file", "operation": "open",
                "detail": {"path": "/root/.ssh/id_rsa"},
            }],
            findings_json=[],
            coverage={"level": "incomplete", "capture_mode": "ptrace", "phases": {
                "install": {"status": "started_completed"}, "entry": {"status": "failed"},
                "import": {"status": "started_completed"},
            }},
            evidence_integrity=ev,
            preflight={"status": "ok"},
        )


def _archive(tmp_path: Path) -> Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in {
            "package/package.json": json.dumps({"name": "fixture", "version": "1.0.0"}),
            "package/README.md": "# fixture\nA tiny formatting utility.\n",
            "package/index.js": "module.exports = 1;\n",
        }.items():
            raw = data.encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tf.addfile(info, io.BytesIO(raw))
    p = tmp_path / "fixture-1.0.0.tgz"
    p.write_bytes(buf.getvalue())
    return p


def test_missing_raw_without_independent_evidence_is_insufficient(tmp_path, monkeypatch):
    monkeypatch.setattr(detonation_staging, "STAGING_ROOT", tmp_path / "staging")
    monkeypatch.setattr(store, "store_root", lambda: tmp_path / "store")
    a = runner.assess(str(_archive(tmp_path)), client=FakeClient(independent=False))
    assert a["package_result"] == "insufficient"
    assert a["observations"][0]["evidence_integrity"] == "failed"
    assert a["evidence_integrity"]["status"] == "failed"


class FakeErrorClient:
    def assess_local_sync(self, **kwargs):
        return LocalAssessmentResult(
            status="error",
            request=kwargs,
            phases={"install": {"status": "started_completed"}},
            raw_events=[],
            findings_json=[],
            coverage={"level": "unverified", "phases": {"install": {"status": "started_completed"}}},
            evidence_integrity={"status": "ok", "missing_raw_event_ids": []},
            preflight={"status": "ok"},
            error="sandbox start failed",
        )


def test_api_error_is_insufficient_not_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(detonation_staging, "STAGING_ROOT", tmp_path / "staging")
    monkeypatch.setattr(store, "store_root", lambda: tmp_path / "store")
    a = runner.assess(str(_archive(tmp_path)), client=FakeErrorClient())
    assert a["package_result"] == "insufficient"
    assert a["coverage"]["level"] == "incomplete"
    assert a["evidence_integrity"]["status"] == "failed"
    assert a["api_error"] == "sandbox start failed"


def test_missing_raw_with_independent_evidence_can_remain_review(tmp_path, monkeypatch):
    monkeypatch.setattr(detonation_staging, "STAGING_ROOT", tmp_path / "staging")
    monkeypatch.setattr(store, "store_root", lambda: tmp_path / "store")
    a = runner.assess(str(_archive(tmp_path)), client=FakeClient(independent=True))
    assert a["package_result"] == "review: mismatch"
    assert a["observations"][0]["raw_ref"] is None


def test_missing_local_artifact_has_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="local artifact not found"):
        runner.assess(str(tmp_path / "does-not-exist.tgz"))


def test_directory_is_not_a_package_artifact(tmp_path):
    with pytest.raises(ValueError, match="not a regular package artifact"):
        runner.assess(str(tmp_path))
