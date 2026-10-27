# SPDX-License-Identifier: AGPL-3.0-or-later
"""Canonical assessment storage and append-only human decisions."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STORE_VERSION = "assessment-store-1"


def store_root() -> Path:
    return Path(os.environ.get("CLAIMTRACE_ASSESSMENT_DIR", str(Path.home() / ".claimtrace" / "assessments")))


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_hash(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode()).hexdigest()


def _path(assessment_id: str) -> Path:
    return store_root() / f"{assessment_id}.json"


def _raw_path(assessment_id: str) -> Path:
    return store_root() / f"{assessment_id}.raw.json"


def _decision_path(assessment_id: str) -> Path:
    return store_root() / f"{assessment_id}.decisions.jsonl"


def save(assessment: dict[str, Any], raw_events: list[dict[str, Any]]) -> dict[str, Any]:
    store_root().mkdir(parents=True, exist_ok=True)
    aid = str(assessment["assessment_id"])
    # Hash excludes the convenience hash field itself.
    body = {k: v for k, v in assessment.items() if k != "assessment_hash"}
    digest = canonical_hash(body)
    stored = dict(body)
    stored["assessment_hash"] = digest
    _path(aid).write_text(canonical_json(stored) + "\n", encoding="utf-8")
    _raw_path(aid).write_text(canonical_json(raw_events) + "\n", encoding="utf-8")
    return stored


def load(assessment_id: str) -> dict[str, Any]:
    p = _path(assessment_id)
    if not p.exists():
        raise FileNotFoundError(f"assessment not found: {assessment_id}")
    return json.loads(p.read_text(encoding="utf-8"))


def raw_events(assessment_id: str) -> list[dict[str, Any]]:
    p = _raw_path(assessment_id)
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding="utf-8"))


def load_decisions(assessment_id: str) -> list[dict[str, Any]]:
    p = _decision_path(assessment_id)
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def append_decision(
    assessment: dict[str, Any],
    *,
    decision: str,
    reason: str,
    author: str,
    acknowledged: list[str],
) -> dict[str, Any]:
    if decision not in ("accept", "investigate", "reject"):
        raise ValueError("decision must be accept, investigate, or reject")
    declared = {
        o["observation_id"] for o in assessment.get("observations", [])
        if o.get("outcome") == "declared-sensitive"
    }
    acked = set(acknowledged)
    missing = sorted(declared - acked)
    if decision == "accept" and missing:
        raise PermissionError("unacknowledged declared-sensitive observations: " + ", ".join(missing))
    if decision == "accept" and not reason.strip():
        raise ValueError("accept requires a reason")

    decisions = load_decisions(str(assessment["assessment_id"]))
    revision = max((int(d.get("decision_revision", 0)) for d in decisions), default=0) + 1
    record = {
        "decision_id": "dec-" + uuid.uuid4().hex,
        "decision_revision": revision,
        "assessment_id": assessment["assessment_id"],
        "assessment_hash": assessment.get("assessment_hash"),
        "decision": decision,
        "reason": reason,
        "author": author,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "acknowledged_sensitive": sorted(acked),
    }
    p = _decision_path(str(assessment["assessment_id"]))
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(canonical_json(record) + "\n")
    return record
