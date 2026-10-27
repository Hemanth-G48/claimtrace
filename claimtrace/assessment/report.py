# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic human-readable report rendering."""
from __future__ import annotations

import hashlib
from typing import Any


def report_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def render(assessment: dict[str, Any], decisions: list[dict[str, Any]], revision: int | None = None) -> str:
    if revision is None:
        revision = max((int(d.get("decision_revision", 0)) for d in decisions), default=0)
    selected = sorted(
        [d for d in decisions if int(d.get("decision_revision", 0)) <= revision],
        key=lambda d: int(d.get("decision_revision", 0)),
    )
    result = assessment.get("package_result", "insufficient")
    qualifier = assessment.get("package_qualifier")
    headline = result + (f" ({qualifier})" if qualifier else "")
    out: list[str] = [
        "# ClaimTrace assessment",
        "",
        f"Result: {headline}",
        f"Assessment: {assessment.get('assessment_id')}",
        f"Assessment hash: {assessment.get('assessment_hash')}",
        f"Report identity: ({assessment.get('assessment_hash')}, {revision})",
        "",
        "## Input",
        "",
    ]
    inp = assessment.get("input", {})
    for key in ("target", "kind", "package", "version", "artifact_path", "artifact_digest"):
        if inp.get(key):
            out.append(f"- {key}: {inp[key]}")
    out += ["", "## Claims", ""]
    claims = assessment.get("claims", [])
    if not assessment.get("claims_available", False):
        out.append("Claims unavailable: no README was found; this is not proof of a contradiction.")
    elif not claims:
        out.append("No explicit claims extracted.")
    for c in claims:
        out.append(f"- {c.get('claim_id')} [{c.get('source')}] {c.get('text')}")
        if c.get("ambiguity"):
            out.append(f"  ambiguity: {c['ambiguity']}")

    out += ["", "## Observations", ""]
    observations = assessment.get("observations", [])
    if not observations:
        out.append("No observations in the supported capture vocabulary.")
    for o in observations:
        out.append(
            f"- {o.get('observation_id')} {o.get('term')} phase={o.get('phase')} "
            f"sensitive={str(o.get('sensitive')).lower()} outcome={o.get('outcome')}"
        )
        if o.get("resource"):
            out.append(f"  resource: {o['resource']}")
        if o.get("destination"):
            out.append(f"  destination: {o['destination']}")
        out.append(
            f"  raw_event_id: {o.get('raw_event_id')} raw_ref: {o.get('raw_ref')} "
            f"evidence_integrity: {o.get('evidence_integrity')}"
        )
        out.append(f"  reason: {o.get('reason')}")
        if o.get("claim_ref"):
            out.append(f"  claim_ref: {o['claim_ref']}")

    out += ["", "## Coverage", ""]
    cov = assessment.get("coverage", {})
    for key in ("level", "capture_mode", "telemetry_level", "egress", "dns_mode", "sinkhole_mode", "sinkhole_ports", "capture_health", "capture_profile_hash",
                "captured_paths", "decoy_set_hash", "settle_window_seconds", "install_mode"):
        if cov.get(key) is not None:
            out.append(f"- {key}: {cov[key]}")
    out.append("- phases:")
    for phase, state in sorted((cov.get("phases") or {}).items()):
        if isinstance(state, dict):
            out.append(
                f"  - {phase}: status={state.get('status')} exit_code={state.get('exit_code')} "
                f"timed_out={state.get('timed_out')}"
            )
        else:
            out.append(f"  - {phase}: {state}")
    ev = assessment.get("evidence_integrity", {})
    out.append(f"- evidence_integrity: {ev.get('status')}")
    if ev.get("missing_raw_event_ids"):
        out.append(f"- missing_raw_event_ids: {', '.join(ev['missing_raw_event_ids'])}")
    if ev.get("capture_failures"):
        out.append(f"- capture_failures: {', '.join(ev['capture_failures'])}")
    refusal = assessment.get("preflight_refusal")
    if refusal:
        out += ["", "## Preflight refusal", ""]
        for key in ("failed_control", "effective_profile_hash", "profile_source", "reason"):
            if refusal.get(key):
                out.append(f"- {key}: {refusal[key]}")
        if refusal.get("effective_profile"):
            out.append(f"- effective_profile: {refusal['effective_profile']}")

    out += ["", "## Package rule", "", assessment.get("package_rule", "")]
    if qualifier:
        out.append("")
        out.append("Coverage is unverified: absence of an observation is not proof of clean behavior.")
    out += ["", "## Human decision", ""]
    if not selected:
        out.append("No human decision recorded.")
    else:
        for d in selected:
            out.append(
                f"- revision {d.get('decision_revision')} ({d.get('decision_id')}): "
                f"{d.get('decision')} by {d.get('author')} at {d.get('timestamp')}"
            )
            if d.get("reason"):
                out.append(f"  reason: {d['reason']}")
            if d.get("acknowledged_sensitive"):
                out.append(f"  acknowledged: {', '.join(d['acknowledged_sensitive'])}")
    out.append("")
    return "\n".join(out)
