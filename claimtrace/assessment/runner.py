# SPDX-License-Identifier: AGPL-3.0-or-later
"""Stage 0 orchestration: local artifact -> API -> assessment -> canonical store."""
from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path
from typing import Any

from claimtrace import detonation_staging
from claimtrace.assessment import claims as claims_mod
from claimtrace.assessment import classify, store
from claimtrace.detonate.client import DetonationClient

SCHEMA_VERSION = "assessment-1"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _stage_local(path: Path) -> tuple[Path, str]:
    digest = _sha256_file(path)
    staged = detonation_staging.stage_bytes(path.read_bytes(), path.name, prefix="assess-")
    return staged, digest


def resolve_coordinate(target: str) -> tuple[Path, str, str]:
    """Resolve name@version once in the CLI, never in the API.

    Registry resolution is intentionally explicit and optional; local artifacts
    are the reproducible path used by the demo.
    """
    m = re.fullmatch(r"(?P<name>(?:@[^/@]+/)?[^@]+)@(?P<version>[^@]+)", target)
    if not m:
        raise ValueError("target must be a local artifact or name@version")
    name, version = m.group("name"), m.group("version")
    import subprocess
    import tempfile
    work = Path(tempfile.mkdtemp(prefix="claimtrace-pack-"))
    try:
        proc = subprocess.run(
            ["npm", "pack", f"{name}@{version}", "--pack-destination", str(work),
             "--ignore-scripts", "--no-audit", "--no-fund"],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"name@version resolution failed: {e}") from e
    if proc.returncode != 0:
        raise RuntimeError(f"npm pack failed: {proc.stderr.strip()[:500]}")
    archives = sorted(work.glob("*.tgz"))
    if len(archives) != 1:
        raise RuntimeError("npm pack did not produce exactly one archive")
    return archives[0], name, version


def _coverage_from_api(api: dict[str, Any], phases: dict[str, Any]) -> dict[str, Any]:
    cov = dict(api.get("coverage") or {})
    cov.setdefault("phases", phases)
    cov.setdefault("capture_mode", "ptrace")
    cov.setdefault("telemetry_level", "unverified")
    cov.setdefault("egress", "recording_sinkhole")
    cov.setdefault("dns_mode", "fake_nonforwarding")
    cov.setdefault("sinkhole_mode", "tcp_accept_common_ports")
    cov.setdefault("sinkhole_ports", [80, 443, 8080, 8443])
    cov.setdefault("settle_window_seconds", 10)
    cov.setdefault("install_mode", "controlled")
    cov.setdefault("captured_paths", [])
    cov.setdefault("capture_profile_hash", None)
    cov.setdefault("decoy_set_hash", None)
    level = cov.get("level")
    if level not in ("complete", "unverified", "incomplete"):
        failed = any(
            isinstance(v, dict) and v.get("status") in ("failed", "timed_out", "requested_not_started")
            for v in phases.values()
        )
        cov["level"] = "incomplete" if failed else "unverified"
    return cov


def assess(
    target: str,
    *,
    ecosystem: str = "npm",
    client: DetonationClient | None = None,
    timeout_seconds: int = 180,
    fault_drop_raw: str | None = None,
    fault_independent: bool = False,
) -> dict[str, Any]:
    if ecosystem not in ("npm",):
        raise ValueError("Milestone 2 assessment supports npm artifacts only")

    local = Path(target).expanduser()
    if local.exists():
        if not local.is_file():
            raise ValueError(f"target is not a regular package artifact: {target}")
        archive = local.resolve()
        digest = _sha256_file(archive)
        staged, digest = _stage_local(archive)
        kind = "local"
    else:
        try:
            archive, _, _ = resolve_coordinate(target)
        except ValueError as e:
            raise FileNotFoundError(f"local artifact not found: {target}") from e
        digest = _sha256_file(archive)
        staged, digest = _stage_local(archive)
        kind = "coordinate"

    pkg = claims_mod.read_package_info(staged)
    claim_list, claims_available = claims_mod.extract_claims(pkg)
    api_client = client or DetonationClient()
    result = api_client.assess_local_sync(
        ecosystem=ecosystem,
        name=pkg.name,
        version=pkg.version,
        archive_path=str(staged),
        archive_kind="npm",
        timeout_seconds=timeout_seconds,
        fault_drop_raw=fault_drop_raw,
        fault_independent=fault_independent,
    )

    raw = result.raw_events
    evidence = dict(result.evidence_integrity or {})
    missing = list(evidence.get("missing_raw_event_ids") or [])
    # An API-created unresolved reference is still an observation even when its
    # raw payload is missing; retain the ID and mark integrity failure.
    missing = [m for m in missing if m]
    independent = list(evidence.get("independent_evidence_ids") or [])
    coverage = _coverage_from_api(
        {"coverage": result.coverage, "phases": result.phases},
        result.phases,
    )
    if evidence.get("status") == "failed":
        coverage["level"] = "incomplete"

    observations = classify.normalize_observations(
        raw,
        claims=claim_list,
        claims_available=claims_available,
        coverage_level=str(coverage.get("level") or "unverified"),
        missing_raw_ids=missing,
        independent_evidence_ids=independent,
    )
    pkg_result, qualifier, rule = classify.package_result(
        observations,
        claims_available=claims_available,
        coverage_level=str(coverage.get("level") or "unverified"),
        evidence_integrity_failed=evidence.get("status") == "failed",
    )
    if result.status == "refused":
        pkg_result, qualifier, rule = "insufficient", None, "preflight refusal: no package execution"
        coverage["level"] = "incomplete"
        observations = []
    elif result.status != "completed":
        # An API error/timeout is not an assessment. Do not let an empty raw
        # event list turn into "no mismatch found"; preserve the failure and
        # require a human to investigate.
        pkg_result, qualifier, rule = "insufficient", None, f"API did not complete: {result.status}" + (f": {result.error}" if result.error else "")
        coverage["level"] = "incomplete"
        observations = []
        evidence["status"] = "failed"
        evidence["api_status"] = result.status

    aid = "asm-" + uuid.uuid4().hex
    assessment: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "assessment_id": aid,
        "input": {
            "target": target,
            "kind": kind,
            "package": pkg.name,
            "version": pkg.version,
            "artifact_path": str(staged),
            "artifact_digest": digest,
        },
        "package": {"name": pkg.name, "version": pkg.version},
        "claims_available": claims_available,
        "claims": [c.to_dict() for c in claim_list],
        "observations": [o.to_dict() for o in observations],
        "coverage": coverage,
        "evidence_integrity": {
            "status": evidence.get("status", "ok"),
            "missing_raw_event_ids": missing,
            "capture_failures": evidence.get("capture_failures", []),
            "independent_evidence_ids": evidence.get("independent_evidence_ids", []),
        },
        "preflight": result.preflight,
        "preflight_refusal": (
            {
                "failed_control": (result.preflight or {}).get("failed_control"),
                "effective_profile": (result.preflight or {}).get("effective_profile"),
                "effective_profile_hash": (result.preflight or {}).get("effective_profile_hash"),
                "profile_source": (result.preflight or {}).get("profile_source"),
                "reason": (result.preflight or {}).get("reason"),
            }
            if result.status == "refused" else None
        ),
        "package_result": pkg_result,
        "package_qualifier": qualifier,
        "package_rule": rule,
        "api_status": result.status,
        "api_error": result.error,
        "classification_rules_version": classify.CLASSIFICATION_VERSION,
        "extractor_version": claims_mod.EXTRACTOR_VERSION,
        "normalizer_version": classify.NORMALIZER_VERSION,
        "vocabulary_version": classify.VOCABULARY_VERSION,
        "sensitive_list_version": classify.SENSITIVE_LIST_VERSION,
        "sandbox_profile_hash": coverage.get("capture_profile_hash"),
        "decoy_set_hash": coverage.get("decoy_set_hash"),
    }
    return store.save(assessment, raw)
