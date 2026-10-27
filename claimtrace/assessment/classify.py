# SPDX-License-Identifier: AGPL-3.0-or-later
"""Normalize captured events and apply the architecture's assessment rules."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from claimtrace.assessment.claims import Claim

NORMALIZER_VERSION = "normalize-1"
CLASSIFICATION_VERSION = "classify-1"
VOCABULARY_VERSION = "vocab-1"
SENSITIVE_LIST_VERSION = "sensitive-1"

_SENSITIVE_PARTS = (
    "/.ssh/", "/.aws/", "/.npmrc", "/.pypirc", "/.netrc", "/.docker/config",
    "/.kube/config", "/.config/gcloud", "/.cargo/credentials", "/.env",
)
_PERSISTENCE_PARTS = (
    "/etc/cron", "/etc/systemd", "/.bashrc", "/.profile", "/.zshrc",
    "/.config/autostart", "/authorized_keys",
)
_DOWNLOADERS = ("curl", "wget", "nc", "ncat", "socat")
_SHELLS = ("sh", "bash", "dash", "zsh")
_TOOLCHAIN = ("node", "npm", "npx", "python", "python3", "pip", "cargo", "go", "make", "gcc")
_DOWNLOADER_RE = re.compile(r"(?:^|[\s/])(?:curl|wget|ncat|socat|nc)(?:\s|$)")


@dataclass
class Observation:
    observation_id: str
    term: str
    phase: str
    sensitive: bool
    resource: str | None
    destination: str | None
    process: str | None
    raw_event_id: str
    raw_ref: str | None
    evidence_integrity: str
    evidence_sufficient: bool
    outcome: str
    reason: str
    claim_ref: str | None
    filter_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sid(prefix: str, *parts: str) -> str:
    return prefix + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


def _basename(value: str) -> str:
    return value.rsplit("/", 1)[-1] if value else ""


def _is_sensitive_path(path: str) -> bool:
    p = path.replace("\\", "/")
    if any(part in p for part in _SENSITIVE_PARTS):
        return True
    return p.endswith("/id_rsa") or p.endswith("/id_ed25519")


def _is_persistence_path(path: str) -> bool:
    return any(part in path.replace("\\", "/") for part in _PERSISTENCE_PARTS)


def _claim_matches(claim: Claim, term: str, resource: str | None, destination: str | None) -> bool:
    if claim.resource and resource:
        r = resource.replace("\\", "/")
        c = claim.resource.replace("\\", "/").lstrip("~")
        if c and c in r:
            return True
    if claim.destination and destination:
        d = destination.lower().rstrip(".")
        c = claim.destination.lower().rstrip(".")
        if d == c or d.endswith("." + c):
            return True
    return term in claim.expected_capability


def _specific_claim(claim: Claim, term: str, resource: str | None, destination: str | None) -> bool:
    """A claim is specific only when it names the exact resource/host or capability."""
    if claim.resource and resource:
        c = claim.resource.replace("\\", "/").lstrip("~")
        if c and c in resource.replace("\\", "/"):
            return True
    if claim.destination and destination:
        d = destination.lower().rstrip(".")
        c = claim.destination.lower().rstrip(".")
        if d == c or d.endswith("." + c):
            return True
    return term in claim.expected_capability and not (claim.resource or claim.destination)


def _specific_sensitive(claim: Claim, resource: str | None, destination: str | None) -> bool:
    # Free-text capability mentions (e.g. a README heading containing "network")
    # cannot explain a sensitive observation. The claim must name the exact
    # resource or destination.
    if claim.resource and resource:
        c = claim.resource.replace("\\", "/").lstrip("~")
        if c and c in resource.replace("\\", "/"):
            return True
    if claim.destination and destination:
        d = destination.lower().rstrip(".")
        c = claim.destination.lower().rstrip(".")
        if d == c or d.endswith("." + c):
            return True
    return False


def _event_detail(raw: dict[str, Any]) -> dict[str, Any]:
    detail = raw.get("detail")
    return detail if isinstance(detail, dict) else {}


def normalize_observations(
    raw_events: Iterable[dict[str, Any]],
    *,
    claims: Iterable[Claim],
    claims_available: bool,
    coverage_level: str,
    missing_raw_ids: Iterable[str] = (),
    independent_evidence_ids: Iterable[str] = (),
) -> list[Observation]:
    """Turn raw events into the closed observation vocabulary.

    Events outside the captured capability vocabulary are retained raw but do not
    become observations; the report says general file tracking is unavailable.
    """
    claims = list(claims)
    missing = set(missing_raw_ids)
    independent = set(independent_evidence_ids)
    out: list[Observation] = []
    seen: set[tuple[str, str, str, str]] = set()

    for raw in raw_events:
        raw_id = str(raw.get("raw_event_id") or raw.get("raw_id") or "")
        if not raw_id:
            continue
        phase = str(raw.get("phase") or "unknown")
        category = str(raw.get("category") or "")
        operation = str(raw.get("operation") or "")
        detail = _event_detail(raw)
        term: str | None = None
        resource: str | None = None
        destination: str | None = None
        process: str | None = None

        if category == "process" and operation == "exec":
            binary = str(detail.get("binary") or "")
            base = _basename(binary)
            args = str(detail.get("arguments") or "")
            process = binary
            if base in _DOWNLOADERS or _DOWNLOADER_RE.search(args):
                term = "process.spawn.downloader"
            elif base in _SHELLS and _DOWNLOADER_RE.search(args):
                term = "process.spawn.shell"
            elif base not in _TOOLCHAIN and base not in _SHELLS:
                term = "process.spawn"
            else:
                continue
        elif category == "file" and operation in ("open", "read", "write"):
            path = str(detail.get("path") or detail.get("filename") or "")
            if not path:
                continue
            # npm reading its own .npmrc is installer baseline noise; a package
            # read of a credential path outside that baseline remains visible.
            if phase == "install" and path.endswith("/.npmrc"):
                continue
            resource = path
            if _is_sensitive_path(path):
                term = "file.read.sensitive"
            elif _is_persistence_path(path):
                term = "file.write"
            else:
                continue
        elif category == "network" and operation in ("connect", "send"):
            destination = str(detail.get("hostname") or detail.get("addr") or "")
            if not destination:
                continue
            term = "network.connect"
        elif category == "dns" and operation == "query":
            destination = str(detail.get("hostname") or "")
            if not destination:
                continue
            term = "dns.query"
        elif category == "process" and operation == "ptrace":
            term = "process.inject"
        elif category == "process" and operation in ("memfd_create", "fileless_exec"):
            term = "process.fileless_exec"
        else:
            continue

        assert term is not None
        key = (phase, term, resource or "", destination or "")
        if key in seen:
            continue
        seen.add(key)

        sensitive = term in {
            "file.read.sensitive",
            "network.connect",
            "process.spawn.shell",
            "process.spawn.downloader",
            "process.inject",
            "process.fileless_exec",
            "credential.honeytoken",
        } or (term == "file.write" and bool(resource))
        evidence_ok = raw_id not in missing
        evidence_sufficient = evidence_ok or raw_id in independent
        matching = [c for c in claims if _claim_matches(c, term, resource, destination)]
        specific = [c for c in matching if _specific_claim(c, term, resource, destination)]
        specific_sensitive = [c for c in matching if _specific_sensitive(c, resource, destination)]

        if sensitive:
            if specific_sensitive:
                outcome = "declared-sensitive"
                reason = "a specific claim names the observed sensitive resource or destination"
                claim_ref = specific_sensitive[0].claim_id
            elif claims_available:
                outcome = "unexplained"
                reason = "sensitive behavior is not named by a specific claim"
                claim_ref = None
            else:
                outcome = "unexplained"
                reason = "claims unavailable; sensitive behavior is unexplained by the missing-claims policy"
                claim_ref = None
            if not evidence_sufficient:
                reason += "; supporting raw evidence is insufficient for review"
        else:
            if specific and evidence_sufficient:
                outcome = "explained"
                reason = "specific claim scopes the exact non-sensitive observation"
                claim_ref = specific[0].claim_id
            elif not claims_available or coverage_level == "incomplete":
                outcome = "insufficient"
                reason = ("claims unavailable" if not claims_available
                          else "incomplete coverage prevents a reliable comparison")
                claim_ref = None
            else:
                outcome = "unremarkable"
                reason = "adequate claims/coverage but no claim applies; retained as context"
                claim_ref = None

        out.append(Observation(
            observation_id=_sid("obs-", raw_id, term, phase, resource or "", destination or ""),
            term=term,
            phase=phase,
            sensitive=sensitive,
            resource=resource,
            destination=destination,
            process=process,
            raw_event_id=raw_id,
            raw_ref=None if raw_id in missing else raw_id,
            evidence_integrity="failed" if not evidence_ok else "ok",
            evidence_sufficient=evidence_sufficient,
            outcome=outcome,
            reason=reason,
            claim_ref=claim_ref,
            filter_reason=raw.get("filter_reason"),
        ))
    return out


def package_result(
    observations: Iterable[Observation],
    *,
    claims_available: bool,
    coverage_level: str,
    evidence_integrity_failed: bool,
) -> tuple[str, str | None, str]:
    obs = list(observations)
    # Only an observation with retained/independent evidence can support review.
    unexplained = [o for o in obs if o.outcome == "unexplained" and o.evidence_sufficient]
    declared = [o for o in obs if o.outcome == "declared-sensitive" and o.evidence_sufficient]
    if unexplained:
        return "review: mismatch", None, "rule 1: adequately evidenced unexplained sensitive observation"
    if declared:
        return "review: declared-sensitive", None, "rule 2: adequately evidenced declared-sensitive observation"
    if (any(o.outcome == "insufficient" for o in obs) or not claims_available
            or coverage_level == "incomplete" or evidence_integrity_failed):
        return "insufficient", None, "rule 3: insufficient observation, claims, coverage, or evidence integrity"
    qualifier = "coverage unverified" if coverage_level == "unverified" else None
    return "no mismatch found", qualifier, "rule 4: no unexplained or declared-sensitive observation"
