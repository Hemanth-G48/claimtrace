# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import copy

import pytest

from claimtrace.assessment import report, store
from claimtrace.assessment.claims import Claim
from claimtrace.assessment.classify import normalize_observations, package_result


def _raw(raw_id: str, *, category="file", operation="open", phase="entry", **detail):
    return {
        "raw_event_id": raw_id,
        "phase": phase,
        "category": category,
        "operation": operation,
        "detail": detail,
    }


def _claim(term: str, **kw):
    return Claim(
        claim_id="claim-test", text="test claim", source="README.md:1", span="L1",
        expected_capability=(term,), phase="any", confidence="high", ambiguity="",
        status="parsed", **kw,
    )


def _classify(events, claims=(), available=True, coverage="unverified", **kw):
    return normalize_observations(
        events, claims=claims, claims_available=available,
        coverage_level=coverage, **kw,
    )


def test_specific_non_sensitive_claim_is_explained():
    obs = _classify([_raw("r1", category="process", operation="exec", binary="/opt/tool", arguments="tool")],
                    [_claim("process.spawn")])
    assert [o.outcome for o in obs] == ["explained"]


def test_sensitive_credential_read_is_unexplained():
    obs = _classify([_raw("r1", path="/root/.ssh/id_rsa")], [_claim("file.read")])
    assert obs[0].term == "file.read.sensitive"
    assert obs[0].sensitive is True
    assert obs[0].outcome == "unexplained"


def test_readme_naming_credential_is_declared_sensitive():
    obs = _classify([_raw("r1", path="/root/.ssh/id_rsa")],
                    [_claim("file.read.sensitive", resource=".ssh")])
    assert obs[0].outcome == "declared-sensitive"


def test_missing_claims_makes_non_sensitive_insufficient_but_sensitive_unexplained():
    obs = _classify([
        _raw("r1", path="/root/.ssh/id_rsa"),
        _raw("r2", category="process", operation="exec", binary="/opt/tool", arguments="tool"),
    ], [], available=False)
    by_id = {o.raw_event_id: o for o in obs}
    assert by_id["r1"].outcome == "unexplained"
    assert by_id["r2"].outcome == "insufficient"


def test_unmatched_non_sensitive_is_unremarkable_under_adequate_coverage():
    obs = _classify([_raw("r1", category="process", operation="exec", binary="/opt/tool", arguments="tool")])
    assert obs[0].outcome == "unremarkable"


def test_explained_survives_incomplete_coverage_but_package_is_insufficient():
    obs = _classify([_raw("r1", category="process", operation="exec", binary="/opt/tool", arguments="tool")],
                    [_claim("process.spawn")], coverage="incomplete")
    assert obs[0].outcome == "explained"
    result, qual, _ = package_result(obs, claims_available=True, coverage_level="incomplete",
                                     evidence_integrity_failed=False)
    assert result == "insufficient"
    assert qual is None


def test_unverified_no_mismatch_has_mandatory_qualifier():
    result, qual, _ = package_result([], claims_available=True, coverage_level="unverified",
                                     evidence_integrity_failed=False)
    assert result == "no mismatch found"
    assert qual == "coverage unverified"


def test_declared_sensitive_review_and_precedence():
    obs = _classify([_raw("r1", path="/root/.ssh/id_rsa")],
                    [_claim("file.read.sensitive", resource=".ssh")])
    assert package_result(obs, claims_available=True, coverage_level="incomplete",
                          evidence_integrity_failed=False)[0] == "review: declared-sensitive"


def test_missing_raw_without_independent_evidence_cannot_support_review():
    obs = _classify([_raw("r1", path="/root/.ssh/id_rsa")], missing_raw_ids={"r1"})
    assert obs[0].evidence_integrity == "failed"
    assert obs[0].raw_ref is None
    assert package_result(obs, claims_available=True, coverage_level="incomplete",
                          evidence_integrity_failed=True)[0] == "insufficient"


def test_missing_raw_with_independent_evidence_can_support_review():
    obs = _classify([_raw("r1", path="/root/.ssh/id_rsa")], missing_raw_ids={"r1"},
                    independent_evidence_ids={"r1"})
    assert obs[0].evidence_integrity == "failed"
    assert obs[0].evidence_sufficient is True
    assert package_result(obs, claims_available=True, coverage_level="incomplete",
                          evidence_integrity_failed=True)[0] == "review: mismatch"


def _assessment(tmp_path, monkeypatch, package_result="review: declared-sensitive"):
    monkeypatch.setattr(store, "store_root", lambda: tmp_path)
    obs = _classify([_raw("r1", path="/root/.ssh/id_rsa")],
                    [_claim("file.read.sensitive", resource=".ssh")])
    return store.save({
        "schema_version": "assessment-1", "assessment_id": "asm-test",
        "input": {"target": "x.tgz", "kind": "local", "package": "x", "version": "1.0.0"},
        "package": {"name": "x", "version": "1.0.0"},
        "claims_available": True,
        "claims": [],
        "observations": [o.to_dict() for o in obs],
        "coverage": {"level": "unverified", "phases": {}},
        "evidence_integrity": {"status": "ok", "missing_raw_event_ids": []},
        "package_result": package_result,
        "package_qualifier": None,
        "package_rule": "test",
    }, [_raw("r1", path="/root/.ssh/id_rsa")])


def test_accept_requires_acknowledgement_and_revisions_append(tmp_path, monkeypatch):
    a = _assessment(tmp_path, monkeypatch)
    with pytest.raises(PermissionError):
        store.append_decision(a, decision="accept", reason="looks fine", author="tester", acknowledged=[])
    d1 = store.append_decision(a, decision="investigate", reason="look", author="tester", acknowledged=[])
    d2 = store.append_decision(a, decision="accept", reason="confirmed", author="tester",
                               acknowledged=[a["observations"][0]["observation_id"]])
    assert d1["decision_revision"] == 1
    assert d2["decision_revision"] == 2
    assert d2["acknowledged_sensitive"] == [a["observations"][0]["observation_id"]]
    assert len(store.load_decisions("asm-test")) == 2


def test_report_is_deterministic_for_same_revision_and_changes_on_new_decision(tmp_path, monkeypatch):
    a = _assessment(tmp_path, monkeypatch)
    first = report.render(a, store.load_decisions("asm-test"), 0)
    assert report.report_hash(first) == report.report_hash(first)
    store.append_decision(a, decision="investigate", reason="look", author="tester", acknowledged=[])
    second = report.render(a, store.load_decisions("asm-test"), 1)
    assert report.report_hash(first) != report.report_hash(second)
    assert report.report_hash(first) == report.report_hash(report.render(a, store.load_decisions("asm-test"), 0))


def test_canonical_hash_stable():
    a = {"b": 2, "a": [1, 3]}
    b = copy.deepcopy(a)
    assert store.canonical_hash(a) == store.canonical_hash(b)
