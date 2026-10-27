# SPDX-License-Identifier: AGPL-3.0-or-later
"""Demo intel overlay: compiles standalone, loads through CLAIMTRACE_INTEL_PATH,
and matches only files that combine a credential source with an exfil/control
primitive. Kept separate from the baseline pack so it can be enabled or
disabled without touching shipped detection content.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "examples" / "intel-overlay"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "intel_overlay"
RULE_FILES = sorted((OVERLAY / "yara").glob("*.yar"))

MALICIOUS_EXPECTATIONS = {
    "ci_token_exfil.py": "claimtrace_ci_runner_token_exfil",
    "paste_upload.py": "claimtrace_paste_site_exfil",
    "docker_socket_control.py": "claimtrace_docker_socket_control",
}


@pytest.fixture(scope="module")
def compiled():
    assert RULE_FILES, f"no overlay rules under {OVERLAY / 'yara'}"
    return yara.compile(filepaths={p.stem: str(p) for p in RULE_FILES})


def _hits(compiled, path: Path) -> set[str]:
    return {m.rule for m in compiled.match(filepath=str(path))}


def test_one_rule_per_file_and_name_matches_stem():
    stems = [p.stem for p in RULE_FILES]
    assert len(stems) == len(set(stems)) == 3
    for p in RULE_FILES:
        assert f"rule {p.stem}" in p.read_text(encoding="utf-8")


def test_malicious_fixtures_match_their_rule(compiled):
    for filename, rule in MALICIOUS_EXPECTATIONS.items():
        hits = _hits(compiled, FIXTURES / "malicious" / filename)
        assert rule in hits, f"{filename}: expected {rule}, got {sorted(hits)}"


def test_benign_fixtures_do_not_match(compiled):
    benign = sorted((FIXTURES / "benign").glob("*.py"))
    assert benign, "benign fixtures missing"
    for p in benign:
        hits = _hits(compiled, p)
        assert not hits, f"{p.name}: unexpected matches {sorted(hits)}"


def test_overlay_merges_with_baseline(monkeypatch):
    from claimtrace import intel

    monkeypatch.setenv("CLAIMTRACE_INTEL_PATH", str(OVERLAY))
    pack = intel.load()
    assert pack.source.startswith("baseline+")
    assert len(pack.yara_dirs) == 2
    assert OVERLAY / "yara" in pack.yara_dirs


def test_analyzer_emits_overlay_findings(monkeypatch):
    from claimtrace import intel
    from claimtrace.analyze import yara_scan

    monkeypatch.setenv("CLAIMTRACE_INTEL_PATH", str(OVERLAY))
    intel.load()
    yara_scan._compiled_rules = None
    try:
        findings = yara_scan.analyze_yara(FIXTURES / "malicious")
    finally:
        yara_scan._compiled_rules = None

    ids = {f.rule_id for f in findings}
    for rule in MALICIOUS_EXPECTATIONS.values():
        assert f"yara.{rule}" in ids, f"missing yara.{rule} in {sorted(ids)}"


def test_overlay_disabled_means_no_overlay_rules(monkeypatch):
    from claimtrace import intel
    from claimtrace.analyze import yara_scan

    monkeypatch.delenv("CLAIMTRACE_INTEL_PATH", raising=False)
    pack = intel.load(use_env=False)
    assert len(pack.yara_dirs) == 1
    yara_scan._compiled_rules = None
    try:
        findings = yara_scan.analyze_yara(FIXTURES / "malicious")
    finally:
        yara_scan._compiled_rules = None
    assert not any(f.rule_id.startswith("yara.claimtrace_") for f in findings)
