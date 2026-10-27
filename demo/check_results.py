"""Assert the demo verdicts recorded by `claimtrace replay`."""

from __future__ import annotations

import sqlite3
import sys

EXPECTED = {
    "demo-benign-math": "clean",
    "demo-ssh-beacon": "malicious",
    "demo-net-beacon": "suspicious",
    "demo-ci-token": "suspicious",
}

QUERY = """
select p.name, v.version, s.verdict, s.score, s.id
from scan s
join version v on s.version_id = v.id
join package p on v.package_id = p.id
order by s.id
"""


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_results.py <sqlite-db>", file=sys.stderr)
        return 2
    con = sqlite3.connect(sys.argv[1])
    latest: dict[str, tuple[str, int, int]] = {}
    for name, version, verdict, score, scan_id in con.execute(QUERY):
        latest[name] = (verdict, score, scan_id)

    ok = True
    for name, expected in EXPECTED.items():
        verdict, score, scan_id = latest.get(name, ("MISSING", -1, -1))
        passed = verdict == expected
        ok &= passed
        print(
            f"{'PASS' if passed else 'FAIL'}  {name}: expected={expected} actual={verdict} score={score}"
        )
        if scan_id >= 0:
            rows = con.execute(
                "select rule_id, severity, file from finding where scan_id = ? order by id",
                (scan_id,),
            ).fetchall()
            for rule_id, severity, path in rows[:8]:
                print(f"        {rule_id} [{severity}] {path}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
