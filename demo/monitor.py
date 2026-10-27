# SPDX-License-Identifier: AGPL-3.0-or-later
"""Print the live scan queue and recent scans for the background demo."""
from __future__ import annotations

import os
from collections import Counter

from sqlalchemy import func, select

from claimtrace.store import session as sess
from claimtrace.store.models import Package, Scan, ScanQueue, Version


def main() -> int:
    db = os.environ.get("CLAIMTRACE_DB_URL", sess.DEFAULT_URL)
    sess.init_db()
    with sess.session_scope() as s:
        statuses = Counter(
            {str(status): int(count) for status, count in s.execute(
                select(ScanQueue.status, func.count()).group_by(ScanQueue.status)
            ).all()}
        )
        total_scans = s.scalar(select(func.count()).select_from(Scan)) or 0
        rows = s.execute(
            select(Package.name, Version.version, Scan.verdict, Scan.score, Scan.started_at)
            .join(Version, Scan.version_id == Version.id)
            .join(Package, Version.package_id == Package.id)
            .order_by(Scan.id.desc())
            .limit(8)
        ).all()

    print(f"db: {db}")
    print("queue:", " ".join(f"{k}={statuses.get(k, 0)}" for k in ("pending", "claimed", "done", "failed")))
    print(f"scans: {total_scans}")
    for name, version, verdict, score, started in rows:
        print(f"  {started}  {name}=={version}  {verdict} score={score}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
