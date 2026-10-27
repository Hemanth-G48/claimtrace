# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from typing import List, Optional

import typer

from claimtrace.logging_setup import configure_logging, get_logger
from claimtrace.store import session as sess

app = typer.Typer(no_args_is_help=True, help="Multi-ecosystem package malware scanner (PyPI, crates.io, Go modules, npm).")
log = get_logger("cli")


@app.callback()
def _root(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    configure_logging(level="DEBUG" if verbose else "INFO")


@app.command("init-db")
def init_db_cmd() -> None:
    """Create all tables."""
    sess.init_db()
    typer.echo("ok")


@app.command("run")
def run_cmd(
    workers: int = typer.Option(4, "--workers", "-w"),
    duration: int = typer.Option(0, "--duration", help="Stop after N seconds (0 = forever)."),
    focus: str = typer.Option(
        None, "--focus", "-f",
        help="Focused mode: load this combined focus file ([pypi]/[crates]/[gomod] "
             "sections) and scan ONLY focus packages. Omit for normal mode.",
    ),
) -> None:
    """Start ingest + worker pool + scheduler.

    With -f/--focus the scanner runs in exclusive focused mode against the given
    combined file (authoritative — the file defines the focus list). Without it,
    the usual watchlist + brand-new ingest runs.
    """
    from claimtrace.runtime import run_forever  # late import to keep CLI fast
    run_forever(workers=workers, duration=duration, focus_file=focus)


@app.command("backfill")
def backfill_cmd(days: int = typer.Option(1, "--days")) -> None:
    """Enqueue everything from PyPI changelog over the last N days."""
    from claimtrace.runtime import backfill_days
    backfill_days(days=days)


@app.command("rescan")
def rescan_cmd(
    package: str = typer.Option(..., "--package"),
    version: str = typer.Option(..., "--version"),
    ecosystem: str = typer.Option("pypi", "--ecosystem"),
) -> None:
    """Re-enqueue a single (ecosystem, package, version)."""
    from claimtrace.runtime import enqueue_one
    enqueue_one(ecosystem=ecosystem, name=package, version=version, priority="high")
    typer.echo("enqueued")


@app.command("replay")
def replay_cmd(
    names: Optional[List[str]] = typer.Argument(
        None, help="Explicit package names to replay (the usual scoped path)."),
    package: str = typer.Option(None, "--package", "--name", help="Single-name filter."),
    version: str = typer.Option(None, "--version", help="Filter by version."),
    ecosystem: str = typer.Option(None, "--ecosystem", "-e", help="Filter by ecosystem."),
    all_vaulted: bool = typer.Option(False, "--all", help="Replay EVERY vaulted sample (whole vault)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirm prompt."),
) -> None:
    """Replay vaulted sample(s) through the REAL scan pipeline (analyze→score→LLM→Discord).

    Sources bytes from the vault, not the registry — for testing / re-running known-bad
    samples whose registry versions were yanked. Fires real Discord alerts and writes
    real Scan rows; NOT part of the live firehose.

    Scope it: `replay weavedb-base zkjson ...` (names), or `--package X [--version Y]`,
    or `--ecosystem npm`. `--all` replays the ENTIRE vault and requires confirmation.
    """
    import asyncio as _aio
    import uuid as _uuid
    from datetime import datetime, timezone

    import claimtrace.ecosystems  # noqa: F401  populates adapter_registry
    from claimtrace import queue, vault
    from claimtrace.pipeline import process_one

    sess.init_db()
    if not vault.is_enabled():
        typer.echo("vault not enabled (set CLAIMTRACE_VAULT_PATH)")
        raise typer.Exit(1)

    targets = vault.list_vaulted()
    name_set = {n for n in (names or [])}
    if not all_vaulted:
        if not (name_set or package or version or ecosystem):
            raise typer.BadParameter(
                "give package NAMES, or --package/--version/--ecosystem, or --all")
        targets = [
            t for t in targets
            if (not ecosystem or t["ecosystem"] == ecosystem)
            and (not package or t["name"] == package)
            and (not version or t["version"] == version)
            and (not name_set or t["name"] in name_set)
        ]
    if not targets:
        typer.echo("no matching vaulted samples")
        raise typer.Exit(1)

    # Guard: never fire a large batch (esp. --all over the whole vault) without an
    # explicit OK. Each malicious target sends a real Discord alert.
    if len(targets) > 20 and not yes:
        typer.echo(f"about to replay {len(targets)} samples — each malicious one fires a "
                   f"real Discord alert.\nre-run with --yes to confirm.")
        raise typer.Exit(1)

    typer.echo(f"replaying {len(targets)} vaulted sample(s) through the real pipeline...")

    async def _go() -> None:
        for t in targets:
            with sess.session_scope() as s:
                row = queue.enqueue(
                    s, ecosystem=t["ecosystem"], name=t["name"], version=t["version"],
                    priority="high", allow_rescan=True,
                )
                if row is None:
                    typer.echo(f"  SKIP {t['name']}@{t['version']} (enqueue failed)")
                    continue
                token = _uuid.uuid4().hex
                row.status = "claimed"
                row.claim_token = token
                row.claimed_at = datetime.now(timezone.utc)
                qid = row.id
            await process_one(qid, token, replay_from_vault=True)
            typer.echo(f"  replayed {t['ecosystem']}/{t['name']}@{t['version']}")

    _aio.run(_go())
    typer.echo("done — malicious verdicts fire Discord alerts")


@app.command("scan-watchlist")
def scan_watchlist_cmd(
    limit: int = typer.Option(0, "--limit", "-n", help="Max packages (0 = all)."),
    concurrency: int = typer.Option(20, "--concurrency", "-c"),
) -> None:
    """Enqueue all watchlist packages for scanning (first-pass baseline)."""
    import asyncio as _aio

    from claimtrace.ecosystems.pypi.ingest import watchlist as wl
    sess.init_db()

    async def _go():
        from sqlalchemy import select

        from claimtrace.store.models import Watchlist
        with sess.session_scope() as s:
            empty = s.scalars(select(Watchlist).limit(1)).first() is None
        if empty:
            typer.echo("watchlist empty — refreshing from PyPI...")
            await wl.refresh_watchlist()
        n = await wl.poll_watchlist_releases(
            limit=limit or None, concurrency=concurrency,
        )
        typer.echo(f"enqueued {n} packages")

    _aio.run(_go())


@app.command("show")
def show_cmd(
    package: str = typer.Option(..., "--package"),
    version: str = typer.Option(..., "--version"),
    ecosystem: str = typer.Option("pypi", "--ecosystem"),
) -> None:
    """Print latest scan + findings for a package version."""
    from claimtrace.runtime import show_findings
    show_findings(ecosystem=ecosystem, name=package, version=version)


@app.command("review")
def review_cmd(
    limit: int = typer.Option(50, "--limit", "-n", help="How many recent inconclusive scans to show."),
    ecosystem: str = typer.Option(None, "--ecosystem", "-e", help="Filter by ecosystem."),
) -> None:
    """List packages the LLM marked INCONCLUSIVE (needs a human look), newest first,
    with what evidence it was missing (the MISSING EVIDENCE line in the reasoning)."""
    from sqlalchemy import desc, select

    from claimtrace.store.models import Package, Scan, Version
    sess.init_db()
    with sess.session_scope() as s:
        q = (
            select(Package.ecosystem, Package.name, Version.version,
                   Scan.score, Scan.finished_at, Scan.llm_reasoning)
            .join(Version, Scan.version_id == Version.id)
            .join(Package, Version.package_id == Package.id)
            .where(Scan.verdict == "inconclusive")
        )
        if ecosystem:
            q = q.where(Package.ecosystem == ecosystem)
        rows = s.execute(q.order_by(desc(Scan.finished_at)).limit(limit)).all()
    for eco, name, version, score, finished, reasoning in rows:
        when = finished.isoformat() if finished else "?"
        typer.echo(f"\n{eco}\t{name}=={version}\tscore={score}\t{when}")
        if reasoning:
            typer.echo(f"  {reasoning.strip()}")
    typer.echo(f"\n# {len(rows)} inconclusive scan(s) awaiting review")


focus_app = typer.Typer(
    no_args_is_help=True,
    help="Manage focus packages — a per-ecosystem personal watchlist.",
)
app.add_typer(focus_app, name="focus")

_ECOSYSTEMS = ("pypi", "crates", "gomod", "npm")


def _check_ecosystem(ecosystem: str) -> None:
    if ecosystem not in _ECOSYSTEMS:
        raise typer.BadParameter(f"ecosystem must be one of {_ECOSYSTEMS}")


@focus_app.command("load")
def focus_load_cmd(
    file: str = typer.Argument(..., help="Path to focus list file."),
    ecosystem: str = typer.Option(
        None, "--ecosystem", "-e",
        help="pypi|crates|gomod for a flat file. Omit for a combined file with "
             "[pypi]/[crates]/[gomod] sections (covers all ecosystems at once).",
    ),
    enqueue_pinned: bool = typer.Option(
        True, "--enqueue-pinned/--no-enqueue-pinned",
        help="Enqueue any pinned versions for immediate scanning.",
    ),
) -> None:
    """Load focus packages from a file.

    Flat file with -e: additive upsert for that ecosystem (one `name` or
    `name==version` per line). Combined file without -e: each `[ecosystem]`
    section authoritatively replaces that ecosystem's focus list.
    """
    from pathlib import Path

    from claimtrace import focus
    from claimtrace.queue import enqueue

    sess.init_db()
    text = Path(file).read_text(encoding="utf-8")

    if ecosystem:
        _check_ecosystem(ecosystem)
        sections = {ecosystem: focus.parse_focus_file(text, ecosystem)}
        authoritative = False  # flat single-ecosystem load is additive
    else:
        sections = focus.parse_combined_focus_file(text)
        if not sections:
            raise typer.BadParameter(
                "no [ecosystem] sections found — pass -e for a flat single-ecosystem file."
            )
        authoritative = True  # combined file is the source of truth

    total = 0
    enq = 0
    with sess.session_scope() as s:
        for eco, entries in sections.items():
            if authoritative:
                focus.sync_focus(s, eco, entries)
            else:
                focus.upsert_focus(s, eco, entries)
            total += len(entries)
            if enqueue_pinned:
                for e in entries:
                    if e.pinned_version and enqueue(
                        s, ecosystem=eco, name=e.name,
                        version=e.pinned_version, priority="high",
                    ):
                        enq += 1
    scope = ", ".join(sorted(sections)) if sections else "—"
    typer.echo(f"loaded {total} focus entries ({scope}) — {enq} pinned versions enqueued")


@focus_app.command("list")
def focus_list_cmd(
    ecosystem: str = typer.Option(None, "--ecosystem", "-e"),
) -> None:
    """List focus entries (warns if exclusive mode is on but the list is empty)."""
    from sqlalchemy import select

    from claimtrace.focus import focus_exclusive
    from claimtrace.store.models import FocusList

    sess.init_db()
    with sess.session_scope() as s:
        q = select(FocusList)
        if ecosystem:
            q = q.where(FocusList.ecosystem == ecosystem)
        rows = s.scalars(q.order_by(FocusList.ecosystem, FocusList.name)).all()
        for r in rows:
            typer.echo(f"{r.ecosystem}\t{r.name}\t{r.pinned_version or '-'}")
        typer.echo(f"# {len(rows)} entries")
        if focus_exclusive() and not rows:
            typer.echo(
                "WARNING: CLAIMTRACE_FOCUS_EXCLUSIVE=1 but focus list is empty — the scanner will idle."
            )


@focus_app.command("clear")
def focus_clear_cmd(
    ecosystem: str = typer.Option(None, "--ecosystem", "-e", help="Limit to one ecosystem (default: all)."),
) -> None:
    """Remove focus entries (all, or one ecosystem)."""
    from claimtrace.focus import clear_focus

    sess.init_db()
    with sess.session_scope() as s:
        n = clear_focus(s, ecosystem)
    typer.echo(f"cleared {n} entries")


# --- watchlist auto subcommands ---------------------------------------------
# Manage the auto-watchlist gate: every double-confirmed malicious verdict
# (rules + LLM agree) adds the (ecosystem, name) here at a sentinel rank, so
# the next release is scanned at high priority. See claimtrace.watchlist_auto.

watchlist_app = typer.Typer(
    no_args_is_help=True,
    help="Watchlist administration (auto-added confirmed-malicious entries).",
)
app.add_typer(watchlist_app, name="watchlist")

scope_app = typer.Typer(
    no_args_is_help=True,
    help="Scope-watchlist: watch a whole org (npm @scope / gomod path prefix / pypi name prefix).",
)
app.add_typer(scope_app, name="scope")

maintainer_app = typer.Typer(
    no_args_is_help=True,
    help="Maintainer-pivot: force-scan a caught maintainer's other packages (never watchlists).",
)
app.add_typer(maintainer_app, name="maintainer")


@maintainer_app.command("sweep")
def maintainer_sweep_cmd(
    ecosystem: str = typer.Argument(..., help="pypi|npm"),
    name: str = typer.Argument(..., help="A package whose maintainer to pivot from."),
) -> None:
    """Force-scan the maintainer's catalog (manual/backfill). Honors the shadow
    flag — shadow mode logs the would-sweep set and enqueues nothing."""
    from claimtrace import maintainer_pivot
    sess.init_db()
    outcome = maintainer_pivot.sweep_on_malicious(ecosystem, name, source="manual")
    for k, v in outcome.items():
        typer.echo(f"{k}\t{v}")


@maintainer_app.command("list")
def maintainer_list_cmd() -> None:
    """Show the effective maintainer-pivot configuration (verify shadow state)."""
    from claimtrace import maintainer_pivot as mp
    from claimtrace import maintainer_watch as mw
    typer.echo(f"enabled\t{mp.is_enabled()}")
    typer.echo(f"shadow\t{mp.is_shadow()}")
    typer.echo(f"supported\t{', '.join(mp.SUPPORTED)}")
    typer.echo(f"max_pkgs\t{mp._max_pkgs()}")
    typer.echo(f"corr_days\t{mp._corr_days()}")
    typer.echo(f"timeout_s\t{mp._timeout()}")
    typer.echo(f"dedup_ttl_s\t{mp._dedup_ttl()}")
    allow = sorted(mp._trigger_allow())
    deny = sorted(mp._trigger_deny())
    typer.echo(f"trigger_allow\t{', '.join(allow) if allow else '(any)'}")
    typer.echo(f"trigger_deny\t{', '.join(deny) if deny else '(none)'}")
    typer.echo(f"watch_enabled\t{mw.is_enabled()}")
    typer.echo(f"watch_releases\t{mw._releases()}")
    typer.echo(f"watch_ttl_days\t{mw._ttl_days()}")


maintainer_watch_app = typer.Typer(
    no_args_is_help=True,
    help="Bounded force-scan watches on caught maintainers' clean sibling packages.",
)
maintainer_app.add_typer(maintainer_watch_app, name="watch")


@maintainer_watch_app.command("list")
def maintainer_watch_list_cmd(
    ecosystem: str = typer.Option(None, "--ecosystem", "-e"),
) -> None:
    """List active bounded force-scan watches."""
    from claimtrace.maintainer_watch import list_watches
    sess.init_db()
    with sess.session_scope() as s:
        rows = list_watches(s, ecosystem)
    for eco, name, maint, added in rows:
        typer.echo(f"{eco}\t{name}\t{maint or '-'}\t{added}")
    typer.echo(f"# {len(rows)} watches")


@maintainer_watch_app.command("remove")
def maintainer_watch_remove_cmd(
    ecosystem: str = typer.Argument(..., help="pypi|npm"),
    name: str = typer.Argument(..., help="The package to stop watching (FP exit ramp)."),
) -> None:
    """Drop a bounded watch (false-positive exit ramp)."""
    from claimtrace.maintainer_watch import remove_watch
    sess.init_db()
    with sess.session_scope() as s:
        n = remove_watch(s, ecosystem, name)
    typer.echo(f"removed: {n}")


@scope_app.command("list")
def scope_list_cmd(
    ecosystem: str = typer.Option(None, "--ecosystem", "-e"),
) -> None:
    """List watched scopes (optionally filtered by ecosystem)."""
    from sqlalchemy import select

    from claimtrace.store.models import WatchlistScope
    sess.init_db()
    with sess.session_scope() as s:
        q = select(WatchlistScope).order_by(WatchlistScope.ecosystem, WatchlistScope.scope)
        if ecosystem:
            q = q.where(WatchlistScope.ecosystem == ecosystem)
        rows = s.scalars(q).all()
        for r in rows:
            typer.echo(f"{r.ecosystem}\t{r.scope}\t{r.source}")
        typer.echo(f"# {len(rows)} scopes")


@scope_app.command("add")
def scope_add_cmd(
    ecosystem: str = typer.Argument(..., help="npm|gomod|pypi"),
    scope: str = typer.Argument(..., help="@org (npm) / path prefix (gomod) / name prefix (pypi)"),
) -> None:
    """Watch a scope: every package + release under it is scanned at high priority."""
    from claimtrace import scope_watchlist
    sess.init_db()
    with sess.session_scope() as s:
        status = scope_watchlist.add_scope(s, ecosystem, scope, source="manual")
    typer.echo(f"{status}: {ecosystem} {scope}")


@scope_app.command("remove")
def scope_remove_cmd(
    ecosystem: str = typer.Argument(..., help="npm|gomod|pypi"),
    scope: str = typer.Argument(..., help="The scope to stop watching."),
) -> None:
    """Stop watching a scope."""
    from claimtrace import scope_watchlist
    sess.init_db()
    with sess.session_scope() as s:
        n = scope_watchlist.remove_scope(s, ecosystem, scope)
    typer.echo(f"removed: {n}")


@scope_app.command("seed")
def scope_seed_cmd() -> None:
    """(Re)seed the baseline vendor scopes (idempotent)."""
    from claimtrace import scope_watchlist
    sess.init_db()
    with sess.session_scope() as s:
        added = scope_watchlist.seed_baseline(s)
    typer.echo(f"seeded: {added} new scopes")


threatintel_app = typer.Typer(
    no_args_is_help=True,
    help="Threat-intel fingerprints (auto-seeding is DISABLED in code; manage existing/baseline seeds + matching).",
)
app.add_typer(threatintel_app, name="threatintel")


@threatintel_app.command("backfill")
def threatintel_backfill_cmd(
    limit: int = typer.Option(0, "--limit", help="Cap scans processed (0 = all)."),
) -> None:
    """Seed fingerprints from ALL historically double-confirmed-malicious scans.

    NOTE: auto-seeding is hard-disabled in code (maintainer directive), so this
    currently seeds 0 fingerprints. Retained for if/when seeding is re-enabled.
    """
    from claimtrace import threat_intel_auto
    sess.init_db()
    with sess.session_scope() as s:
        scans, seeded = threat_intel_auto.backfill(s, limit=limit or None)
    typer.echo(f"backfill: {scans} malicious scans processed, {seeded} new fingerprints seeded")


@threatintel_app.command("backfill-tlsh")
def threatintel_backfill_tlsh_cmd() -> None:
    """Fill missing TLSH on auto-seeded fingerprints by re-hashing vaulted archives."""
    from claimtrace import threat_intel_auto
    sess.init_db()
    with sess.session_scope() as s:
        archives, updated = threat_intel_auto.backfill_tlsh_from_vault(s)
    typer.echo(f"tlsh backfill: {archives} vault archives read, {updated} fingerprints gained TLSH")


@threatintel_app.command("candidates")
def threatintel_candidates_cmd() -> None:
    """List auto-seeded campaigns awaiting review (exact-SHA-256-only until promoted).

    Operates on existing `source="auto"` rows only; no new candidates are generated
    while auto-seeding is disabled.
    """
    from claimtrace import threat_intel_auto
    sess.init_db()
    with sess.session_scope() as s:
        cands = threat_intel_auto.candidates(s)
    for campaign, n in cands:
        typer.echo(f"{n}\t{campaign}")
    typer.echo(f"# {len(cands)} candidate campaigns")


@threatintel_app.command("promote")
def threatintel_promote_cmd(
    campaign: str = typer.Argument(..., help="campaign (auto:eco:name) or bare package name"),
) -> None:
    """Promote a confirmed-bad campaign to FUZZY matching (ssdeep/TLSH). Until
    promoted, auto-seeded fingerprints match on exact SHA-256 only (zero-FP)."""
    from claimtrace import threat_intel_auto
    sess.init_db()
    with sess.session_scope() as s:
        n = threat_intel_auto.promote(s, campaign)
    typer.echo(f"promoted: {n} fingerprints -> fuzzy matching enabled")


@threatintel_app.command("remove")
def threatintel_remove_cmd(
    campaign: str = typer.Argument(..., help="campaign (auto:eco:name) or bare package name"),
) -> None:
    """Remove a campaign's fingerprints — the FP exit-ramp for the moat. Use when a
    seed is a false positive (e.g. a since-fixed rule auto-seeded a benign package
    and it now self-confirms). Re-evaluated by current rules on next scan; add the
    name to WATCHLIST_AUTO_BLOCKLIST to stop re-seeding."""
    from claimtrace import threat_intel_auto
    sess.init_db()
    with sess.session_scope() as s:
        n = threat_intel_auto.remove(s, campaign)
    typer.echo(f"removed: {n} fingerprints for {campaign!r}")


@threatintel_app.command("stats")
def threatintel_stats_cmd() -> None:
    """Show threat-intel fingerprint counts (auto exact-only / promoted fuzzy / total)."""
    from claimtrace import threat_intel_auto
    sess.init_db()
    with sess.session_scope() as s:
        st = threat_intel_auto.stats(s)
    typer.echo(f"fingerprints: {st['auto']} auto (exact-only) / {st['promoted']} promoted (fuzzy) / {st['total']} total")


auto_app = typer.Typer(
    no_args_is_help=True,
    help="Manage auto-added confirmed-malicious entries.",
)
watchlist_app.add_typer(auto_app, name="auto")


@auto_app.command("list")
def watchlist_auto_list_cmd(
    ecosystem: str = typer.Option(None, "--ecosystem", "-e"),
) -> None:
    """List auto-added (confirmed-malicious) watchlist entries."""
    from claimtrace.watchlist_auto import list_auto_entries
    sess.init_db()
    with sess.session_scope() as s:
        entries = list_auto_entries(s, ecosystem=ecosystem)
    for eco, name, refreshed in entries:
        typer.echo(f"{eco}\t{name}\t{refreshed.isoformat()}")
    typer.echo(f"# {len(entries)} entries")


@auto_app.command("remove")
def watchlist_auto_remove_cmd(
    ecosystem: str = typer.Argument(..., help="pypi|crates|gomod|npm"),
    name: str = typer.Argument(..., help="Package name (case-insensitive)."),
) -> None:
    """Remove a single auto-added entry (FP exit ramp). Popularity rows untouched."""
    _check_ecosystem(ecosystem)
    from claimtrace.watchlist_auto import remove_auto_entry
    sess.init_db()
    with sess.session_scope() as s:
        removed = remove_auto_entry(s, ecosystem, name)
    typer.echo(f"removed: {removed}")


@auto_app.command("purge")
def watchlist_auto_purge_cmd(
    older_than_days: int = typer.Option(
        0, "--older-than-days",
        help="Drop auto-added entries older than N days. 0 = drop all auto-added.",
    ),
) -> None:
    """Bulk-prune auto-added entries. With --older-than-days 0 drops all of them."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import delete

    from claimtrace.store.models import Watchlist
    from claimtrace.watchlist_auto import AUTO_MALICIOUS_RANK

    sess.init_db()
    with sess.session_scope() as s:
        q = delete(Watchlist).where(Watchlist.rank == AUTO_MALICIOUS_RANK)
        if older_than_days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
            q = q.where(Watchlist.refreshed_at < cutoff)
        res = s.execute(q)
    typer.echo(f"purged {res.rowcount or 0} auto-added entries")


@auto_app.command("backfill")
def watchlist_auto_backfill_cmd(
    days: int = typer.Option(
        30, "--days", help="Look back this many days of scan history.",
    ),
) -> None:
    """Walk scan history and add every package that produced an LLM-malicious
    verdict BACKED BY primary high/critical evidence (not solely a soft
    iocs/dep_intel/metadata signal) to the auto-watchlist.

    Mirrors the live promotion bar (see pipeline._auto_watchlist_qualifies).
    Useful one-shot after enabling the gate so prior known-bad packages get
    high-priority coverage going forward without waiting for a re-publish.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from claimtrace.pipeline import _NON_PRIMARY_PROMOTE_CATEGORIES
    from claimtrace.store.models import Finding, Package, Scan, Version
    from claimtrace.watchlist_auto import add_confirmed_malicious

    sess.init_db()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    added = 0
    refreshed = 0
    skipped = 0
    with sess.session_scope() as s:
        # Mirror the live promotion bar: LLM-malicious is not enough — the scan
        # must also carry PRIMARY high/critical evidence (not solely the FP-prone
        # iocs / dep_intel / metadata / version_diff categories). The rule verdict
        # itself isn't persisted separately (Scan.verdict is overwritten with the
        # LLM verdict), so we corroborate via the findings rather than re-deriving it.
        primary_evidence = (
            select(Finding.id)
            .where(
                Finding.scan_id == Scan.id,
                Finding.severity.in_(("high", "critical")),
                Finding.category.notin_(tuple(_NON_PRIMARY_PROMOTE_CATEGORIES)),
                ~Finding.rule_id.like("opengrep.shadow_%"),
            )
            .exists()
        )
        rows = s.execute(
            select(Package.ecosystem, Package.name)
            .select_from(Scan)
            .join(Version, Scan.version_id == Version.id)
            .join(Package, Version.package_id == Package.id)
            .where(
                Scan.verdict == "malicious",
                Scan.llm_verdict == "malicious",
                Scan.finished_at >= cutoff,
                primary_evidence,
            )
            .group_by(Package.ecosystem, Package.name)
        ).all()
        for eco, name in rows:
            status = add_confirmed_malicious(s, eco, name)
            if status == "added":
                added += 1
            elif status == "refreshed":
                refreshed += 1
            else:
                skipped += 1
    typer.echo(
        f"backfilled {len(rows)} unique double-confirmed names — "
        f"added={added} refreshed={refreshed} skipped={skipped}"
    )


# --- local-artifact assessment (Stage 0; not the registry scanner) ----------

@app.command("assess")
def assess_cmd(
    target: str = typer.Argument(..., help="Local npm tarball, or name@version."),
    ecosystem: str = typer.Option("npm", "--ecosystem", "-e"),
    api_url: str = typer.Option(None, "--api-url", help="Detonation API URL (or DETONATION_URL)."),
    socket_path: str = typer.Option(None, "--socket", help="Detonation API UNIX socket (or DETONATION_SOCKET)."),
    timeout: int = typer.Option(180, "--timeout"),
    fault_drop_raw: str = typer.Option(None, "--fault-drop-raw", hidden=True),
    fault_independent: bool = typer.Option(False, "--fault-independent", hidden=True),
) -> None:
    """Assess a local package against its own README/metadata claims.

    Stage 0: no ingest gates, queue, eligibility policy, code-change skip, or
    notifications. The API receives a staged archive path, never a registry
    coordinate.
    """
    import json

    from claimtrace.assessment import assess
    from claimtrace.detonate.client import DetonationClient

    client = DetonationClient(socket_path=socket_path, base_url=api_url)
    try:
        a = assess(target, ecosystem=ecosystem, client=client, timeout_seconds=timeout,
                   fault_drop_raw=fault_drop_raw, fault_independent=fault_independent)
    except Exception as e:
        typer.echo(f"assessment failed: {e}", err=True)
        raise typer.Exit(2)
    typer.echo(json.dumps({
        "assessment_id": a.get("assessment_id"),
        "assessment_hash": a.get("assessment_hash"),
        "package": a.get("package"),
        "package_result": a.get("package_result"),
        "package_qualifier": a.get("package_qualifier"),
        "coverage": (a.get("coverage") or {}).get("level"),
        "observations": len(a.get("observations") or []),
    }, sort_keys=True))


@app.command("report")
def report_cmd(
    assessment_id: str = typer.Argument(..., help="Assessment id."),
    decision_revision: int = typer.Option(None, "--decision-revision", "-r"),
    json_out: bool = typer.Option(False, "--json", help="Print canonical assessment JSON."),
) -> None:
    """Render the deterministic report for an assessment/decision revision."""
    import json

    from claimtrace.assessment import report, store

    try:
        a = store.load(assessment_id)
    except FileNotFoundError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(a, sort_keys=True, indent=2))
        return
    text = report.render(a, store.load_decisions(assessment_id), decision_revision)
    typer.echo(text)
    typer.echo(f"report_hash: {report.report_hash(text)}")


@app.command("decide")
def decide_cmd(
    assessment_id: str = typer.Argument(..., help="Assessment id."),
    decision: str = typer.Option(..., "--decision", help="accept|investigate|reject"),
    reason: str = typer.Option(..., "--reason"),
    author: str = typer.Option(None, "--author"),
    acknowledge: List[str] = typer.Option(None, "--acknowledge", help="Observation id; repeatable or comma-separated."),
) -> None:
    """Append a human decision. Never rewrites the automated package result."""
    import os

    from claimtrace.assessment import store

    try:
        a = store.load(assessment_id)
    except FileNotFoundError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)
    acked: list[str] = []
    for value in acknowledge or []:
        acked.extend(x.strip() for x in value.split(",") if x.strip())
    try:
        rec = store.append_decision(
            a, decision=decision, reason=reason,
            author=author or os.environ.get("USER", "unknown"), acknowledged=acked,
        )
    except PermissionError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)
    except ValueError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(2)
    typer.echo(f"{rec['decision_revision']}\t{rec['decision']}\t{rec['decision_id']}")
