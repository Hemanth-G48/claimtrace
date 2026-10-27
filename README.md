# ClaimTrace

ClaimTrace is a self-hosted supply-chain scanner for **PyPI, crates.io, the Go module proxy, and npm**. It watches both popular packages and first-time publishers, runs static analysis over each release, optionally executes the package in an isolated sandbox, and records evidence for review.

It also has a local **Stage 0 assessment** path: compare what a package *claims* in its README and metadata with what it *actually does* during install and import.

> **Status:** working, tested prototype. The registry scanner and the local assessment path are both implemented; the public baseline is intentionally focused and can be extended with a private intel overlay.

## At a glance

| | |
|---|---|
| **Registry scanner** | Four ecosystems, watchlist + first-publish coverage, durable queue, static analysis, optional detonation |
| **Local assessment** | One npm tarball or `name@version`, sandboxed install/entry/import, claim-vs-behavior report, human decision |
| **Detection** | AST/import analysis, IOCs, install-time patterns, YARA, opengrep, version diff, threat-intel fingerprints, obfuscation, binary analysis |
| **Runtime evidence** | Rootless Docker + Tetragon eBPF, decoy credentials, recording sinkhole + fake DNS |
| **Review workflow** | Deterministic reports, raw-event references, append-only decisions, declared-sensitive acknowledgement |
| **Deployment** | Docker Compose, standalone PostgreSQL, or a Python 3.11 source checkout |

## Why it exists

A package's description is not evidence of its behavior. Typosquats, hijacked releases, dependency confusion, and malicious install scripts all exploit that gap.

ClaimTrace covers two threat models:

- **Popular-package compromise** — a malicious release of a package that already has reach. Covered by watchlist scanning.
- **New-name lures** — a first publish with a name designed to attract a victim. Covered by scanning new packages as they appear.

Normal version updates for packages outside the watchlist are skipped: that is where false-positive cost is highest and attack signal is lowest.

## Quick start

### Docker (recommended)

Requires Docker and Docker Compose.

```bash
git clone https://github.com/Hemanth-G48/claimtrace
cd claimtrace
cp .env.example .env

# Standalone: includes PostgreSQL; no external database needed.
docker compose -f docker-compose.standalone.yml up -d

# Watch the scanner poll the registries.
docker logs claimtrace -f
```

To use your own PostgreSQL, edit `.env` and run `docker compose up -d` instead.

### From source

Requires Python 3.11. No registry credentials are required for a static-only run.

```bash
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
cp .env.example .env

# The CLI does not auto-load .env outside Docker.
set -a; . ./.env; set +a
.venv/bin/claimtrace init-db
.venv/bin/claimtrace run --workers 2
```

Optional analyzers (`opengrep`, UPX unpacking, and `webcrack`) are used when their binaries are on `PATH`; their absence does not stop the pipeline. A private intel overlay is loaded with `CLAIMTRACE_INTEL_PATH`.

## Demo

### 1. Static pipeline — deterministic and offline

```bash
bash demo/run_demo.sh
```

This builds four synthetic packages and replays them through the real scan pipeline. No registry traffic, no package execution, no API keys. The script intentionally ignores ambient LLM credentials so the expected static verdicts stay stable.

| Case | Verdict | Signal |
|---|---|---|
| benign utility | clean | — |
| credential sweep + exfil | malicious | `malware.credential_store_sweep`, `yara.ssh_key_exfiltration` |
| network at import | suspicious | `imports.network_at_import` |
| CI token exfil, overlay only | suspicious | `yara.claimtrace_ci_runner_token_exfil` |

See [demo/README.md](demo/README.md) for the overlay on/off comparison and the full fixture list.

### 2. Local behavioral assessment — real execution

The local path stages a single npm artifact, asks the detonation service to run it inside the rootless sandbox, and writes a canonical assessment plus a human decision. It does not use the registry queue or Discord.

Prerequisites: rootless Docker, the detonation service, and Tetragon for raw event capture.

```bash
export DETONATION_URL=http://127.0.0.1:19100

.venv/bin/claimtrace assess demo/m2/string-format-demo-1.0.0.tgz
.venv/bin/claimtrace report <assessment-id>
.venv/bin/claimtrace decide <assessment-id> \
  --decision investigate --reason "reviewing"
```

`assess` accepts a local npm tarball; `name@version` is resolved once by the CLI before staging. The package runs only inside the isolated sandbox.

A result such as `no mismatch found` is not a “safe” verdict. Coverage remains `unverified` unless every required phase completed and event loss was measured.

The local assessment path is npm-only. The registry scanner supports all four ecosystems.

### 3. Persistent background worker

Start a long-lived worker with a durable SQLite queue:

```bash
export CLAIMTRACE_DB_URL="sqlite:///$PWD/demo/.work/background.db"
SCANNER_INGEST=0 .venv/bin/claimtrace run --workers 1
```

In a second terminal, queue a real package:

```bash
export CLAIMTRACE_DB_URL="sqlite:///$PWD/demo/.work/background.db"
.venv/bin/claimtrace rescan --package six --version 1.16.0
watch -n 2 '.venv/bin/python demo/monitor.py'
```

`demo/monitor.py` prints queue counts and persisted scans. After the worker is stopped, the same scan is still available:

```bash
.venv/bin/claimtrace show --package six --version 1.16.0
```

`SCANNER_INGEST=0` keeps the demo deterministic. In production, `SCANNER_INGEST=1` also enables feed polling and automatic enqueueing.

## How the registry scanner works

```
        registry feeds                         watchlist / focus
 (PyPI, crates.io, Go, npm)                          |
 RSS / XML-RPC / NDJSON / _changes                   |
              |                                      |
              +------------------+-------------------+
                                 |
                                 v
                 +-------------------------------+
                 | ingest gates                  |
                 | focus | watchlist | new pkg   |
                 +---------------+---------------+
                                 |
                                 v
                 +-------------------------------+
                 | durable scan_queue            |
                 | priority + backlog scheduler  |
                 +---------------+---------------+
                                 |
                                 v
                 +-------------------------------+
                 | async worker pool             |
                 | claim -> download -> verify   |
                 | extract -> hash -> code-diff  |
                 | static analyzers -> findings  |
                 | score -> static verdict       |
                 | LLM triage (optional)         |
                 +-------+---------------+-------+
                         |               |
          persist + static alert         | detonation eligible
                         v               v
              +------------------+   +-----------------------+
              | SQLite/Postgres  |   | DetonationQueue       |
              | scans/findings   |   +-----------+-----------+
              +------------------+               |
                                                 v
                              +----------------------------------+
                              | detonation worker pool           |
                              | rootless Docker + Tetragon       |
                              | fake DNS + TCP sinkhole          |
                              | re-fetch -> run -> re-score      |
                              +----------------+-----------------+
                                               |
                                               v
                              +----------------------------------+
                              | delayed alert if verdict flips   |
                              | to malicious                     |
                              +----------------------------------+
```

The queue and scan records are durable in SQLite or PostgreSQL. Workers claim items atomically; completed scans, findings, hashes, and decisions survive process restarts.

Static alerting and detonation are separate paths. The scan finalizes on its static verdict and alerts on a static-malicious result (fail-open if the LLM cannot adjudicate). Detonation eligibility is decided during scoring, before LLM triage; an eligible scan is queued and drained by a separate worker pool. That pool re-fetches the archive, executes it under rootless Docker and Tetragon, re-scores the result, and sends a delayed alert only if the verdict flips to malicious.

The local Stage 0 assessment is a separate, single-artifact path:

```
local npm tarball
       |
       v
 /api/v1/assess
       |
       v
 rootless sandbox -> raw events -> claims comparison -> report -> human decision
```

## Detection layers

- AST import analysis and IOC extraction
- Install-time malware patterns and ecosystem-specific install scripts
- Package metadata, typosquatting, and lure-name detection
- YARA signatures and opengrep taint rules
- Version diff and clean-to-critical transitions
- Threat-intel fingerprints (SHA-256, ssdeep, TLSH)
- Obfuscation and packer detection
- UPX unpacking, webcrack deobfuscation, and binary analysis
- npm lifecycle-script analysis, PyPI `setup.py`, crates `build.rs`, and Go directives
- Optional detonation with Tetragon eBPF tracing

opengrep runs in shadow mode by default: findings are retained but excluded from scoring until an operator opts into cutover.

## LLM triage

After static scoring, a suspicious or malicious package can be sent for a second opinion.

- Default provider: CommandCode OpenAI-compatible endpoint
- Default model: `deepseek/deepseek-v4.1-flash`
- Preferred key: `COMMANDCODE_API_KEY`
- Legacy fallback: `OPENROUTER_API_KEY` (automatically selects OpenRouter)
- Override endpoint: `CLAIMTRACE_LLM_BASE_URL`

Triage is bounded by the LLM budget and hourly call limits. It runs only in the registry pipeline; the local Stage 0 assessment stays offline and does not require an API key.

## Ecosystem coverage

| Ecosystem | Coverage | Incremental ingest | Detonation |
|---|---|---|---|
| PyPI | top-10K watchlist + every new package | RSS + XML-RPC cursor | yes |
| crates.io | top-10K watchlist + every new crate | RSS feeds | yes |
| Go modules | ~9K watchlist + brand-new modules | NDJSON cursor | yes |
| npm | top-N watchlist + every new package | CouchDB `_changes` cursor | yes |

Detonation is optional and runs in a separately deployed service on a BTF-enabled Linux host. npm install-time analysis parses `package.json` lifecycle scripts; detonation runs the install with scripts under Tetragon tracing. crates.io and Go builds are best-effort inside the sandbox.

## Intel pack

The engine is open source; detection content is loaded at runtime from an intel pack.

- The public baseline ships in `claimtrace/intel/baseline/` and is licensed under Apache-2.0.
- A private overlay can add YARA rules, hash seeds, IOC whitelists, behavioral chain IDs, keywords, and tuned prompts via `CLAIMTRACE_INTEL_PATH`.
- Additive content is UNIONed with the baseline; scalar tuning replaces the baseline value.
- The engine remains public while operators control their detection content.

See `NOTICE` for third-party YARA licensing.

## Verification

Local verification of this implementation:

- Python: **984 passed, 17 skipped**
- Go detonation suite: **all packages pass**
- Ruff: **all selected checks pass**
- Static demo: **4/4 expected verdicts**
- Local assessment fixtures: clean, declared-sensitive, unexplained-behavior, and lifecycle-failure outcomes verified
- Report rendering is deterministic for the same assessment hash and decision revision

The regression corpus under `tests/corpus/` runs labeled known-bad and known-good samples through the real analyze-and-score path.

## Repository layout

```
claimtrace/        registry scanner, analyzers, queue, LLM triage, local assessment
detonation/        Go detonation service, sandbox, Tetragon, sinkhole
demo/              synthetic samples, local-assessment fixtures, monitor
tests/             unit, integration, and regression-corpus tests
tools/             vault import, parity, statistics, and triage utilities
ARCHITECTURE.md    design, assessment model, controls, and limits
PROJECT.md         problem framing, scope, and acceptance criteria
problem_statement.md
```

## Scope and operational notes

- Schema changes are create-only. New columns on an existing populated database require a manual `ALTER TABLE`.
- Detonation is optional and separately deployed; the standalone quickstart does not enable it.
- crates.io and Go sandbox builds are best-effort. Malicious install-time code is still traced when the build fails.
- The public baseline intel pack is deliberately focused. A private overlay supplies tuned operational detection.
- Local assessment is npm-only; the registry pipeline covers all four ecosystems.
- A local result describes observed behavior and claim mismatches, not proof of malicious intent.

## Security

Report security issues privately to the repository owner rather than opening a public issue that discloses an active vulnerability.

## Acknowledgments

- [t0asts](https://github.com/t0asts) — guidance on the opengrep static-analysis integration.
- [Cyb3rjerry](https://github.com/cyb3rjerry) — the known-malicious dependency gate: tracking packages that take a new dependency on a confirmed-malicious package.

## License

The engine is **AGPL-3.0**; see `LICENSE`. The baseline intel pack in `claimtrace/intel/baseline/` is **Apache-2.0**; see `NOTICE`.
