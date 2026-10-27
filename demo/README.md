# ClaimTrace demo — offline, static-only

Four synthetic packages, replayed through the **real scan pipeline** (extract → static
analyzers → score → verdict). No registry traffic, no LLM key, no Discord webhook, and
nothing is installed or executed: the samples are only ever read as bytes.

## Run it

```bash
cd claimtrace
bash demo/run_demo.sh
```

The script builds sdists from `demo/samples/`, imports them into a throwaway vault under
`demo/.work/` (gitignored), and calls:

```bash
CLAIMTRACE_VAULT_PATH=demo/.work/vault \
CLAIMTRACE_DB_URL=sqlite:///demo/.work/demo.db \
CLAIMTRACE_INTEL_PATH=examples/intel-overlay \
SCANNER_INGEST=0 \
claimtrace replay --all -y
```

It exits non-zero if any verdict differs from the expected value below.

## Verified results (2026-10-26, Python 3.11.15)

| # | Package | Expected | Actual | Score | Evidence |
|---|---------|----------|--------|-------|----------|
| 1 | `demo-benign-math` | clean | clean | 0 | no findings |
| 2 | `demo-ssh-beacon` | malicious | malicious | 60 | `malware.credential_store_sweep` (critical), `yara.ssh_key_exfiltration` (critical) |
| 3 | `demo-net-beacon` | suspicious | suspicious | 25 | `imports.network_at_import` (high) |
| 4 | `demo-ci-token` | suspicious | suspicious | 25 | `yara.claimtrace_ci_runner_token_exfil` (high, overlay only) |

Case 4 is the overlay demonstration: with `CLAIMTRACE_INTEL_PATH` **unset** the same
sample scans **clean / score 0**. Set it to `examples/intel-overlay` and the demo rule
fires. Verify the baseline result yourself:

```bash
CLAIMTRACE_VAULT_PATH=$PWD/demo/.work/vault \
CLAIMTRACE_DB_URL=sqlite:///$PWD/demo/.work/baseline.db \
CLAIMTRACE_INTEL_PATH= SCANNER_INGEST=0 \
claimtrace replay --package demo-ci-token -y
claimtrace show --package demo-ci-token --version 1.0.0
```

## What each case exercises

1. **Benign baseline.** A normal utility with no suspicious behavior; guards against
   false positives in the demo itself.
2. **Credential sweep + exfiltration.** Reads two synthetic SSH keys, a fake
   `~/.aws/credentials`, and a fake `~/.npmrc`, then POSTs them. Exercises the
   credential-store-sweep analyzer and the YARA SSH-exfil rule. Paths point at
   `/home/demo-user` (which does not exist) and the endpoint is a reserved
   `.invalid` domain, so accidental execution cannot read or send anything real.
3. **Unexpected network at import.** `urlopen()` runs at module import; exercises
   `imports.network_at_import`.
4. **CI token exfil.** Reads `ACTIONS_RUNTIME_TOKEN` and POSTs it; caught only when the
   demo overlay is loaded, which shows the baseline/overlay split.

## Limitations

- **Static analysis only.** Detonation (rootless Docker + Tetragon) is not used or
  required; no runtime/trace events are produced.
- **LLM triage and Discord are not demonstrated.** With no `OPENROUTER_API_KEY`, triage
  is skipped and scans carry `alert_tag=llm_unverified`; with no `DISCORD_WEBHOOK_URL`,
  no alert is sent. Both are graceful, not errors.
- **The samples are deliberately simple.** A verdict here proves the wiring works, not
  that the rules generalise; see `tests/` and `docs/detection-rules.md` for coverage.
- **Do not install or import `demo/samples/`.** They are analysis fixtures, not packages.
- The demo vault and DB live in `demo/.work/` and are gitignored; delete the directory to
  reset.

## Background scanner demo (persistent worker)

This demonstrates the scanner as a long-running worker rather than a one-shot replay.

Terminal A:

```bash
cd /home/hemanth/hackathon/claimtrace
export CLAIMTRACE_DB_URL="sqlite:///$PWD/demo/.work/background.db"
SCANNER_INGEST=0 .venv/bin/claimtrace run --workers 1
```

Terminal B:

```bash
cd /home/hemanth/hackathon/claimtrace
export CLAIMTRACE_DB_URL="sqlite:///$PWD/demo/.work/background.db"

# Queue a real package manually; the running worker claims and scans it.
.venv/bin/claimtrace rescan --package six --version 1.16.0

# Watch queue state and persisted scans update.
watch -n 2 '.venv/bin/python demo/monitor.py'

# The completed scan survives after the worker is stopped.
.venv/bin/claimtrace show --package six --version 1.16.0
```

`SCANNER_INGEST=0` keeps the demo deterministic by disabling feed polling. In
production, use `SCANNER_INGEST=1` (the default) so the scheduler also polls the
four registries and enqueues new releases automatically.

## Milestone 2 — local assessment fixtures

`demo/m2/` contains separate **real-execution** fixtures for the local-artifact
assessment path; they are not used by `run_demo.sh` and are not installed on the host.
They are inert and only run inside the rootless-Docker assessment container:

| Fixture | Purpose |
|---|---|
| `string-format-demo` | README claims a formatter; entry/import read a decoy `~/.ssh/id_rsa` |
| `clean-demo` | formatter with no sensitive behavior; `no mismatch found` + `coverage unverified` |
| `declared-demo` | README names `~/.ssh`; result is `review: declared-sensitive` |
| `crash-demo` | reads the decoy then crashes; observation survives the failure |
| `lifecycle-fail-demo` | postinstall reads the decoy then exits 7; install phase is failed |
| `no-readme-demo` | no README; claims unavailable, sensitive observations still reported |
| `esm-demo` | ESM `type: module` import path |
| `network-demo` | resolves `unclaimed.example` and connects to it; sinkhole records DNS + TCP |
| `one-shot-demo` | one entry-only credential read; used for live missing-raw fault injection |

Use the checklist in `docs/MILESTONE_2_IMPLEMENTATION.md`. Tetragon v1.7.1 is installed
as a rootful agent and the local runner uses `ASSESS_CAPTURE=tetragon`. The package runs on
an `--internal` bridge with a trusted fake-DNS/TCP sinkhole; coverage remains `unverified`
because file/process event loss is not measured and the sinkhole captures only common TCP
ports. See the scoped PASS and limits in `docs/MILESTONE_2_IMPLEMENTATION.md`.
