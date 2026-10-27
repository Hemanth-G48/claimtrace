# ClaimTrace demo intel overlay

A small, **additive** intel pack for demonstrating the `CLAIMTRACE_INTEL_PATH` overlay
mechanism. It is deliberately separate from the shipped baseline
(`claimtrace/intel/baseline/`) so it can be enabled, disabled, and evaluated on its own.

## Enable

```bash
export CLAIMTRACE_INTEL_PATH="$PWD/examples/intel-overlay"
claimtrace run --workers 4          # startup log: intel_loaded source=baseline+<path>
```

Unset the variable (or point it elsewhere) and the rules disappear; no engine code
changes and no baseline rules are touched. YARA rule files are UNION-merged by directory.

## Rules

| Rule | Technique | Matches when |
|------|-----------|--------------|
| `claimtrace_ci_runner_token_exfil` | CI/OIDC token theft (T1552.001) | A CI token env var (`ACTIONS_RUNTIME_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `GITLAB_CI_JOB_TOKEN`) appears in a file that also contains a network send primitive |
| `claimtrace_paste_site_exfil` | Exfil to paste/transfer services (T1567.002) | A paste/transfer host (`pastebin.com/api`, `transfer.sh`, `0x0.st`, `file.io`, `paste.ee`) appears alongside a local data source (`os.environ`, `process.env`, `open(`, `read_text`, `read_bytes`, `base64`) |
| `claimtrace_docker_socket_control` | Container escape / host control (T1611) | `/var/run/docker.sock` appears alongside a container-control primitive (`/containers/create`, `--unix-socket`, `docker exec`) |

Every rule is one file, named after the rule (the loader convention), and requires the
**combination** of a sensitive source and a control/exfil primitive — a single string is
never enough.

## Verify

```bash
.venv/bin/python -m pytest tests/test_intel_overlay.py -q     # compile + fixtures + merge
bash demo/run_demo.sh                                          # end-to-end, case 4 uses this pack
```

Fixtures live in `tests/fixtures/intel_overlay/` (`malicious/` must match, `benign/` must
not). The benign fixtures are the false-positive controls: a CI token that is only
masked for logs, a file-sharing download with no local read, and a Docker SDK client
that talks to the socket without container-control calls.

## Limitations and false positives

- **Text matching, not data-flow.** A comment or documentation string containing both
  halves of a rule will match. These are technique-level heuristics, not proofs.
- **`paste_site_exfil` can hit legitimate upload clients** that read a local file and
  POST it to one of the listed hosts. Tune or disable if that is normal in your estate.
- **`docker_socket_control` can hit tooling that legitimately creates containers**
  (CI helpers, dev scripts). It is a high-signal but not exclusive indicator.
- **No coverage claims.** These three rules neither enumerate every variant of the
  techniques nor replace the baseline's ~30 YARA rules and static analyzers.
- **Not production-tuned.** They exist to demonstrate the overlay path and are licensed
  with the repo (AGPL-3.0-or-later); adapt them in your own private pack.
