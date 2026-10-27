#!/usr/bin/env bash
# Reproducible, static-only ClaimTrace demo. Builds synthetic sdists, stores them
# in a throwaway vault, and replays them through the real scan pipeline.
# Nothing in demo/samples is ever installed, imported, or executed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/demo/.work"
VAULT="$WORK/vault"
DB="$WORK/demo.db"
PY="$ROOT/.venv/bin/python"
CLI="$ROOT/.venv/bin/claimtrace"
if [ ! -x "$PY" ]; then PY="python3"; CLI="claimtrace"; fi

# This demo is a deterministic, static-only pipeline replay. Ignore any ambient
# LLM credentials so the documented expected verdicts cannot be changed by a
# live second opinion. Use the separate triage smoke test to exercise CommandCode.
unset CLAIMTRACE_LLM_API_KEY COMMANDCODE_API_KEY OPENROUTER_API_KEY

rm -rf "$WORK"
mkdir -p "$VAULT"

echo "== 1/3  building synthetic sdists =="
"$PY" "$ROOT/demo/build_archives.py" "$WORK/archives"

echo "== 2/3  importing into the demo vault =="
store() {
  CLAIMTRACE_VAULT_PATH="$VAULT" "$PY" "$ROOT/tools/vault_import.py" pypi "$1@1.0.0" \
    --archive "$WORK/archives/$1-1.0.0.tar.gz" --kind sdist --verdict "$2" >/dev/null
  echo "  $1 ($2)"
}
store demo-benign-math clean
store demo-ssh-beacon malicious
store demo-net-beacon suspicious
store demo-ci-token suspicious

echo "== 3/3  replaying through the real pipeline (static only) =="
export CLAIMTRACE_DB_URL="sqlite:///$DB"
export CLAIMTRACE_VAULT_PATH="$VAULT"
export SCANNER_INGEST=0
export CLAIMTRACE_INTEL_PATH="${CLAIMTRACE_INTEL_PATH:-$ROOT/examples/intel-overlay}"
"$CLI" replay --all -y

echo
echo "== results =="
"$PY" "$ROOT/demo/check_results.py" "$DB"
