#!/usr/bin/env bash
# Every versioned program still loads, and every self-testing one is green.
#
# The `programs-load` job of ci.yml runs exactly this script; run it locally before a PR with the
# binary you just built (it is the gate that caught tests/wasm_sandbox.probe.syn in v0.6.51 only in
# CI):
#
#   SYN=engine/target/debug/synsema tests/programs-load.sh            # Linux / WSL
#   SYN=engine/target/debug/synsema.exe tests/programs-load.sh        # Git Bash on Windows
#
# Run it from the repository root. Pass file paths to check only those programs.
set -uo pipefail

SYN="${SYN:-engine/target/debug/synsema}"
# tests/wasm_pure.probe.syn and tests/wasm_sandbox.probe.syn read this key; it is the well-known
# test vector (private key 1), the same one the wasm job uses.
export ETH_KEY="${ETH_KEY:-0000000000000000000000000000000000000000000000000000000000000001}"

if [ ! -x "$SYN" ]; then
  echo "programs-load: no synsema binary at $SYN (set SYN=...)" >&2; exit 2
fi

fail=0
if [ $# -gt 0 ]; then
  ALL=("$@")
else
  mapfile -t ALL < <(git ls-files '*.syn' '*.fsyn' | sort)
fi
echo "programs under gate: ${#ALL[@]}"
echo "== parse: synsema check (.syn only; check does not read the flat dialect)"
for f in "${ALL[@]}"; do
  case "$f" in *.fsyn) continue ;; esac
  if ! out=$("$SYN" check "$f" 2>&1); then
    echo "::error file=$f::does not parse: $(echo "$out" | head -1)"; fail=1
  fi
done
echo "== load + self-test: synsema test --labels"
for f in "${ALL[@]}"; do
  # Under `bash -e` (the CI shell) a failing ASSIGNMENT kills the script, and this one fails on
  # purpose for a `serve` program (which does not run under `test`). Without the `|| rc=$?` the job
  # died on the first expected case, before printing which one it was.
  rc=0
  out=$(timeout 120 "$SYN" test --labels "$f" 2>&1) || rc=$?
  if [ $rc -eq 0 ]; then
    printf '   ok   %-62s %s\n' "$f" "$(echo "$out" | tail -1)"; continue
  fi
  if echo "$out" | grep -q "serve is only available through the Synsema engine runtime"; then
    printf '   load %-62s (serve program: loads, not runnable under test)\n' "$f"; continue
  fi
  if [ "$f" = "examples/error_demo.syn" ]; then
    printf '   load %-62s (error demo: raises at top level on purpose)\n' "$f"; continue
  fi
  # Cases of the differential oracle that exercise ERROR paths (reference_oracle.rs compares the
  # error of both paths): they end in an error on purpose.
  case "$f" in engine/crates/synsema-runtime/tests/oracle_cases/errors/*)
    printf '   load %-62s (oracle error case: ends in an error on purpose)\n' "$f"; continue ;;
  esac
  echo "::error file=$f::failed to load or its tests failed"
  echo "$out" | head -8 | sed 's/^/      /'
  fail=1
done
if [ "$fail" != "0" ]; then
  echo "::error::at least one versioned program no longer loads"; exit 1
fi
echo "all versioned programs load; every self-testing one is green"
