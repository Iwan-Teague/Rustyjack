#!/bin/sh
# rustyjack member gate entrypoint (AQ-148).
#
# tooling/dev-push.sh runs exactly this file -- executable, at this exact
# path -- and advances `development` only on exit 0. "No gates" is not
# "gates passed"; a missing tool fails the run rather than skipping it.
#
# CI parity: .github/workflows/ci.yml runs this same sequence in this same
# order (cheapest-to-fail first). Notes on the two deliberate differences
# from the CI YAML, both mechanical:
#   - the CI job compiles the four custom lint tools in ci/ with rustc and
#     runs them from the repo root (they resolve baselines and allowlists
#     from the current directory); so does this script;
#   - the lab guardrail's output check uses POSIX grep here where CI uses
#     rg -- same predicate ("not allowed in release builds" must appear in
#     the output of a `cargo check --release --features lab` that is
#     REQUIRED to fail), one less binary dependency locally.
set -eu

cd "$(dirname "$0")/../.."

# AQ-233: every gate below compiles rustyjack's Linux-only crates (the
# daemon's dependencies do not build off Linux, and gates 1-4 compile and
# run the custom lint tools from /tmp), so on any other host there is
# nothing this gate can gate. It SKIPs with rc 0 and names the
# authoritative gate: GitHub CI runs this exact script on ubuntu-latest
# on every push (ci.yml "Code Quality Checks"). GATE_RUSTYJACK_FORCE=1
# restores the old hard failure for debugging. On Linux nothing changes:
# all 9 gates still run, unchanged.
if [ "$(uname -s)" != "Linux" ] && [ "${GATE_RUSTYJACK_FORCE:-0}" != "1" ]; then
  printf 'rustyjack local gates: SKIPPED on non-Linux host (%s).\n' "$(uname -s)"
  printf '  These crates are Linux-only and cannot compile here, so a local run\n'
  printf '  cannot gate anything.\n'
  printf '  The authoritative gate is GitHub CI: .github/workflows/ci.yml runs all\n'
  printf '  9 gates on ubuntu-latest on every push.\n'
  exit 0
fi

# AQ-233: run every step below under the toolchain rust-toolchain.toml
# pins -- the one CI gates on -- not the ambient toolchain of the pushing
# host (measured on this project's Mac, AQ-232: a Homebrew cargo ahead of
# the rustup shims makes the pin file alone inert). One guarded re-exec
# under `rustup run` puts the pinned toolchain first on PATH for the
# whole run. Parsing is grep + parameter expansion only. Fail-closed: no
# rustup, an unparsable pin, or an uninstalled pin refuses the gate.
if [ "${GATE_PIN_RESOLVED:-0}" != "1" ] && [ -f rust-toolchain.toml ]; then
  pin=$(grep '^channel = "' rust-toolchain.toml) || {
    printf 'gate FAILED: rust-toolchain.toml has no `channel = "..."` line\n' >&2
    exit 1
  }
  pin=${pin#*\"}
  case $pin in
    *\") pin=${pin%\"} ;;
    *) printf 'gate FAILED: cannot parse the pinned channel from rust-toolchain.toml\n' >&2; exit 1 ;;
  esac
  command -v rustup >/dev/null 2>&1 || {
    printf 'gate FAILED: rustup not found; cannot resolve the pinned toolchain (%s)\n' "$pin" >&2
    exit 1
  }
  rustup run "$pin" true >/dev/null 2>&1 || {
    printf 'gate FAILED: pinned toolchain %s is not installed. Run: rustup toolchain install %s\n' "$pin" "$pin" >&2
    exit 1
  }
  printf 'gate toolchain: %s (%s)\n' "$pin" "$(rustup run "$pin" rustc --version)"
  GATE_PIN_RESOLVED=1 exec rustup run "$pin" sh "$0" "$@"
fi

printf '=== 1/9 forbid Command::new outside allowlist (ci/forbid_command_new.rs) ===\n'
rustc ci/forbid_command_new.rs -o /tmp/forbid_command_new
/tmp/forbid_command_new

printf '=== 2/9 no new unwrap/expect callsites vs baseline (ci/no_new_unwrap_expect.rs) ===\n'
rustc ci/no_new_unwrap_expect.rs -o /tmp/no_new_unwrap_expect
/tmp/no_new_unwrap_expect

printf '=== 3/9 no blocking calls in async contexts (ci/no_blocking_in_async.rs) ===\n'
rustc ci/no_blocking_in_async.rs -o /tmp/no_blocking_in_async
/tmp/no_blocking_in_async

printf '=== 4/9 no emoji in source (ci/no_emoji_in_source.rs) ===\n'
rustc ci/no_emoji_in_source.rs -o /tmp/no_emoji_in_source
/tmp/no_emoji_in_source

printf '=== 5/9 cargo fmt --all --check ===\n'
cargo fmt --all --check

printf '=== 6/9 cargo deny check advisories bans sources ===\n'
cargo deny check advisories bans sources

printf '=== 7/9 cargo check --workspace ===\n'
cargo check --workspace

printf '=== 8/9 lab-feature release guardrail (must refuse) ===\n'
set +e
lab_out=$(cargo check --release -p rustyjack-daemon --features lab 2>&1)
lab_rc=$?
set -e
if [ "$lab_rc" -eq 0 ]; then
  printf 'gate 8/9 FAILED: lab feature built in release; guardrail missing\n'
  exit 1
fi
printf '%s\n' "$lab_out" | grep -q "not allowed in release builds" || {
  printf 'gate 8/9 FAILED: release guardrail did not trigger\n'
  exit 1
}

printf '=== 9/9 cargo test --workspace ===\n'
cargo test --workspace

printf 'All 9 rustyjack gates passed.\n'
