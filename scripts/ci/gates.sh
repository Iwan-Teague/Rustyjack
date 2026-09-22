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
