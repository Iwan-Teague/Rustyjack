# unwrap/expect baseline — justification (AQ-220)

The gate `ci/no_new_unwrap_expect.rs` counts every `unwrap(` / `expect(`
substring in `*.rs` files, skipping only the directories `.git ci target
prebuilt node_modules vendor tests benches`. It does NOT skip inline
`#[cfg(test)]` modules, so unit-test panics inside source files are counted.
The baseline value in `unwrap_expect_baseline.txt` must be a bare integer
(the checker does `content.trim().parse::<u64>()`), so this justification
lives here rather than in a header comment.

## History
- 2026-02-14 (888b6ca): baseline set to 220.
- 2026-09-24 (AQ-220): count at HEAD had grown to 307; re-baselined to 306.

## What the +87 growth since 220 was
Blame of every counted site at HEAD attributes 87 net-new sites to
post-baseline commits. Of these:
- 86 are inside `#[cfg(test)]` modules (idiomatic test-only panics), added by
  test-artifact and isolation/hostapd/systemd/interface-selection test suites.
- 1 was a production-path panic: `system/mod.rs` `redact_webhook_url`
  `Regex::new(...).expect("valid regex")`.

## What changed under AQ-220
The single production-path site was made fail-closed: on the (unreachable)
regex-compile error it now returns a fully-redacted placeholder instead of
panicking, so a logging/error path can neither crash nor leak a webhook token.
That drops the count 307 -> 306.

## Residual remainder (306) and why it is accepted
The remaining post-baseline additions (86) are all `#[cfg(test)]` test code;
panicking in a unit test is idiomatic and is the intended failure mode. They
are counted only because the gate does not exclude inline test modules. No
production-path unwrap/expect was added since the 220 baseline other than the
one fixed above. Pre-baseline production sites are unchanged and out of scope
for AQ-220 (which covers sites added since the baseline was set).
