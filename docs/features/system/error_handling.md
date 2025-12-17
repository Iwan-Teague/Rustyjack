# Error Handling Guidelines

Supersedes:
- `ERROR_HANDLING_IMPROVEMENTS.md`
- `ERROR_HANDLING_ENHANCEMENT.md`
- `ERROR_HANDLING_REVIEW.md`

## Current posture
- Production code avoids `.unwrap()`/`.expect()`; rich `Result` errors with context.
- Mutex locks use descriptive errors instead of panics.
- Path handling avoids double-unwraps; fallbacks used where needed.

## Practices to follow
- Always bubble context: include interface names, operations, and external command details in errors.
- Prefer typed error enums per crate/module; keep `anyhow` at boundaries if needed.
- For background threads, log and propagate via channels rather than panicking.
- In tests, `.unwrap()` is acceptable.

## Known exceptions
- Some internal crypto calls still use `expect` with hardcoded key sizes (acceptable risk).
- Legacy modules may still have unwraps; refactor opportunistically.
