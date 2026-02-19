`repl` runs source text in a persistent Python REPL session and returns emitted stdout/stderr and images.

Arguments:
- `input` (string): bytes to write to backend stdin.
- `timeout_ms` (number, optional): maximum milliseconds to wait before returning.

Python REPL affordances:
- Session state persists across calls.
- Pager mode activates on large output. While active, backend input is blocked; use pager commands (for example `:q`, `:/pattern`, `:n`, empty input for next page).
- Plot images are returned as image content (for example matplotlib output).
- Help flows are in-band (`help()`, `dir()`, `pydoc.help`).
- Debugging workflows are supported (`breakpoint()`, `pdb.set_trace()`).
- Control prefixes in `input`: `\u0003` (interrupt) and `\u0004` (reset then run remaining input).
