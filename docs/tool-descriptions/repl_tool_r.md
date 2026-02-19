`repl` runs source text in a persistent R REPL session and returns emitted stdout/stderr and images.

Arguments:
- `input` (string): bytes to write to backend stdin.
- `timeout_ms` (number, optional): maximum milliseconds to wait before returning.

R REPL affordances:
- Session state persists across calls.
- Pager mode activates on large output. While active, backend input is blocked; use pager commands (for example `:q`, `:/pattern`, `:n`, empty input for next page).
- Plot images are returned as image content. You can tune sizing via `options(console.plot.width, console.plot.height, console.plot.units, console.plot.dpi)`.
- Help/manual flows are in-band (`?topic`, `help()`, `help.search()`, `vignette()`, `RShowDoc()`).
- Debugging workflows are supported (`browser()`, `debug()`, `debugonce()`, `trace()`).
- Control prefixes in `input`: `\u0003` (interrupt) and `\u0004` (reset then run remaining input).
