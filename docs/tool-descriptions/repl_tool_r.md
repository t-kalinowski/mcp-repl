The r repl tool executes R code in a persistent session. Returns stdout, stderr, and rendered plots.

Arguments:
- `input` (string): R code to execute. Send empty string to poll for output from long-running work.
- `timeout_ms` (number, optional): Max milliseconds to wait (bounds this call only; doesn't cancel backend work).

Behavior:
- Session state (variables, loaded packages) persists across calls. Errors don't crash the session.
- Uses the user's R installation and library paths.

- Plots (ggplot2 and base R) are captured and returned as images. Adjust sizing with `options(console.plot.width, console.plot.height, console.plot.units, console.plot.dpi)`.
- Empty `input` polls for more output from a timed-out request or for detached background output while idle.
- If a request times out, keep polling with empty `input` until the remaining worker output is drained. New non-empty input is discarded while that timed-out request is still active.
- Large output from text-only replies may be compacted to a head/marker/tail preview that includes an absolute `full output:` path to a server-owned worker transcript file.
- Worker transcript files contain worker-originated REPL text such as echoed input, prompts, stdout, and rendered stderr text. Server status lines such as timeout markers stay inline.
- Replies containing any image content remain unchanged; image replies do not use the oversized text preview path in v1.
- Documentation entry points work in-band. Prefer the normal R interfaces such as `?topic`, `help()`, `vignette()`, and `RShowDoc("R-exts")`; the REPL renders their text/HTML output directly instead of launching an external viewer.
- `?topic`, `help()`, `vignette()`, and `RShowDoc()` render directly into the tool response instead of opening a pager.
- Debugging: `browser()`, `debug()`, `trace()`.
- Control: `\u0003` in input interrupts; `\u0004` resets session then runs remaining input.
