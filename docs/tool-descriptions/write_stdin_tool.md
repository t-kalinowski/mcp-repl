`mcp-console` is an MCP server that exposes a long-lived interactive console over stdio. By default it runs an embedded R session, and it can also run an opt-in Python backend at server startup (`--backend python`).

Stateful REPL for computation, experimentation, debugging, and development. Session persists across calls (objects and packages stay loaded). Use persistence for efficiency, not correctness; clear state (e.g. `rm(list = ls())`) or restart the session with `write_stdin("\u0004")` when needed.

## Memory Hygiene (Important)

Long-lived REPL sessions can retain large objects and keep gigabytes of RAM allocated even while idle. When you're basically done with large objects (you no longer expect to reuse them soon), prefer restarting the session via `write_stdin("\u0004")` to aggressively release memory back to the host. This is a guardrail: treat idle memory hoarding as a bug.

## Backend selection

- Default backend: R.
- CLI: `mcp-console --backend r|python`
- Environment: `MCP_CONSOLE_BACKEND=r|python`

## R REPL skill (general use)

The R REPL is your workbench, calculator, and data analysis environment. Use it whenever interactive exploration, quick computation, or grounded inspection will save time and tokens. It is a great tool for narrowing uncertainty, validating assumptions, and iterating on code in tight loops. Prefer it over long, speculative reasoning when you can test or inspect directly. If you are unsure about a value, behavior, or type, use the REPL to find out (do not guess).

Default to using the REPL when it can answer a question faster than reasoning: inspect objects, confirm return values, verify package behavior, test small code paths, and compute intermediate results before committing to a longer solution.

Treat persistence as a tool for development efficiency, not as a guarantee of correctness:
- Keep objects in memory while exploring, iterating, or debugging.
- Reuse loaded packages and intermediate results.
- Clear memory with `rm(list = ls())` or restart the session to reset state. Prefer restarting with `write_stdin("\u0004")` once you don't need large objects anymore.

Accessing documentation (text/markdown in console):
- `?topic` / `help(...)`
- `help(package="pkg")` / `help.search("", package="pkg")` / `library(help="pkg")` / `package?pkg`
- `vignette(package="pkg")` / `vignette("topic", package="pkg")`
- `RShowDoc("R-exts")` for manuals
- `getAnywhere(name)` to inspect source

Recommended work patterns:
- After package edits: `devtools::load_all()` so the REPL reflects current source.
- Use the REPL for small expressions and focused questions.
- If repeated setup is required, place it in an R script and load it with `source("file.R")`.

Debugging and inspection:
- Use `browser()`, `debug()`, and `debugonce()` to interrupt and inspect execution at the point of interest.
- Inside the debugger, use `ls.str()` and `sys.calls()` to see where you are. Send `?` to see debugger commands.
- `trace()` helps observe when and how functions are called (and you can print a stack trace).

Browser-driven development is a reliable pattern:
- Start with a stub implementation: `function(...) { browser() }`
- Trigger the call site.
- Inspect inputs using `str(...)`.
- Incrementally write and evaluate the function body one expression at a time, observing intermediate results before proceeding.

When working on complex R code (especially data manipulation/unpacking/transformations, or string manipulation like `grep()`, `sub()`, `gsub()`, `regexec()`, etc.), avoid "guessing" and avoid defensive try-then-fallback patterns to compensate for uncertainty. Instead, lean into R's interactive strengths: insert `browser()`, step through slowly, and validate assumptions with small, concrete checks. In a duck-typed language like R, this workflow is often the fastest path to simple, readable, correct code, which is typically what the user wants.

Argument checks and expectations:
- Make argument expectations explicit at the start of functions.
- Prefer `stopifnot()` as a lightweight, readable contract.
- Use alternative type-checking frameworks only when project conventions require it.

Pager mode (server-managed):
- Pager mode activates when output is too large and you see `--More--`.
- While the pager is active:
  - empty input (`""`) advances to the next page
  - non-empty pager commands must be `:`-prefixed (e.g. `:q`, `:/pattern`)
  - any other non-empty input is rejected while pager is active (use `:q` to exit pager before sending backend input)
- While the pager is active, the backend prompt is suppressed (you only see pager output + the `--More--` / `(END)` footer). After `q`, the normal REPL prompt returns.
- Output is de-duplicated within the pager session (no repeats).
- In some situations the server may echo a compact summary of the input you sent as a log line like `[mcp-console] input: <first line>.... [TRUNCATED]`. This is not the backend prompt.

Pager commands (recommended minimal set):
- Next page: empty input (send `""`)
- Search forward-only: `:/pattern` (repeat with `:n`)
- All remaining: `:a`
- Quit pager: `:q`
- Help: `:help` (prints the full command list)

Tip: when stuck, run `:help` in pager mode to see the full command list.

Plots drawn on the default graphics device are returned as images.

Plot sizing (R backend):
- Use `options(console.plot.width = 4, console.plot.height = 3)` to set the default plot size.
- Units are set with `options(console.plot.units = "in")` (`"in"` default; also supports `"cm"`, `"mm"`, `"px"`).
- Resolution is set with `options(console.plot.dpi = 100)` (alias: `console.plot.res`; default 96).
- When units are `"px"`, width/height are treated as pixel counts.

Arguments:
- `chars` (string): bytes to write to the console stdin.
- `timeout` (number, optional): maximum seconds to wait before returning (default 60, non-negative).

Timeout behavior: use small positive values (for example `timeout=0.1`) for quick return after launching longer work, then poll with `write_stdin("", timeout=60)` when you want to wait for completion. `timeout=0` is supported as fully non-blocking, but it is usually less useful than a small positive timeout. If the deadline hits, the reply returns a partial snapshot (paged if large) plus a note that the request is still running. The session is not canceled. While it runs, a non-empty `write_stdin` returns a busy status and discards the input; `write_stdin("")` polls for completion and returns any new output. When the session is idle and there is no pending output, `write_stdin("")` returns immediately with an idle status marker.

Sandbox notes:
- In some environments, running commands in a typical bash/shell sandbox may fail due to policy restrictions.
- This console is often configured with targeted allowances for common workflows (depending on the active sandbox policy), especially:
  - `testthat` / `devtools::test()`
  - Building/checking R packages (`R CMD build`, `R CMD check`, `devtools::check()`)
  - `quarto render`
- If a command fails in the shell for sandbox reasons, try running it inside this console instead.

Session endings and crashes:
- `write_stdin` control prefixes at the first character:
  - `\u0003` (Ctrl-C): best-effort interrupt (SIGINT on Unix), then run any remaining input in the same session.
  - `\u0004` (Ctrl-D): restart the session, then run any remaining input in the new session.
  - A separator newline after the control character is optional (`"\u0003foo"` and `"\u0003\nfoo"` both work).
- EOF (`Ctrl-D`, `\u0004`): forwarded to R; if it exits, the worker respawns after the reply. If R asks to save the workspace, the prompt is auto-answered `no` to avoid hangs.
- `quit("no")`: exits without saving; output is returned, then the worker respawns.
- `quit()` / `quit("yes")`: may write a workspace image; if a save prompt appears, it is auto-answered `no`.
- If the worker exits or crashes mid-request, the reply includes captured output (paged if needed) plus a terminal error line.

----

If at any point in using this tool it returns an unexpected error, or you find any behavior
about the console itself confusing or unintuitive, or you have suggestions for how to
make the console better, or this tool description itself better (particular in ways that
would have saved you tokens/context/time, then INFORM THE USER).
