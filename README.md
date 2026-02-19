# mcp-console

`mcp-console` is an MCP server that exposes a long-lived interactive REPL over stdio through one tool: `write_stdin`.

The backend is R by default, with an opt-in Python backend (`--backend python`).
Session state persists across calls, so agents can iterate in place, inspect intermediate values, debug, and read docs in-band.

## Why use it

- Stateful REPL execution in one long-lived process.
- LLM-oriented output handling: prompt/echo cleanup and built-in pager mode.
- In-band docs for common help flows (`?`, `help()`, `vignette()`, `RShowDoc()`).
- Plot images returned as MCP image content.
- OS-level sandboxing by default, plus a memory resource guardrail.

### Safe by default

Like a shell, R and Python are powerful. Without guardrails, an LLM can do real damage on the host (both accidental and prompt-induced). To reduce this risk, `mcp-console` runs the backend process in a sandboxed environment. By default, network is disabled and writes are constrained to workspace roots and temp paths required by the worker. Sandbox policy is enforced with OS primitives at the process level, not command-specific runtime rules. On Unix backends, `mcp-console` also enforces a memory guardrail on the child process tree and kills the worker if it exceeds the configured threshold.

### Token efficient

`mcp-console` can be substantially more token efficient for an LLM than a standard persistent shell call. It includes affordances tailored to common LLM workflow strengths and weaknesses. For example:
- There is rarely a need to repeatedly poll, since the console is embedded in the backend and normally returns as soon as evaluation is complete.
- Echoed inputs are automatically pruned or elided so output is easy to attribute.
- A rich pager, purpose-built for an LLM, prevents context floods while supporting search and controlled navigation.
- Documentation receives special handling. Built-in entry points like `?`, `help`, `vignette()`, and `RShowDoc()` are customized to present plain text or converted Markdown in-band, replacing the usual HTML browser flow.

### Pager

The pager activates only when output exceeds roughly one page, and scales from small multi-page outputs to hundreds of pages (for example, navigating the R manuals). It is designed to keep context focused for the model while still allowing deterministic navigation.

Internally, the pager is backed by a bounded ring buffer with an event timeline, not a naive "dump and slice" stream. That gives it predictable memory usage while still supporting strong navigation semantics:
- Output is tracked with stable offsets, so commands like `:seek` (offset/percent/line) and `:range` can jump deterministically.
- Text and image events are merged into one timeline, so pagination decisions can account for both without duplicating content.
- Already-shown ranges and images are tracked explicitly; when overlap occurs, the pager emits offset-based elision markers instead of replaying content.
- UTF-8-aware indexing keeps search and cursor movement aligned to characters while preserving exact byte offsets internally.

These affordances are all driven by observed LLM workflows and aim to reduce token waste while improving access to reference material.

### Plots

`mcp-console` provides a private space for the LLM to easily visualize plots of data. This allows it to iterate safely and privately, without demanding your attention until it can return with a grounded, verified result.

## Quickstart

### 1) Install

#### Prerequisite: Cargo

You need `cargo` (the Rust toolchain). The standard way to install it is `rustup`:

```sh
# See https://rustup.rs for details.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### Install with cargo (from GitHub)

```sh
cargo install --git https://github.com/t-kalinowski/mcp-console --locked
```

This installs `mcp-console` into Cargo’s bin directory (typically `~/.cargo/bin`). Ensure that directory is on your `PATH`.

### 2) Wire into your MCP client

Point your MCP client at the binary (either via `PATH` or by using an explicit path like `~/.cargo/bin/mcp-console` or `target/release/mcp-console`).

You can auto-install into existing agent config files:

```sh
# update existing ~/.codex/config.toml
mcp-console install-codex

# update existing ~/.claude/settings.json (or ~/.claude/config.json)
# Note: there may be some rough edges with Claude.
# This has been primarily developed and tested with Codex.
mcp-console install-claude

# install to all existing agent homes (does not create ~/.codex or ~/.claude)
mcp-console install
```

`install-codex` also runs a one-time `R` probe and annotates
`~/.codex/config.toml` with additional writable roots (outside `cwd`) commonly needed for R
tooling (`cache`, `data`, `config`). When no explicit sandbox configuration flags are already set,
those roots are injected into readable repeatable CLI flags.

Example generated Codex config (paths vary by OS/user):

```toml
[mcp_servers.console]
command = "/Users/alice/.cargo/bin/mcp-console"
# mcp-console additional writable roots outside cwd (install-time R probe):
# - /Users/alice/Library/Caches/org.R-project.R/R
# - /Users/alice/Library/Application Support/org.R-project.R/R
# - /Users/alice/Library/Preferences/org.R-project.R/R
# Re-run `mcp-console install-codex` to refresh this list.
args = [
  "--sandbox-mode", "workspace-write",
  "--sandbox-network-access", "restricted",
  "--writable-root", "/Users/alice/Library/Caches/org.R-project.R/R",
  "--writable-root", "/Users/alice/Library/Application Support/org.R-project.R/R",
  "--writable-root", "/Users/alice/Library/Preferences/org.R-project.R/R",
]
```

For manual Codex config, the entry looks like:

```toml
[mcp_servers.console]
command = "mcp-console"
```

### 3) Pick backend (optional)

- Default backend: R
- CLI: `mcp-console --backend r|python`
- Environment: `MCP_CONSOLE_BACKEND=r|python`

## Runtime discovery

### Backend selection order

`mcp-console` chooses backend in this order:
- `--backend <r|python>` (if provided)
- `MCP_CONSOLE_BACKEND`
- default: `r`

### R backend: which R installation is used

- To force a specific R installation, set `R_HOME` in the environment that launches `mcp-console`.
- If `R_HOME` is not set, `mcp-console` discovers it from `R` on `PATH` (via `R RHOME`).
- To verify which R is active, run `R.home()` in the console session.

### Python backend: which Python installation is used

Interpreter resolution order:
- nearest `.venv/bin/python` from current working directory upward
- nearest `.venv/bin/python3` from current working directory upward
- first executable `python3` on `PATH`
- first executable `python` on `PATH`
- fallback literal `python3`

Notes:
- Upward `.venv` search stops at `$HOME` (inclusive) when applicable, otherwise at filesystem root.
- Python backend starts in basic REPL mode (`PYTHON_BASIC_REPL=1`) and loads `python/driver.py`.

## Platform support

- **macOS / Linux**: supported.
- **Windows**: experimental. Support is in progress.

## Sandbox

Default sandbox policy is `workspace-write` with network disabled.
Write access includes the working area and temp paths required by the worker (exact roots vary by OS/policy).
On Windows, sandbox enforcement is still under active development and is not yet fully functional/reliable across environments.

See `docs/sandbox.md` for precise behavior, runtime updates, and OS-specific details.

## MCP surface

- `write_stdin` -> `{ "chars": "1+1\n", "timeout": 60 }`

The full operator guide for `write_stdin` is in
`docs/tool-descriptions/write_stdin_tool.md`.

## Session endings

- **Interrupt**: `write_stdin("\u0003")` (best-effort SIGINT), session continues when successful.
- **Restart**: `write_stdin("\u0004")`, worker respawns.
- **EOF / `quit()`**: forwarded to R; output is returned, save prompts auto-answer `no`, and a fresh worker starts next request.

## Docs

- Tool behavior and usage guidance: `docs/tool-descriptions/write_stdin_tool.md`
- Sandbox behavior and configuration: `docs/sandbox.md`
- Worker sideband protocol: `docs/worker_sideband_protocol.md`

## License

Apache-2.0. See `LICENSE`.
