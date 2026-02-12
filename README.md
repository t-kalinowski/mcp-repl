# mcp-console

`mcp-console` is an MCP server that exposes a long-lived interactive REPL (R or Python) over stdio. It gives an LLM agent a persistent workbench where it can keep session state across calls, iterate quickly, debug in place, read docs in-band, and view plot images through a single tool designed for safety and token efficiency.

Instead of treating each tool call as isolated, `mcp-console` enables a continuous workflow. An agent can load data once, refine code incrementally in a live process, step through a debugger, inspect intermediate results, consult documentation without leaving the session, and navigate large outputs safely.

## Why use it

- **Faster iteration**: keep state in one process instead of repeatedly re-initializing context.
- **Safer execution**: run inside an OS sandbox with restricted writes and network disabled by default.
- **Lower token cost**: avoid context floods with LLM-oriented output shaping and paging.
- **Better in-band tooling**: debugging, docs, and plots stay in the same interactive surface.

## Safe by default

Like a shell, R and Python are powerful. Without guardrails, an LLM can do real damage on the host (both accidental and prompt-induced). To reduce this risk, `mcp-console` runs the backend process in a sandboxed environment. By default, network is disabled and writes are limited to the current working directory. Sandbox policy is enforced with OS primitives at the process level, not command-specific runtime rules.

## Token efficient

`mcp-console` can be substantially more token efficient for an LLM than a standard persistent shell call. It includes affordances tailored to common LLM workflow strengths and weaknesses. For example:
- There is rarely a need to repeatedly poll, since the console is embedded in the backend and returns as soon as evaluation is complete.
- Echoed inputs are automatically pruned or elided so output is always easy to attribute.
- A rich pager, purpose-built for an LLM, prevents context floods while supporting search and controlled navigation. It never shows duplicate content and activates only when output exceeds roughly one page, scaling from small multi-page outputs to hundreds of pages (e.g., navigating the R manuals).
- Documentation receives special handling. Built-in entry points like `?`, `help`, `vignette()`, and `RShowDoc()` are customized to present plain text or converted Markdown in-band, replacing the usual HTML browser flow.

These affordances are all driven by observed LLM workflows and aim to reduce token waste while improving access to reference material.

## Plots

`mcp-console` provides a private space for the LLM to quickly visualize plots of data. This allows it to iterate safely and privately, without demanding your attention until it can return with a grounded, verified result.

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

For manual Codex config, the entry looks like:

```toml
[mcp_servers.mcp-console]
command = "mcp-console"
```

### 3) Pick backend (optional)

- Default backend: R
- CLI: `mcp-console --backend r|python`
- Environment: `MCP_CONSOLE_BACKEND=r|python`


## Core capabilities

- **Stateful session**: `write_stdin` evaluates text in one persistent backend process.
- **Backends**: embedded R by default; optional Python with `--backend python`.
- **Image output**: plots are returned as image content (R graphics device; Python when `matplotlib` is available).
- **LLM-friendly docs**: `?topic`, `help()`, `vignette()`, and `RShowDoc()` are routed toward text/markdown output in-band.
- **Pager mode**: large output is paged with explicit commands (`""`, `:help`, `:/pattern`, `:n`, `:a`, `:q`).

## Platform support

- **macOS / Linux**: supported.
- **Windows**: not yet (coming soon!)

## Sandbox

By default, `mcp-console` runs the backend worker in an OS sandbox intended to match Codex-style
restrictions: broad reads, constrained writes, and restricted network access.

Defaults (when MCP client does not provide sandbox configuration):
- **Network**: disabled.
- **Writes**: current working directory + per-session temp directory. On macOS, `.git/`, `.codex/`,
  and `.agents/` under writable roots are forced read-only.
- **Reads**: broad local reads for source trees, libraries, and docs.

Configuration:
- CLI: `mcp-console --sandbox-state read-only|workspace-write|danger-full-access`
- MCP: some clients (including Codex) can update sandbox state at runtime via an experimental capability.

macOS proxy-aware network mode:
- With `network_access: true`, proxy env vars (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, plus lowercase variants) are inspected.
- Loopback proxy endpoints (for example `127.0.0.1:8080`) are allowlisted for outbound.
- Proxy configured but no usable loopback endpoint: fail closed (no network).
- `MCP_CONSOLE_MANAGED_NETWORK=1`: enforce proxy-only mode (no valid loopback proxy => no network).
- `ALLOW_LOCAL_BINDING=1`: additionally allow localhost bind/inbound operations.

Linux bubblewrap mode (opt-in):
- `MCP_CONSOLE_USE_LINUX_BWRAP=1`: run Linux sandbox helper via `bwrap` before inner seccomp/Landlock stage.
- By default, tries fresh `/proc`; retries automatically without `/proc` when unsupported.
- `MCP_CONSOLE_LINUX_BWRAP_NO_PROC=1`: skip `/proc` mounting preemptively.
- If `bwrap` is missing, worker startup fails fast with a sandbox error.

## MCP surface

- `write_stdin` -> `{ "chars": "1+1\n", "timeout": 60 }`
- Control prefixes:
  - `"\u0003"` (Ctrl-C): best-effort interrupt
  - `"\u0004"` (Ctrl-D): restart

The `write_stdin` tool description is intentionally detailed and acts as an operator guide for the
LLM: debugger workflow, docs/source access, session control, and pager behavior.

## Session endings

- **Interrupt**: `write_stdin("\u0003")` (best-effort SIGINT), session continues when successful.
- **Restart**: `write_stdin("\u0004")`, worker respawns.
- **EOF / `quit()`**: forwarded to R; output is returned, save prompts auto-answer `no`, and a fresh worker starts next request.

## Docs

- Tool behavior and usage guidance: `docs/tool-descriptions/write_stdin_tool.md`
- Worker sideband protocol: `docs/worker_sideband_protocol.md`
- Notes/eval ideas: `docs/notes/eval_suite_ideas.md`

## License

Apache-2.0. See `LICENSE`.
