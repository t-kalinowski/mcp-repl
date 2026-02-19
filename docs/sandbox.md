# Sandbox

`mcp-console` applies an OS sandbox to worker processes unless the sandbox policy is
`danger-full-access` (or `external-sandbox`).

## Default policy

When no sandbox update is provided by the MCP client, the default is:

- `workspace-write`
- `network_access: false`

The worker also gets a per-session temp directory, exported as:

- `TMPDIR`
- `MCP_CONSOLE_R_SESSION_TMPDIR`

## Configure sandbox policy

- CLI mode: `mcp-console --sandbox-mode read-only|workspace-write|danger-full-access`
- CLI network toggle (workspace-write only): `mcp-console --sandbox-network-access restricted|enabled`
- CLI writable roots (workspace-write only, repeatable): `mcp-console --writable-root /absolute/path`
- MCP custom method: `codex/sandbox-state/update` (experimental capability `codex/sandbox-state`)

## macOS behavior

Sandboxing is enforced via `sandbox-exec`.

For `workspace-write`, writable roots include:

- configured `writable_roots` (absolute paths only),
- current working directory,
- R `cache`/`data`/`config` roots configured in client policy (for Codex configs installed via `mcp-console install-codex`, this is auto-populated at install time via a one-time `R` probe),
- temp roots (`/tmp`, `TMPDIR` when absolute), and
- the per-session temp directory.

Within writable roots, these subpaths are forced read-only when present:

- `.git`
- `.codex`
- `.agents`

Proxy-aware network behavior when `network_access: true`:

- proxy env vars are inspected (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and lowercase variants),
- loopback proxy endpoints are allowlisted for outbound traffic,
- proxy configured but no usable loopback endpoint => fail closed (no network),
- `MCP_CONSOLE_MANAGED_NETWORK=1` enforces proxy-only mode,
- `ALLOW_LOCAL_BINDING=1` additionally allows localhost bind/inbound operations.

## Linux behavior

Sandboxing is enforced by a Linux sandbox helper that applies seccomp + Landlock.

- `workspace-write` always includes the per-session temp directory in writable roots.
- `read-only` is translated to a minimal writable setup for the session temp directory only.
- default Linux worker setup disables network unless explicitly enabled.

Optional `bwrap` stage:

- `MCP_CONSOLE_USE_LINUX_BWRAP=1` enables a bubblewrap outer sandbox.
- `MCP_CONSOLE_LINUX_BWRAP_NO_PROC=1` skips `/proc` mounting.
- if `bwrap` is requested but unavailable, worker startup fails fast.

## Windows status

Current worker/sideband flow is Unix-focused; Windows is not currently supported.
