# Debugging MCP REPL

`mcp-repl` has built-in debugging at a few different layers:

- Internal event logs from inside `mcp-repl`
- Worker startup and sandbox diagnostics
- An external trace proxy that captures the raw stdio traffic between the client and `mcp-repl`

Use the built-in logs when you want to understand what `mcp-repl` thinks happened. Use the external proxy when you need to see the exact bytes that crossed the wire.

## Built-in event logs

Enable per-startup JSONL logs with either:

- `mcp-repl --debug-events-dir /path/to/log-dir`
- `MCP_REPL_DEBUG_EVENTS_DIR=/path/to/log-dir`

Each startup writes a fresh `mcp-repl-*.jsonl` file. The log includes:

- A `startup` record with cwd, argv, backend, and visible `CODEX_*` session hints
- Server lifecycle events such as worker warm start and server listen start/end
- Tool-call events such as `tool_call_begin`, `tool_call_end`, and `tool_call_error`
- Sandbox custom request and notification events

Example:

```sh
mkdir -p /tmp/mcp-repl-events
MCP_REPL_DEBUG_EVENTS_DIR=/tmp/mcp-repl-events mcp-repl --interpreter r
```

## Startup diagnostics

Use startup diagnostics when the worker fails early or startup feels slow.

- `MCP_CONSOLE_DEBUG_STARTUP=1` enables startup logging
- `MCP_CONSOLE_DEBUG_STARTUP_FILE=/path/to/file.log` chooses the log file

If `MCP_CONSOLE_DEBUG_STARTUP=1` is set and the worker has a session temp directory, `mcp-repl` writes the worker-side startup log to `mcp-console-worker-startup.log` inside that temp directory. Otherwise it uses `MCP_CONSOLE_DEBUG_STARTUP_FILE` if set. The default server-side path is `mcp-console-startup.log`.

Example:

```sh
MCP_CONSOLE_DEBUG_STARTUP=1 mcp-repl --interpreter python
```

## MCP and sandbox tracing

These switches are useful when the client is sending custom sandbox updates or when the sandbox policy is the thing you are debugging.

- `MCP_CONSOLE_DEBUG_MCP=1` prints incoming custom MCP request method names to `stderr`
- `MCP_CONSOLE_SANDBOX_STATE_LOG=/path/to/file.jsonl` appends sandbox policy and sandbox-state update payloads as JSON lines
- `MCP_CONSOLE_KEEP_SESSION_TMPDIR=1` keeps the worker session temp directory after exit so you can inspect it
- macOS only: `MCP_CONSOLE_SANDBOX_LOG_DENIALS=1` prints collected sandbox denials when the worker exits

Example:

```sh
MCP_CONSOLE_SANDBOX_STATE_LOG=/tmp/mcp-repl-sandbox.jsonl \
MCP_CONSOLE_DEBUG_MCP=1 \
mcp-repl --sandbox inherit
```

## Interactive debug REPL

`--debug-repl` runs `mcp-repl` as a local interactive driver for the worker instead of as an MCP server. This is the fastest way to reproduce REPL behavior without involving a client.

Start it with:

```sh
mcp-repl --debug-repl --interpreter r
```

Behavior:

- Enter multi-line input and finish it with a line ending in `END`
- Type `INTERRUPT` to send an interrupt
- Type `RESTART` to restart the worker
- Type `Ctrl-D` to exit

Useful environment variables:

- `MCP_CONSOLE_REPL_IMAGES=0|1|kitty` controls inline image rendering in the debug REPL
- `MCP_CONSOLE_PAGER_PAGE_CHARS=<n>` overrides the pager page size if you want larger or smaller pages while debugging

## External wire trace proxy

The built-in event log only sees what reaches `mcp-repl` after startup. If you need the exact stdio traffic between the client and the server, use the external proxy in [scripts/mcp-repl-trace-proxy.py](/Users/tomasz/github/t-kalinowski/mcp-repl/scripts/mcp-repl-trace-proxy.py).

What it does:

- Spawns the real `mcp-repl`
- Forwards client stdin to server stdin
- Forwards server stdout back to the client
- Captures server stderr into the trace log
- Writes both a raw JSONL log and an indented `.pretty.json` log under `.mcp-repl-trace/` in the current working directory

Each captured chunk includes:

- Timestamp and pid
- Stream name and route
- Raw bytes as base64
- UTF-8 text when the chunk decodes cleanly
- Parsed JSON in `text_as_json` when the chunk is line-delimited JSON

Set `MCP_REPL_TRACE_FORWARD_STDERR=1` if you also want the proxied server `stderr` mirrored to your terminal.

Direct invocation:

```sh
scripts/mcp-repl-trace-proxy.py ~/.cargo/bin/mcp-repl --interpreter r
```

Client-config pattern:

```json
{
  "command": "/absolute/path/to/scripts/mcp-repl-trace-proxy.py",
  "args": [
    "/absolute/path/to/mcp-repl",
    "--interpreter",
    "r",
    "--debug-events-dir",
    "/tmp/mcp-repl-events"
  ]
}
```

That setup gives you two views at once:

- The proxy log shows the exact client/server traffic
- The debug-events log shows the internal `mcp-repl` interpretation of that traffic

## Claude clear-hook worktree

The `clean-claude-hook-session-reset` worktree adds Claude-specific debugging that is not on `main`.

Branch-specific surfaces:

- `mcp-repl claude-hook session-start`
- `mcp-repl claude-hook session-end`
- `CLAUDE_ENV_FILE`
- `MCP_REPL_CLAUDE_SESSION_ID`

That worktree also keeps inspectable Claude clear-hook state under:

- `$XDG_STATE_HOME/mcp-repl/claude-clear`
- `~/.local/state/mcp-repl/claude-clear` when `XDG_STATE_HOME` is not set

In that worktree, the JSONL debug log also records:

- `server_name` in the startup payload
- `claude_state_prune_begin`
- `claude_state_prune_end`

Use those only when you are debugging the Claude `/clear` reset flow on that branch.
