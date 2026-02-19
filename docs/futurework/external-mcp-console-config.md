# Deferred: External `mcp-repl` Config File

## Summary

Potential future feature: support `mcp-repl --config /path/to/mcp-repl.toml`
to keep sandbox policy in a dedicated file instead of long CLI arg lists.

## Motivation

- Better readability than long argument arrays in `~/.codex/config.toml`.
- Easier manual editing and commenting by users.
- Cleaner extension path for additional policy features.

## Possible shape

`~/.codex/config.toml`:

```toml
[mcp_servers.repl]
command = "/Users/alice/.cargo/bin/mcp-repl"
args = ["--config", "/Users/alice/.codex/mcp-repl.toml"]
```

`/Users/alice/.codex/mcp-repl.toml`:

```toml
[sandbox]
mode = "workspace-write"
network_access = false
writable_roots = [
  "/Users/alice/Library/Caches/org.R-project.R/R",
  "/Users/alice/Library/Application Support/org.R-project.R/R",
]
```

## Notes

- This is intentionally deferred.
- Current implementation uses explicit repeatable CLI flags:
  - `--sandbox-mode`
  - `--sandbox-network-access`
  - `--writable-root`
