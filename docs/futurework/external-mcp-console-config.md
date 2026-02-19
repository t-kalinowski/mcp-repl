# Deferred: External `mcp-console` Config File

## Summary

Potential future feature: support `mcp-console --config /path/to/mcp-console.toml`
to keep sandbox policy in a dedicated file instead of long CLI arg lists.

## Motivation

- Better readability than long argument arrays in `~/.codex/config.toml`.
- Easier manual editing and commenting by users.
- Cleaner extension path for additional policy features.

## Possible shape

`~/.codex/config.toml`:

```toml
[mcp_servers.console]
command = "/Users/alice/.cargo/bin/mcp-console"
args = ["--config", "/Users/alice/.codex/mcp-console.toml"]
```

`/Users/alice/.codex/mcp-console.toml`:

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
