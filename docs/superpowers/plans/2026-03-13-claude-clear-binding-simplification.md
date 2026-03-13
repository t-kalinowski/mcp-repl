# Claude Clear Binding Simplification Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the heuristic Claude session handoff model with one-time per-process binding keyed by `CLAUDE_ENV_FILE`, so `/clear` only resets the exact owning session and concurrent same-directory Claude sessions remain isolated.

**Architecture:** Keep Claude clear state local to each running server instance. Remove project-state and rebinding logic from `src/claude.rs`, make `SessionStart` append-only, make `SessionEnd(clear)` match exact `(env_file_path, session_id)`, and preserve the existing late-bind restart behavior only for the server’s own worker.

**Tech Stack:** Rust, cargo test, cargo clippy, cargo +nightly fmt

---

## Chunk 1: Contract Rewrite

### Task 1: Rewrite the public regression surface around the reduced contract

**Files:**
- Modify: `tests/claude_clear_binding.rs`
- Modify: `tests/sandbox_state_updates.rs`
- Reference: `docs/superpowers/specs/2026-03-13-claude-clear-binding-simplification-design.md`

- [ ] **Step 1: Write failing contract tests in `tests/claude_clear_binding.rs`**

Keep these exact surviving tests and make sure their assertions match the reduced contract:

- `claude_clear_restart_binds_after_session_start_hook`
  - start a server after `SessionStart`
  - assert the first bound request succeeds under that session
- `claude_clear_late_session_binding_restarts_prebound_worker_state`
  - create interpreter state before binding
  - trigger `SessionStart`
  - assert the first bound request sees a fresh worker, not the pre-bind state

Add these exact new tests:

```rust
#[tokio::test]
async fn claude_clear_matches_exact_env_file_and_session() -> TestResult<()> {
    // Create worker A and worker B with the same session id string but different
    // CLAUDE_ENV_FILE paths. Clear through env file B. Assert B resets and A keeps state.
}

#[tokio::test]
async fn claude_clear_ignores_later_session_start_after_server_is_bound() -> TestResult<()> {
    // Bind worker A, create state, then fire SessionStart for session B.
    // Assert a later request on A still sees A's state, and SessionStart(B) does not restart A.
}

#[tokio::test]
async fn claude_clear_concurrent_same_directory_sessions_do_not_reset_each_other() -> TestResult<()> {
    // Run two workers in the same cwd with distinct env files and session ids.
    // Clear A and assert B still has its state.
}
```

Delete or rewrite tests that depend on:
- project-state handoff
- previous-session matching
- stale-marker recovery
- shared-env-file rollover
- rebinding after normal exit

- [ ] **Step 2: Run the targeted regression tests and confirm RED**

Run:

```bash
cargo test --test claude_clear_binding claude_clear_matches_exact_env_file_and_session -- --exact
cargo test --test claude_clear_binding claude_clear_ignores_later_session_start_after_server_is_bound -- --exact
cargo test --test claude_clear_binding claude_clear_concurrent_same_directory_sessions_do_not_reset_each_other -- --exact
```

Expected:
- at least the new tests fail for missing or still-heuristic behavior

- [ ] **Step 3: Write the late-bind sandbox regression in `tests/sandbox_state_updates.rs` if the existing test no longer expresses the new contract**

Keep the existing test name `sandbox_inherit_late_claude_binding_allows_first_sandbox_update`.
Rewrite its assertions only if needed so it proves:

```rust
#[tokio::test]
async fn sandbox_inherit_late_claude_binding_allows_first_sandbox_update() -> TestResult<()> {
    // A late-bound worker in sandbox-inherit mode accepts the first sandbox update
    // before the forced restart is applied.
}
```

- [ ] **Step 4: Run the targeted sandbox regression and confirm RED if behavior changed**

Run:

```bash
cargo test --test sandbox_state_updates sandbox_inherit_late_claude_binding_allows_first_sandbox_update -- --exact
```

Expected:
- fail only if the new contract requires a test rewrite

- [ ] **Step 5: Commit the red tests**

```bash
git add tests/claude_clear_binding.rs tests/sandbox_state_updates.rs
git commit -m "test: rewrite Claude clear contract regressions"
```

### Task 2: Simplify `src/claude.rs` to one-time binding

**Files:**
- Modify: `src/claude.rs`
- Test: `tests/claude_clear_binding.rs`
- Test: in-file unit tests in `src/claude.rs`
- Reference: `docs/superpowers/specs/2026-03-13-claude-clear-binding-simplification-design.md`

- [ ] **Step 1: Remove unsupported state and helpers**

Delete or inline the parts of `src/claude.rs` that only exist for rebinding:

- `CLAUDE_PROJECT_DIR_ENV`
- `HandoffSource`
- `ProjectSessionRecord`
- `EnvFileSessionRecord`
- project session directory/path helpers
- env-file activity helpers
- stale marker helpers
- `previous_claude_session_id`
- `project_dir`
- `last_seen_unix_ms`
- `rebind_instance_records_for_session`

Keep only the instance record and control request machinery needed for exact-session targeting.

Rewrite or delete the in-file unit tests that cover removed behavior:
- delete `session_end_hook_matches_previous_session_id_during_rebind`
- delete `current_claude_session_id_prefers_project_state_over_stale_env`
- delete `maybe_register_requires_claude_project_dir_for_project_state_lookup`
- replace them with exact-session/env-file tests only

- [ ] **Step 2: Implement exact env-file binding**

Refactor binding registration so it reads only from `CLAUDE_ENV_FILE`, with a single parser rule:

```rust
fn current_claude_session_from_env_file() -> Option<(PathBuf, String)> {
    let env_file_path = env::var_os(CLAUDE_ENV_FILE_ENV).map(PathBuf::from)?;
    let session_id = read_session_id_from_env_file(Some(&env_file_path))?;
    Some((env_file_path, session_id.trim().to_string()))
}
```

Requirements:
- return `None` when `CLAUDE_ENV_FILE` is absent or unreadable
- last valid export wins
- no `CLAUDE_PROJECT_DIR` fallback
- no `MCP_REPL_CLAUDE_SESSION_ID` fallback during binding

- [ ] **Step 3: Make the instance record immutable after bind**

After `maybe_register` or `maybe_register_late` succeeds:
- write a single instance record containing `claude_session_id`, `env_file_path`, backend metadata, and `control_path`
- do not rewrite ownership in `sync()`
- keep late binding by seeding a restart request for late-bound registrations only

- [ ] **Step 4: Make hooks exact and append-only**

Implement:

```rust
fn handle_session_start(input: &HookInput) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = input.session_id.trim();
    // validate SessionStart and append export, inserting a separator newline when needed
}

fn handle_session_end(input: &HookInput) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = input.session_id.trim();
    // only reason == "clear"
    // read hook CLAUDE_ENV_FILE
    // restart records whose session_id and env_file_path both match exactly
}
```

Requirements:
- missing/unreadable hook-side `CLAUDE_ENV_FILE` is a no-op
- no previous-session matching
- no rebinding
- no normal-exit cleanup ledgers

- [ ] **Step 5: Run the focused Claude clear tests and make them GREEN**

Run:

```bash
cargo test --bin mcp-repl claude::tests::
cargo test --test claude_clear_binding
```

Expected:
- the rewritten `src/claude.rs` unit tests pass via the binary test target
- all remaining tests in `tests/claude_clear_binding.rs` pass

- [ ] **Step 6: Commit the core simplification**

```bash
git add src/claude.rs tests/claude_clear_binding.rs
git commit -m "refactor: simplify Claude clear binding ownership"
```

### Task 3: Keep late-bind restart behavior without reintroducing rebinding

**Files:**
- Modify: `src/server.rs`
- Modify: `tests/sandbox_state_updates.rs`
- Test: `tests/claude_clear_binding.rs`

- [ ] **Step 1: Keep unbound servers retrying late registration on each request**

Ensure the server loop still does:

```rust
if claude_clear_binding.is_none() {
    *claude_clear_binding = ClaudeClearBinding::maybe_register_late(backend)?;
}
```

But after a binding exists:
- never replace it with a new Claude session
- let `binding.sync()` only handle control-file restarts for that same binding

- [ ] **Step 2: Preserve inherited-sandbox deferral**

The ordering in `run_worker()` should continue to avoid restarting a late-bound worker before the initial inherited sandbox state arrives.

- [ ] **Step 3: Run the targeted sandbox and late-bind tests**

Run:

```bash
cargo test --test sandbox_state_updates
cargo test --test claude_clear_binding claude_clear_late_session_binding_restarts_prebound_worker_state -- --exact
```

Expected:
- both pass with the simplified one-time binding model

- [ ] **Step 4: Commit the server-side follow-through**

```bash
git add src/server.rs tests/sandbox_state_updates.rs tests/claude_clear_binding.rs
git commit -m "fix: keep late Claude binding restart scoped to one server"
```

### Task 4: Final cleanup and full verification

**Files:**
- Modify: `src/claude.rs`
- Modify: `src/server.rs`
- Modify: `tests/claude_clear_binding.rs`
- Modify: `tests/sandbox_state_updates.rs`

- [ ] **Step 1: Remove any leftover dead code or imports from deleted rebinding paths**

This includes:
- unused constants
- unused helper functions
- stale tests or helper fixtures that only supported project-state handoff
- removed in-file `src/claude.rs` unit tests for previous-session matching and project-state fallback

- [ ] **Step 2: Run formatting and the full project verification suite**

Run:

```bash
cargo +nightly fmt
cargo check
cargo build
cargo clippy
cargo test
```

Expected:
- all commands exit 0

- [ ] **Step 3: Commit the finished rewrite**

```bash
git add src/claude.rs src/server.rs tests/claude_clear_binding.rs tests/sandbox_state_updates.rs
git commit -m "refactor: reduce Claude clear binding to a sound contract"
```
