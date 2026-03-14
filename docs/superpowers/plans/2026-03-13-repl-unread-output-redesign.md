# REPL Unread Output Redesign Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace ring-based unread tracking and transport-coupled overflow retention with server-owned unread batching, destructive drains, and per-reply overflow artifacts that match the redesign spec.

**Architecture:** Move unread capture ownership into a server-owned `PendingOutput` store that survives idle periods and session lifecycle transitions until the next tool response drains it. Keep the existing always-on stdout/stderr reader threads, but append into `PendingOutput` instead of the global ring. Rebuild reply formatting around one drained batch per tool call: send the request, wait until the REPL is idle or timed out, then format all output collected since the previous tool response. Small batches stay inline; oversized batches get a total-budget head-and-tail preview plus a self-contained retained artifact for that reply only.

**Tech Stack:** Rust, Tokio, rmcp, tempfile, serde, integration tests in `tests/*.rs`, snapshot tests via insta

---

## File Map

- Create: `src/pending_output.rs` — server-owned unread-output store, in-memory/spill states, destructive drain API, internal stale-reader guard, latched capture-failure state
- Create: `src/server/reply_batch.rs` — turn one drained batch into MCP content, head-and-tail preview builder, input echo and prompt cleanup integration, preserved echo-collapse behavior
- Create: `src/server/overflow_artifacts.rs` — retained per-reply artifact writer and eviction policy
- Modify: `src/main.rs` — register the new `pending_output` module
- Modify: `src/server.rs` — own `PendingOutput` and overflow artifacts, simplify `repl` request lifecycle, keep `codex/overflow-response-consumed` as a no-op
- Modify: `src/debug_repl.rs` — keep the standalone debug REPL compiling if `WorkerManager::new(...)` or reply formatting ownership changes
- Modify: `src/worker_process.rs` — route reader-thread output into `PendingOutput`, preserve echo-collapse behavior, keep lifecycle requests on the same unread-drain path, and simplify `write_stdin`/poll/control-byte behavior around wait-for-idle and destructive drains
- Modify: `src/worker_protocol.rs` — remove reply fields that only exist to describe ring truncation
- Delete: `src/output_capture.rs` — old ring-buffer capture and replay-gap truncation logic
- Delete: `src/server/response.rs` — move surviving logic into `reply_batch.rs` and `overflow_artifacts.rs`
- Modify: `tests/common/mod.rs` — stop expecting overflow ack metadata and add server env wiring for public overflow write-failure coverage
- Modify: `tests/write_stdin_batch.rs` — non-overlapping batch, background output, poll/wait semantics, huge echo preservation
- Modify: `tests/interrupt.rs` — combined `\u0003`/`\u0004` plus remaining-input semantics
- Modify: `tests/session_endings.rs` — session-end output and respawn output in one later reply
- Modify: `tests/manage_session_behavior.rs` — respawn/reset lifecycle semantics and unread co-batching
- Modify: `tests/repl_surface.rs` — `repl_reset` lifecycle semantics on the same unread-drain path
- Modify: `tests/plot_images.rs` — oversized reply artifact/retention behavior and head-and-tail previews
- Modify: `tests/python_plot_images.rs` — long-line preview slicing and image-path preview rules
- Modify: `tests/python_backend.rs` — replace the old truncation-contract assertion with the new spill-backed unread contract
- Modify: `tests/r_file_show.rs` — visible overflow wording if file-overflow assertions need updating
- Modify: `docs/tool-descriptions/repl_tool_r.md`
- Modify: `docs/tool-descriptions/repl_tool_python.md`
- Modify: `docs/tool-descriptions/repl_reset_tool.md`

## Chunk 1: Server-Owned Unread Output And Request Semantics

### Task 1: Lock in the public unread-output semantics with failing tests

**Files:**
- Modify: `tests/write_stdin_batch.rs`
- Modify: `tests/interrupt.rs`
- Modify: `tests/session_endings.rs`
- Modify: `tests/repl_surface.rs`
- Modify: `tests/common/mod.rs`

- [ ] **Step 1: Write failing public tests for the new batch semantics**

Add tests that drive only the public `repl`/`write_stdin` surface:

```rust
#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_background_output_while_idle_prefixes_next_reply() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let _ = session
        .write_stdin_raw_with(
            "system2(command = file.path(R.home(\"bin\"), \"Rscript\"), args = c(\"-e\", \"Sys.sleep(0.2); cat('BG\\\\n')\"), wait = FALSE, stdout = \"\", stderr = \"\")",
            Some(10.0),
        )
        .await?;

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let result = session.write_stdin_raw_with("cat('NEXT\\n')", Some(10.0)).await?;
    let text = collect_text(&result);
    assert!(text.contains("BG"));
    assert!(text.contains("NEXT"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn interrupt_then_run_returns_one_combined_batch() -> TestResult<()> {
    let mut session = common::spawn_server().await?;
    let _ = session
        .write_stdin_raw_with("cat('start\\n'); flush.console(); Sys.sleep(5)", Some(0.2))
        .await?;

    let result = session
        .write_stdin_raw_with("\u{3}cat('after\\n')", Some(10.0))
        .await?;
    let text = collect_text(&result);
    assert!(text.contains("start"));
    assert!(text.contains("after"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn session_end_notice_and_respawn_output_can_share_one_reply() -> TestResult<()> {
    let mut session = common::spawn_server().await?;
    let _ = session.write_stdin_raw_with("quit(\"no\")", Some(10.0)).await?;
    let result = session.write_stdin_raw_with("1+1", Some(10.0)).await?;
    let text = collect_text(&result);
    assert!(text.contains("session ended") || text.contains("new session started"));
    assert!(text.contains("2"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn repl_reset_includes_unread_output_in_its_reply() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let _ = session
        .write_stdin_raw_with(
            "system2(command = file.path(R.home(\"bin\"), \"Rscript\"), args = c(\"-e\", \"Sys.sleep(0.2); cat('OLD\\\\n')\"), wait = FALSE, stdout = \"\", stderr = \"\")",
            Some(10.0),
        )
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let result = session.call_tool_raw("repl_reset", serde_json::json!({})).await?;
    let text = collect_text(&result);
    assert!(text.contains("OLD"));
    assert!(text.contains("new session started"));
    Ok(())
}
```

Use `Rscript` rather than `/bin/sh` so the test stays portable across supported platforms. If the background-output assertion is flaky on slower CI, wrap the idle wait in a short deadline-based retry loop rather than relying on one narrow fixed sleep.

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run:

```bash
cargo test --test write_stdin_batch write_stdin_background_output_while_idle_prefixes_next_reply -- --exact
cargo test --test interrupt interrupt_then_run_returns_one_combined_batch -- --exact
cargo test --test session_endings session_end_notice_and_respawn_output_can_share_one_reply -- --exact
cargo test --test repl_surface repl_reset_includes_unread_output_in_its_reply -- --exact
```

Expected: FAIL because the current ring/poll logic still discards or splits these batches according to the old semantics. In particular, lifecycle requests do not yet consistently return all output collected since the previous tool response.

- [ ] **Step 3: Commit the red tests**

```bash
git add tests/write_stdin_batch.rs tests/interrupt.rs tests/session_endings.rs tests/repl_surface.rs tests/common/mod.rs
git commit -m "test: lock in unread-output redesign semantics"
```

### Task 2: Introduce the server-owned unread buffer and wire the reader threads into it

**Files:**
- Create: `src/pending_output.rs`
- Modify: `src/main.rs`
- Modify: `src/server.rs`
- Modify: `src/debug_repl.rs`
- Modify: `src/worker_process.rs`

- [ ] **Step 1: Create the new unread-output store**

Add `src/pending_output.rs` with one clear owner-facing API:

```rust
pub(crate) enum PendingItem {
    Text { text: String, stream: TextStream },
    Image { id: String, mime_type: String, data: String, is_new: bool },
}

pub(crate) struct DrainedBatch {
    pub items: Vec<PendingItem>,
    pub capture_failed: bool,
}

pub(crate) struct PendingOutput { /* in-memory or spilled */ }

impl PendingOutput {
    pub(crate) fn append_text(&self, text: String, stream: TextStream) -> Result<(), PendingOutputError>;
    pub(crate) fn append_image(&self, id: String, mime_type: String, data: String, is_new: bool) -> Result<(), PendingOutputError>;
    pub(crate) fn has_unread(&self) -> bool;
    pub(crate) fn drain(&self) -> DrainedBatch;
    pub(crate) fn mark_capture_failed(&self, message: String);
    pub(crate) fn take_capture_failure(&self) -> Option<String>;
}
```

Keep this module focused on unread storage only:
- no prompt logic
- no overflow file retention
- no transport lifecycle logic

Semantics to lock in here:
- unread storage is server-owned and may spill instead of truncating
- lifecycle requests do not clear unread output; the next response drains everything collected since the previous tool response
- if an internal stale-reader guard is needed to avoid double-appends after teardown, keep it private to the implementation and do not make process identity part of the public drain semantics

- [ ] **Step 2: Register the new module in the crate**

Add `mod pending_output;` in `src/main.rs` and import the new types at the first call sites that will own or consume them.

- [ ] **Step 3: Run the partially wired tree through a failing build**

Run:

```bash
cargo check
```

Expected: FAIL with unresolved imports or constructor/call-site mismatches until the server, debug REPL, and worker wiring is updated.

- [ ] **Step 4: Make the server own the buffer**

Modify `src/server.rs` so `SharedServer` owns `Arc<PendingOutput>` and passes it into `WorkerManager::new(...)`. Keep `codex/overflow-response-consumed` accepted, but reduce it to a no-op log path instead of reply-lifetime bookkeeping.

- [ ] **Step 5: Update the other direct `WorkerManager` constructor callers**

If `WorkerManager::new(...)` takes `PendingOutput` (or a factory for it), update the direct non-server callers too:
- `src/debug_repl.rs`
- unit tests in `src/worker_process.rs`

Do not leave the debug REPL on a stale constructor shape while the server compiles.

- [ ] **Step 6: Port the reader-thread append path**

Modify `src/worker_process.rs` so the existing stdout/stderr/image reader path appends directly into `PendingOutput` instead of `OutputTimeline`/`OutputBuffer`. Preserve the existing always-on reader-thread behavior while the worker is idle. If you need an internal stale-reader guard to prevent duplicate appends after teardown, keep it as an implementation detail and do not let it drop output that should still be surfaced by the next tool response.

- [ ] **Step 7: Preserve the public echo-collapse behavior before deleting the ring helpers**

Before removing `OutputBuffer`-based snapshots, move or rewrite the current `IpcEchoEvent`-driven behaviors so they still run over one drained batch:
- drop pure echo-only output for large silent inputs
- collapse large echoed transcripts while preserving attribution markers
- keep prompt trimming behavior for single-expression inputs

Do not regress the existing public tests in `tests/write_stdin_batch.rs` that cover large echo handling.

- [ ] **Step 8: Re-run the focused tests**

Run:

```bash
cargo test --test write_stdin_batch write_stdin_background_output_while_idle_prefixes_next_reply -- --exact
cargo test --test session_endings session_end_notice_and_respawn_output_can_share_one_reply -- --exact
cargo test --test repl_surface repl_reset_includes_unread_output_in_its_reply -- --exact
cargo test --test write_stdin_batch write_stdin_drops_huge_echo_only_inputs -- --exact
cargo test --test write_stdin_batch write_stdin_collapses_huge_echo_with_output_attribution -- --exact
```

Expected: still FAIL on request formatting and drain semantics, but compile and append path should now be using `PendingOutput` and the echo-focused tests should still be exercising the new path.

- [ ] **Step 9: Commit the wiring work**

```bash
git add src/pending_output.rs src/main.rs src/server.rs src/debug_repl.rs src/worker_process.rs
git commit -m "refactor: introduce server-owned pending output store"
```

### Task 3: Replace ring-based poll logic with destructive drain semantics

**Files:**
- Modify: `src/worker_process.rs`
- Modify: `src/worker_protocol.rs`
- Delete: `src/output_capture.rs`
- Modify: `src/server.rs`
- Modify: `tests/common/mod.rs`
- Modify: `tests/manage_session_behavior.rs`
- Modify: `tests/repl_surface.rs`
- Modify: `tests/python_backend.rs`

- [ ] **Step 1: Remove protocol fields that only exist for ring truncation**

Delete `older_output_dropped` from `WorkerReply::Output` in `src/worker_protocol.rs` and update all serde, constructors, and tests that depend on it.

- [ ] **Step 2: Rewrite `write_stdin` and poll behavior around destructive drains**

In `src/worker_process.rs`:
- make `write_stdin("")` wait until idle or timeout, then drain `PendingOutput` exactly once
- if the session is already idle, return immediately with the drained batch or the current idle marker when there is no unread output
- keep plain non-empty input rejected while busy unless it starts with `\u0003` or `\u0004`
- preserve the one-deadline behavior for `\u0003`/`\u0004` plus remaining input
- preserve unread prefix output across `\u0003`, `\u0004`, worker exit, and respawn
- preserve the single public invariant for lifecycle requests too: send the request, wait for idle or timeout, then return all output collected since the previous tool response

- [ ] **Step 3: Update the public truncation contract**

Because unread output is now server-owned and may spill instead of truncating, remove the public contract that says older unread output disables full-response artifacts. Replace it with a public assertion that oversized unread batches still produce a bounded inline preview plus a retained artifact when the server can spill/write successfully.

- [ ] **Step 4: Delete the dead ring machinery**

Remove `src/output_capture.rs`, its imports, its tests, and any ring-offset bookkeeping in `src/worker_process.rs`, `src/server.rs`, and `tests/common/mod.rs`.

- [ ] **Step 5: Run the semantics tests**

Run:

```bash
cargo test --test write_stdin_batch write_stdin_background_output_while_idle_prefixes_next_reply -- --exact
cargo test --test write_stdin_batch write_stdin_timeout_polling_returns_pending_output -- --exact
cargo test --test interrupt interrupt_then_run_returns_one_combined_batch -- --exact
cargo test --test session_endings session_end_notice_and_respawn_output_can_share_one_reply -- --exact
cargo test --test manage_session_behavior restart_while_busy_resets_session -- --exact
cargo test --test repl_surface repl_reset_clears_state -- --exact
cargo test --test repl_surface repl_reset_includes_unread_output_in_its_reply -- --exact
cargo test --test python_backend python_truncated_pending_prefix_spills_to_server_owned_artifact -- --exact
```

Expected: PASS for the new semantics, including lifecycle consistency. Snapshots may still fail later because the formatter still uses the old overflow presentation.

- [ ] **Step 6: Commit the semantic cut-over**

```bash
git add -A src tests/common/mod.rs tests/write_stdin_batch.rs tests/interrupt.rs tests/session_endings.rs tests/manage_session_behavior.rs tests/repl_surface.rs tests/python_backend.rs
git commit -m "refactor: switch repl polling to destructive unread drains"
```

## Chunk 2: Reply Formatting, Overflow Artifacts, And Cleanup

### Task 4: Lock in oversized-preview behavior with failing public tests

**Files:**
- Modify: `tests/plot_images.rs`
- Modify: `tests/python_plot_images.rs`
- Modify: `tests/common/mod.rs`

- [ ] **Step 1: Add failing public tests for oversized replies**

Add tests for the spec rules that changed:

```rust
#[tokio::test(flavor = "multi_thread")]
async fn oversized_reply_preview_shows_head_middle_notice_and_tail() -> TestResult<()> {
    let mut session = common::spawn_server().await?;
    let result = session.write_stdin_raw_with("cat(paste(rep('line', 5000), collapse='\\n'))", Some(10.0)).await?;
    let text = collect_text(&result);
    assert!(text.contains("[repl] middle of this reply omitted from inline preview"));
    assert!(text.starts_with(">"));
    assert!(text.contains("line"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_single_line_respects_total_budget() -> TestResult<()> {
    let mut session = common::spawn_python_server().await?;
    let result = session.write_stdin_raw_with("print('x' * 200000)", Some(10.0)).await?;
    let text = collect_text(&result);
    assert!(text.len() < 20_000);
    assert!(text.contains("[repl] middle of this reply omitted from inline preview"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_never_shows_partial_full_image_path_notice() -> TestResult<()> {
    let mut session = common::spawn_python_server().await?;
    let input = fake_plot_image_script(240, 10_000, 12_000);
    let result = session.write_stdin_raw_with(&input, Some(120.0)).await?;
    let text = collect_text(&result);
    for path in extract_all_paths(&text, "full image at ") {
        assert!(path.exists(), "expected complete visible path: {path:?}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn overflow_write_failure_returns_bounded_preview_with_notice() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let read_only = temp.path().join("overflow-root");
    std::fs::create_dir(&read_only)?;
    let mut perms = std::fs::metadata(&read_only)?.permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&read_only, perms)?;

    let mut session = common::spawn_server_with_env_vars(vec![
        (
            "MCP_CONSOLE_OVERFLOW_ROOT".to_string(),
            read_only.display().to_string(),
        ),
    ])
    .await?;
    let result = session
        .write_stdin_raw_with("cat(paste(rep('line', 5000), collapse='\\n'))", Some(10.0))
        .await?;
    let text = collect_text(&result);
    assert!(text.contains("could not write full reply artifact"));
    assert!(text.len() < 20_000);
    Ok(())
}
```

Reuse the existing `fake_plot_image_script(...)` helper in `tests/python_plot_images.rs` for the path-notice case; do not introduce a separate `test_plot_fixture` module just for this test. If the overflow write-failure case cannot be driven with the current harness, add a server startup env var such as `MCP_CONSOLE_OVERFLOW_ROOT` and use `spawn_server_with_env_vars(...)` to point the server at a read-only directory. Do not add a test-only constructor to the product code.

- [ ] **Step 2: Run the targeted overflow tests to verify they fail**

Run:

```bash
cargo test --test plot_images oversized_reply_preview_shows_head_middle_notice_and_tail -- --exact
cargo test --test python_plot_images oversized_single_line_respects_total_budget -- --exact
cargo test --test python_plot_images preview_never_shows_partial_full_image_path_notice -- --exact
cargo test --test plot_images overflow_write_failure_returns_bounded_preview_with_notice -- --exact
```

Expected: FAIL because the current formatter is head-only, line-biased, and still tied to the old overflow store.

- [ ] **Step 3: Commit the red overflow tests**

```bash
git add tests/plot_images.rs tests/python_plot_images.rs tests/common/mod.rs
git commit -m "test: lock in oversized reply preview behavior"
```

### Task 5: Replace `response.rs` with per-reply formatting and artifact retention

**Files:**
- Create: `src/server/reply_batch.rs`
- Create: `src/server/overflow_artifacts.rs`
- Modify: `src/server.rs`
- Delete: `src/server/response.rs`

- [ ] **Step 1: Move retained-artifact ownership into its own module**

Create `src/server/overflow_artifacts.rs` with a store keyed by completed reply batches, not by transport-delivery state. It should:
- write one self-contained text artifact plus any image files for one reply
- retain the most recent `N` replies plus a coarse byte cap
- evict oldest retained replies after a new reply is finalized
- stop emitting `overflowResponseToken`

- [ ] **Step 2: Build the new reply formatter**

Create `src/server/reply_batch.rs` with one entry point that accepts:

```rust
pub(crate) fn format_drained_batch(
    batch: DrainedBatch,
    artifacts: Option<&OverflowArtifacts>,
    metadata: ReplyMetadata,
) -> CallToolResult
```

The formatter must:
- preserve image ordering after `collapse_image_updates`
- apply the total inline-size budget, not a line-count quota
- produce a non-overlapping head slice, one synthetic middle-omission notice, and a tail slice
- prefer whole text lines when possible, but cut inside a single oversized text line if necessary
- never show a partial `full image at ...` notice inline
- preserve the existing input-echo cleanup guarantees after the worker-side drain refactor
- write a self-contained full-reply artifact when possible
- on artifact write failure, keep the bounded preview, add a short write-failure notice, and drop the undisplayed tail

- [ ] **Step 3: Replace the old server integration**

Modify `src/server.rs` to call the new formatter and artifact store. Delete the transport-completion hooks, pending-send maps, response-token metadata emission, and `codex/overflow-response-consumed` retention behavior from the old flow.

- [ ] **Step 4: Run the targeted overflow tests**

Run:

```bash
cargo test --test plot_images oversized_reply_preview_shows_head_middle_notice_and_tail -- --exact
cargo test --test python_plot_images oversized_single_line_respects_total_budget -- --exact
cargo test --test python_plot_images preview_never_shows_partial_full_image_path_notice -- --exact
cargo test --test plot_images overflow_write_failure_returns_bounded_preview_with_notice -- --exact
```

Expected: PASS.

- [ ] **Step 5: Commit the formatter/artifact rewrite**

```bash
git add -A src/server tests/plot_images.rs tests/python_plot_images.rs tests/common/mod.rs
git commit -m "refactor: rewrite repl overflow formatting per reply batch"
```

### Task 6: Remove dead coverage, refresh snapshots, and run the full verification suite

**Files:**
- Modify: `tests/write_stdin_batch.rs`
- Modify: `tests/session_endings.rs`
- Modify: `tests/interrupt.rs`
- Modify: `tests/manage_session_behavior.rs`
- Modify: `tests/repl_surface.rs`
- Modify: `tests/python_backend.rs`
- Modify: `tests/plot_images.rs`
- Modify: `tests/python_plot_images.rs`
- Modify: `docs/tool-descriptions/repl_tool_r.md`
- Modify: `docs/tool-descriptions/repl_tool_python.md`
- Modify: `docs/tool-descriptions/repl_reset_tool.md`

- [ ] **Step 1: Delete internal-only tests that exercised removed helpers**

Remove the `src/server/response.rs` unit tests and any `src/output_capture.rs` tests that are no longer reachable through the public MCP surface. Keep coverage in the integration tests only.

- [ ] **Step 2: Refresh snapshots and public assertions**

Before accepting snapshots:
- rename/update the old truncation-contract test in `tests/python_backend.rs`
- keep or add public assertions for huge echoed input handling, lifecycle-request consistency, and retained-artifact behavior
- verify the docs describe server-owned unread batching rather than worker-side truncation/acknowledgement
- update `docs/tool-descriptions/repl_reset_tool.md` so it no longer promises a reset reply that contains only the new-session status line if unread output is now co-batched into that response

Run:

```bash
cargo insta test
cargo insta pending-snapshots
```

Expected: pending snapshots in the REPL transcript suites that changed because of the new head-and-tail preview and drain semantics.

- [ ] **Step 3: Accept the intentional snapshot changes**

Run:

```bash
cargo insta accept
```

- [ ] **Step 4: Run the full required verification suite**

Run:

```bash
cargo +nightly fmt
cargo check
cargo build
cargo clippy
cargo test
```

Expected: all commands succeed cleanly.

- [ ] **Step 5: Commit the cleanup and verification pass**

```bash
git add docs/tool-descriptions/repl_tool_r.md docs/tool-descriptions/repl_tool_python.md docs/tool-descriptions/repl_reset_tool.md tests src
git commit -m "cleanup: remove ring-based repl output machinery"
```
