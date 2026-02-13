#![cfg(unix)]

mod common;

use common::{McpTestSession, TestResult};
use rmcp::model::{CallToolResult, RawContent};
use serde_json::json;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::path::PathBuf;
use std::time::{Duration, Instant};

const SANDBOX_STATE_METHOD: &str = "codex/sandbox-state/update";

fn collect_text(result: &CallToolResult) -> String {
    let text = result
        .content
        .iter()
        .filter_map(|content| match &content.raw {
            RawContent::Text(text) => Some(text.text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("");
    text.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !(trimmed.starts_with("> ") || trimmed.starts_with("+ ") || trimmed == ">")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn sandbox_update_params(network_access: bool) -> serde_json::Value {
    json!({
        "sandboxPolicy": {
            "type": "workspace-write",
            "writable_roots": [],
            "network_access": network_access,
            "exclude_tmpdir_env_var": false,
            "exclude_slash_tmp": false
        }
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn sandbox_full_access_params() -> serde_json::Value {
    json!({
        "sandboxPolicy": {
            "type": "danger-full-access"
        }
    })
}

async fn assert_session_reset(session: &mut McpTestSession) -> TestResult<()> {
    session.write_stdin_with("x <- 42", Some(10.0)).await;
    let result = session
        .write_stdin_raw_with("print(exists(\"x\"))", Some(10.0))
        .await?;
    let text = collect_text(&result);
    assert!(
        text.contains("TRUE"),
        "expected pre-update TRUE, got: {text}"
    );
    Ok(())
}

async fn assert_variable_cleared(session: &mut McpTestSession) -> TestResult<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_text = String::new();
    while Instant::now() < deadline {
        let result = session
            .write_stdin_raw_with("print(exists(\"x\"))", Some(10.0))
            .await?;
        last_text = collect_text(&result);
        if last_text.contains("FALSE") {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        last_text.contains("FALSE"),
        "expected post-update FALSE, got: {last_text}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sandbox_state_update_request_restarts_worker() -> TestResult<()> {
    if !common::sandbox_exec_available() {
        eprintln!("sandbox-exec unavailable; skipping");
        return Ok(());
    }
    let mut session = common::spawn_server().await?;
    assert_session_reset(&mut session).await?;
    session
        .send_custom_request(SANDBOX_STATE_METHOD, sandbox_update_params(true))
        .await?;
    assert_variable_cleared(&mut session).await?;
    session.cancel().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sandbox_state_update_notification_restarts_worker() -> TestResult<()> {
    if !common::sandbox_exec_available() {
        eprintln!("sandbox-exec unavailable; skipping");
        return Ok(());
    }
    let mut session = common::spawn_server().await?;
    assert_session_reset(&mut session).await?;
    session
        .send_custom_notification(SANDBOX_STATE_METHOD, sandbox_update_params(true))
        .await?;
    assert_variable_cleared(&mut session).await?;
    session.cancel().await?;
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test(flavor = "multi_thread")]
async fn sandbox_state_update_applies_full_access_policy() -> TestResult<()> {
    if !common::sandbox_exec_available() {
        eprintln!("sandbox-exec unavailable; skipping");
        return Ok(());
    }
    if std::env::var_os("CODEX_SANDBOX").is_some() {
        return Ok(());
    }
    let target = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join("mcp-console-sandbox-state-update.txt"));
    if let Some(path) = &target {
        let _ = std::fs::remove_file(path);
    }
    let mut session = common::spawn_server().await?;
    session
        .send_custom_request(SANDBOX_STATE_METHOD, sandbox_full_access_params())
        .await?;
    let code = r#"
target <- file.path(Sys.getenv("HOME"), "mcp-console-sandbox-state-update.txt")
tryCatch({
  writeLines("allowed", target)
  cat("WRITE_OK\n")
}, error = function(e) {
  message("WRITE_ERROR:", conditionMessage(e))
})
"#;
    let result = session.write_stdin_raw_with(code, Some(10.0)).await?;
    let text = collect_text(&result);
    assert!(
        text.contains("WRITE_OK"),
        "expected full access to allow write, got: {text}"
    );
    assert!(
        !text.contains("WRITE_ERROR:"),
        "full access unexpectedly blocked write: {text}"
    );
    if let Some(path) = &target {
        let _ = std::fs::remove_file(path);
    }
    session.cancel().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sandbox_state_capability_advertised() -> TestResult<()> {
    let session = common::spawn_server().await?;
    let info = session.server_info().ok_or_else(|| {
        let message = "missing server info from initialize".to_string();
        Box::<dyn std::error::Error + Send + Sync>::from(message)
    })?;
    let experimental = info.capabilities.experimental.as_ref().ok_or_else(|| {
        let message = "missing experimental capabilities".to_string();
        Box::<dyn std::error::Error + Send + Sync>::from(message)
    })?;
    assert!(
        experimental.contains_key("codex/sandbox-state"),
        "expected sandbox state capability in experimental: {experimental:?}"
    );
    session.cancel().await?;
    Ok(())
}
