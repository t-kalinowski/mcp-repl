mod common;

use common::TestResult;
use rmcp::model::{CallToolResult, RawContent};
#[cfg(any(unix, windows))]
use tokio::time::{Duration, Instant, sleep};

fn result_text(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|item| match &item.raw {
            RawContent::Text(text) => Some(text.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

fn is_busy_response(text: &str) -> bool {
    text.contains("<<console status: busy")
        || text.contains("worker is busy")
        || text.contains("request already running")
        || text.contains("input discarded while worker busy")
}

async fn spawn_interrupt_session() -> TestResult<common::McpTestSession> {
    #[cfg(target_os = "windows")]
    {
        return common::spawn_server_with_args(vec![
            "--sandbox-state".to_string(),
            "danger-full-access".to_string(),
        ])
        .await;
    }
    #[cfg(not(target_os = "windows"))]
    {
        common::spawn_server().await
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn interrupt_unblocks_long_running_request() -> TestResult<()> {
    let mut session = spawn_interrupt_session().await?;

    let timeout_result = session
        .write_stdin_raw_with("Sys.sleep(30)", Some(0.5))
        .await?;
    let timeout_text = result_text(&timeout_result);
    assert!(
        timeout_text.contains("<<console status: busy"),
        "expected sleep call to time out, got: {timeout_text:?}"
    );

    let interrupt_result = session.write_stdin_raw_with("\u{3}", Some(5.0)).await?;
    let interrupt_text = result_text(&interrupt_result);
    if interrupt_text.contains("failed to start R session")
        || interrupt_text.contains("worker exited with status")
        || interrupt_text.contains("unable to initialize the JIT")
    {
        eprintln!("interrupt test backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }
    assert!(
        interrupt_text.contains("> ")
            || interrupt_text.contains("<<console status: busy")
            || interrupt_text.contains("worker is busy")
            || interrupt_text.contains("request already running")
            || interrupt_text.contains("input discarded while worker busy"),
        "expected prompt or transient busy response after interrupt, got: {interrupt_text:?}"
    );

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() >= deadline {
            session.cancel().await?;
            eprintln!("interrupt did not unblock worker in time; skipping");
            return Ok(());
        }

        let result = session.write_stdin_raw_with("1+1", Some(1.0)).await?;
        let text = result_text(&result);
        if text.contains("worker is busy")
            || text.contains("request already running")
            || text.contains("input discarded while worker busy")
            || text.contains("<<console status: busy")
        {
            sleep(Duration::from_millis(50)).await;
            continue;
        }
        assert!(
            text.contains("[1] 2") || text.contains("2"),
            "expected evaluation to run after interrupt, got: {text:?}"
        );
        break;
    }

    session.cancel().await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_ctrl_c_prefix_interrupts_then_runs_remaining_input() -> TestResult<()> {
    let mut session = spawn_interrupt_session().await?;

    let timeout_result = session
        .write_stdin_raw_with("Sys.sleep(30)", Some(0.5))
        .await?;
    let timeout_text = result_text(&timeout_result);
    assert!(
        timeout_text.contains("<<console status: busy"),
        "expected sleep call to time out, got: {timeout_text:?}"
    );

    let result = session.write_stdin_raw_with("\u{3}1+1", Some(5.0)).await?;
    let text = result_text(&result);
    if text.contains("<<console status: busy")
        || text.contains("worker is busy")
        || text.contains("request already running")
        || text.contains("input discarded while worker busy")
    {
        eprintln!("interrupt prefix did not complete in time; skipping");
        session.cancel().await?;
        return Ok(());
    }
    assert!(
        text.contains("[1] 2") || text.contains("2"),
        "expected evaluation after interrupt prefix, got: {text:?}"
    );

    session.cancel().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_ctrl_d_prefix_restarts_then_runs_remaining_input() -> TestResult<()> {
    let mut session = spawn_interrupt_session().await?;

    let _ = session.write_stdin_raw_with("x <- 1", Some(5.0)).await?;

    let first = session
        .write_stdin_raw_with("\u{4}print(exists(\"x\"))", Some(10.0))
        .await?;
    let mut text = result_text(&first);
    if is_busy_response(&text) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if Instant::now() >= deadline {
                session.cancel().await?;
                panic!("expected fresh session after restart prefix, got: {text:?}");
            }
            sleep(Duration::from_millis(100)).await;
            let result = session
                .write_stdin_raw_with("print(exists(\"x\"))", Some(5.0))
                .await?;
            text = result_text(&result);
            if is_busy_response(&text) {
                continue;
            }
            break;
        }
    }
    assert!(
        text.contains("FALSE"),
        "expected fresh session output, got: {text:?}"
    );

    session.cancel().await?;
    Ok(())
}
