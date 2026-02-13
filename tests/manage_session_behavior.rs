#![cfg(unix)]

mod common;

use common::TestResult;
use rmcp::model::RawContent;

fn result_text(result: &rmcp::model::CallToolResult) -> String {
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

#[tokio::test(flavor = "multi_thread")]
async fn interrupt_without_active_request_returns_prompt() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let _ = session.write_stdin_raw_with("1+1", Some(5.0)).await?;
    let result = session.write_stdin_raw_with("\u{3}", Some(5.0)).await?;

    let text = result_text(&result);
    assert!(
        text.contains(">") || text.contains("<<console status: busy"),
        "expected prompt or timeout status in output, got: {text:?}"
    );
    assert!(
        !text.contains("worker exited"),
        "did not expect interrupt to terminate the worker: {text:?}"
    );

    let follow_up = session.write_stdin_raw_with("1+1", Some(5.0)).await?;
    session.cancel().await?;

    let follow_text = result_text(&follow_up);
    assert!(
        follow_text.contains("2"),
        "expected session to recover after interrupt, got: {follow_text:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_while_busy_resets_session() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let _ = session
        .write_stdin_raw_with("x <- 1; Sys.sleep(5)", Some(0.1))
        .await?;

    let restart = session.write_stdin_raw_with("\u{4}", Some(5.0)).await?;
    let restart_text = result_text(&restart);
    assert!(
        restart_text.contains("new session started"),
        "expected restart notice, got: {restart_text:?}"
    );

    let result = session
        .write_stdin_raw_with("print(exists(\"x\"))", Some(5.0))
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("FALSE"),
        "expected cleared session, got: {text:?}"
    );
    Ok(())
}
