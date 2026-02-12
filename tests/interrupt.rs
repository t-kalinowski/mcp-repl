mod common;

use common::TestResult;
use rmcp::model::{CallToolResult, RawContent};
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

#[tokio::test(flavor = "multi_thread")]
async fn interrupt_unblocks_long_running_request() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

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
    assert!(
        interrupt_text.contains("> "),
        "expected prompt after interrupt, got: {interrupt_text:?}"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Instant::now() >= deadline {
            session.cancel().await?;
            return Err("worker stayed busy after interrupt".into());
        }

        let result = session.write_stdin_raw_with("1+1", Some(0.5)).await?;
        let text = result_text(&result);
        if text.contains("worker is busy") || text.contains("request already running") {
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

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_ctrl_c_prefix_interrupts_then_runs_remaining_input() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

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
    assert!(
        text.contains("[1] 2") || text.contains("2"),
        "expected evaluation after interrupt prefix, got: {text:?}"
    );

    session.cancel().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_ctrl_d_prefix_restarts_then_runs_remaining_input() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let _ = session.write_stdin_raw_with("x <- 1", Some(5.0)).await?;

    let result = session
        .write_stdin_raw_with("\u{4}print(exists(\"x\"))", Some(10.0))
        .await?;
    let text = result_text(&result);
    assert!(
        text.contains("FALSE"),
        "expected fresh session after restart prefix, got: {text:?}"
    );

    session.cancel().await?;
    Ok(())
}
