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
async fn write_stdin_discards_when_busy() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let _ = session
        .write_stdin_raw_with("Sys.sleep(2)", Some(0.1))
        .await?;

    let result = session.write_stdin_raw_with("1+1", Some(0.2)).await?;

    let text = result_text(&result);
    assert!(
        text.contains("input discarded while worker busy"),
        "expected busy discard message, got: {text:?}"
    );
    assert_ne!(result.is_error, Some(true));

    session.cancel().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_trims_continuation_echo() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let result = session.write_stdin_raw_with("1+\n1", Some(5.0)).await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(text.contains("2"), "expected result, got: {text:?}");
    assert!(
        !text.contains("> 1+"),
        "did not expect echoed input prompt line, got: {text:?}"
    );
    assert!(
        !text.contains("\n+ 1"),
        "did not expect echoed continuation prompt line, got: {text:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_mixed_stdout_stderr() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let result = session
        .write_stdin_raw_with(
            "cat('out1\\n'); message('err1'); cat('out2\\n')",
            Some(10.0),
        )
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(text.contains("out1"), "missing stdout, got: {text:?}");
    assert!(text.contains("out2"), "missing stdout, got: {text:?}");
    assert!(
        text.contains("stderr:"),
        "missing stderr prefix, got: {text:?}"
    );
    assert_ne!(result.is_error, Some(true));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_normalizes_error_prompt() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let result = session
        .write_stdin_raw_with("cat('> Error: boom\\n'); message('boom')", Some(10.0))
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("Error: boom"),
        "missing error text, got: {text:?}"
    );
    assert!(
        !text.contains("> Error: boom"),
        "expected leading prompt to be normalized, got: {text:?}"
    );
    assert_ne!(result.is_error, Some(true));
    Ok(())
}
