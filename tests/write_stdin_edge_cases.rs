#![cfg(unix)]

mod common;

use common::TestResult;
use rmcp::model::RawContent;
use rmcp::service::ServiceError;

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

fn assert_invalid_timeout(err: ServiceError) {
    match err {
        ServiceError::McpError(error) => {
            assert!(
                error
                    .message
                    .contains("timeout for write_stdin must be a non-negative number"),
                "unexpected error message: {}",
                error.message
            );
        }
        other => panic!("expected MCP error, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_timeout_zero_is_non_blocking() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let timeout_result = session
        .write_stdin_raw_unterminated_with("1+1", Some(0.0))
        .await?;
    let timeout_text = result_text(&timeout_result);
    assert!(
        timeout_text.contains("<<console status: busy"),
        "expected timeout status for non-blocking call, got: {timeout_text:?}"
    );

    let completed = session
        .write_stdin_raw_unterminated_with("", Some(5.0))
        .await?;
    let completed_text = result_text(&completed);
    assert!(
        completed_text.contains("2"),
        "expected pending result after non-blocking call, got: {completed_text:?}"
    );

    let err = session
        .write_stdin_raw_unterminated_with("1+1", Some(-1.0))
        .await
        .expect_err("expected timeout<0 to be rejected");
    assert_invalid_timeout(err);

    session.cancel().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_accepts_crlf_input() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let input = "cat('A\\n')\r\ncat('B\\n')";
    let result = session.write_stdin_raw_with(input, Some(10.0)).await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("A"),
        "expected output to include A, got: {text:?}"
    );
    assert!(
        text.contains("B"),
        "expected output to include B, got: {text:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_without_trailing_newline_runs() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let result = session
        .write_stdin_raw_unterminated_with("1+1", Some(10.0))
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("2"),
        "expected evaluation result, got: {text:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_empty_returns_prompt() -> TestResult<()> {
    let mut session = common::spawn_server().await?;

    let result = session
        .write_stdin_raw_unterminated_with("", Some(1.0))
        .await?;
    session.cancel().await?;

    assert_ne!(result.is_error, Some(true), "empty input should not error");
    let text = result_text(&result);
    assert!(
        text.contains(">"),
        "expected prompt in output, got: {text:?}"
    );
    Ok(())
}
