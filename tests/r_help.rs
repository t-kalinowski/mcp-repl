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
async fn text_help_is_llm_friendly() -> TestResult<()> {
    let mut session = common::spawn_server_with_pager_page_chars(20_000).await?;

    let result = session.write_stdin_raw_with("?mean", Some(30.0)).await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("R Documentation"),
        "expected text help output, got: {text:?}"
    );
    assert!(
        !text.contains('\u{8}'),
        "expected no backspace control characters in help output, got: {text:?}"
    );
    #[cfg(not(windows))]
    assert!(
        !text.contains('\u{fffd}'),
        "expected no replacement characters in help output, got: {text:?}"
    );
    Ok(())
}
