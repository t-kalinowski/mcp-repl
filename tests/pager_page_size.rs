#![cfg(unix)]

mod common;

use common::TestResult;
use rmcp::model::RawContent;

fn text_chunks(result: &rmcp::model::CallToolResult) -> Vec<&str> {
    result
        .content
        .iter()
        .filter_map(|item| match &item.raw {
            RawContent::Text(text) => Some(text.text.as_str()),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn respects_configured_small_page_size() -> TestResult<()> {
    let page_bytes = 80;
    let mut session = common::spawn_server_with_pager_page_chars(page_bytes).await?;

    let result = session
        .write_stdin_raw_with("for (i in 1:50) cat('abcd\\n')", Some(10.0))
        .await?;
    session.cancel().await?;

    let chunks = text_chunks(&result);
    let first = chunks
        .iter()
        .find(|text| !text.contains("--More--") && !text.starts_with("(END"))
        .copied()
        .unwrap_or("");
    assert!(
        !first.starts_with("> "),
        "did not expect input echo by default, got: {first:?}"
    );
    assert!(
        first.len() <= page_bytes as usize,
        "first page exceeded page size: {} > {page_bytes}",
        first.len()
    );

    assert!(
        chunks.iter().any(|text| text.contains("--More--")),
        "expected pager footer in response"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn respects_configured_large_page_size() -> TestResult<()> {
    let page_bytes = 10_000;
    let mut session = common::spawn_server_with_pager_page_chars(page_bytes).await?;

    let result = session
        .write_stdin_raw_with("for (i in 1:10) cat('abcd\\n\')", Some(10.0))
        .await?;
    session.cancel().await?;

    let chunks = text_chunks(&result);
    assert!(
        !chunks.iter().any(|text| text.contains("--More--")),
        "did not expect pager footer"
    );

    Ok(())
}
