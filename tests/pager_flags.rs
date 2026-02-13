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
async fn matches_limit_parses_long_flag() -> TestResult<()> {
    let mut session = common::spawn_server_with_pager_page_chars(60).await?;

    session
        .write_stdin_raw_with(
            "for (i in 1:30) cat(sprintf(\"match %02d configure\\n\", i))",
            Some(30.0),
        )
        .await?;

    let result = session
        .write_stdin_raw_with(":matches --limit 2 configure", Some(30.0))
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("matches: 2") && text.contains("limit 2"),
        "expected matches --limit 2 output, got: {text:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn hits_count_parses_long_flag() -> TestResult<()> {
    let mut session = common::spawn_server_with_pager_page_chars(60).await?;

    session
        .write_stdin_raw_with(
            "for (i in 1:10) cat(sprintf(\"hit configure %02d\\n\", i))",
            Some(30.0),
        )
        .await?;

    let result = session
        .write_stdin_raw_with(":hits --count 2 configure", Some(30.0))
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("#2"),
        "expected hits --count 2 output, got: {text:?}"
    );
    Ok(())
}
