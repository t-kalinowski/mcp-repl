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
async fn file_show_uses_mcp_console_pager() -> TestResult<()> {
    let mut session = common::spawn_server_with_pager_page_chars(4_000).await?;

    let result = session
        .write_stdin_raw_with(
            "line <- paste(rep(\"x\", 200), collapse = \"\"); tf <- tempfile(\"mcp-console-file-show-\"); writeLines(sprintf(\"file_show_line%04d %s\", 1:200, line), tf); file.show(tf, delete.file = TRUE); invisible(NULL)",
            Some(30.0),
        )
        .await?;
    let text = result_text(&result);
    assert!(
        text.contains("file_show_line0001"),
        "expected file.show() content in output, got: {text:?}"
    );
    assert!(
        text.contains("--More--"),
        "expected mcp-console pager footer, got: {text:?}"
    );

    let result = session.write_stdin_raw_with(":next", Some(30.0)).await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("file_show_line") && !text.contains("file_show_line0001"),
        "expected a later page of file.show() output, got: {text:?}"
    );
    assert!(
        text.contains("--More--") || text.contains("(END"),
        "expected pager footer on subsequent page, got: {text:?}"
    );
    Ok(())
}
