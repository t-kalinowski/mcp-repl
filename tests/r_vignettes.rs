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
async fn vignette_prints_contents_in_console() -> TestResult<()> {
    let mut session = common::spawn_server_with_pager_page_chars(4_000).await?;

    let result = session
        .write_stdin_raw_with(
            "x <- vignette(\"grid\", package = \"grid\"); print(x); invisible(NULL)",
            Some(30.0),
        )
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("[mcp-console] vignette: grid (package: grid)"),
        "expected vignette info in console, got: {text:?}"
    );
    assert!(
        text.contains("Source:") && text.contains("grid.Rnw"),
        "expected source path in output, got: {text:?}"
    );
    assert!(
        text.contains("% File src/library/grid/vignettes/grid.Rnw"),
        "expected vignette contents in output, got: {text:?}"
    );
    assert!(
        !text.contains("starting httpd help server"),
        "did not expect dynamic help server output, got: {text:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn browse_vignettes_prints_text_listing() -> TestResult<()> {
    let mut session = common::spawn_server_with_pager_page_chars(20_000).await?;

    let result = session
        .write_stdin_raw_with(
            "x <- browseVignettes(package = \"grid\"); print(x); invisible(NULL)",
            Some(30.0),
        )
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("[mcp-console] browseVignettes:"),
        "expected browseVignettes text output, got: {text:?}"
    );
    assert!(
        text.contains("Package: grid"),
        "expected package heading in output, got: {text:?}"
    );
    assert!(
        !text.contains("starting httpd help server"),
        "did not expect dynamic help server output, got: {text:?}"
    );
    Ok(())
}
