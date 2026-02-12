use common::TestResult;
use rmcp::model::RawContent;

mod common;

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
async fn r_show_doc_prints_manual_html_in_console() -> TestResult<()> {
    let mut session = common::spawn_server_with_pager_page_chars(12_000).await?;

    let result = session
        .write_stdin_raw_with(
            "RShowDoc(\"R-exts\", type = \"html\"); invisible(NULL)",
            Some(30.0),
        )
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("[mcp-console] browseURL file:") && text.contains("R-exts.html"),
        "expected RShowDoc() to print HTML file contents, got: {text:?}"
    );
    assert!(
        text.contains("Writing R Extensions"),
        "expected manual title in output, got: {text:?}"
    );
    assert!(
        !text.contains("starting httpd help server"),
        "did not expect dynamic help server output, got: {text:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn r_show_doc_accepts_text_type_alias() -> TestResult<()> {
    let mut session = common::spawn_server_with_pager_page_chars(12_000).await?;

    let result = session
        .write_stdin_raw_with(
            "RShowDoc(\"R-exts\", type = \"text\"); invisible(NULL)",
            Some(30.0),
        )
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("[mcp-console] browseURL file:") && text.contains("R-exts.html"),
        "expected RShowDoc() to fall back to HTML output, got: {text:?}"
    );
    assert!(
        text.contains("Writing R Extensions"),
        "expected manual content in output, got: {text:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn browseurl_supports_html_fragments_for_r_manuals() -> TestResult<()> {
    let mut session = common::spawn_server_with_pager_page_chars(20_000).await?;

    let result = session
        .write_stdin_raw_with(
            "p <- file.path(R.home(\"doc\"), \"manual\", \"R-exts.html\"); browseURL(paste0(p, \"#\", \"Error-signaling-from-Fortran\")); invisible(NULL)",
            Some(30.0),
        )
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("Error signaling from Fortran"),
        "expected fragment section heading in output, got: {text:?}"
    );
    assert!(
        text.contains("subroutine rexit") && text.contains("subroutine rwarn"),
        "expected Fortran entry points in output, got: {text:?}"
    );
    assert!(
        !text.contains("Table of Contents"),
        "did not expect full manual output for fragment browse, got: {text:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn r_show_doc_does_not_open_pdfs() -> TestResult<()> {
    let mut session = common::spawn_server_with_pager_page_chars(50_000).await?;

    let result = session
        .write_stdin_raw_with("RShowDoc(\"R-exts\"); invisible(NULL)", Some(30.0))
        .await?;
    session.cancel().await?;

    let text = result_text(&result);
    assert!(
        text.contains("[mcp-console] browseURL file:") && text.contains("R-exts.html"),
        "expected RShowDoc() to render HTML in console, got: {text:?}"
    );
    assert!(
        text.contains("Writing R Extensions"),
        "expected manual content in output, got: {text:?}"
    );
    Ok(())
}
