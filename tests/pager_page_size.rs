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

fn backend_unavailable(text: &str) -> bool {
    text.contains("Fatal error: cannot create 'R_TempDir'")
        || text.contains("failed to start R session")
        || text.contains("worker exited with status")
        || text.contains("unable to initialize the JIT")
        || text.contains(
            "worker protocol error: ipc disconnected while waiting for request completion",
        )
}

#[tokio::test(flavor = "multi_thread")]
async fn respects_configured_small_page_size() -> TestResult<()> {
    let page_bytes = 80;
    let mut session = common::spawn_server_with_pager_page_chars(page_bytes).await?;

    let result = session
        .write_stdin_raw_with("for (i in 1:50) cat('abcd\\n')", Some(10.0))
        .await?;
    let full_text = result_text(&result);
    if backend_unavailable(&full_text) {
        eprintln!("pager_page_size backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }
    session.cancel().await?;

    let chunks = text_chunks(&result);
    let first = chunks
        .iter()
        .find(|text| !text.contains("--More--") && !text.starts_with("(END"))
        .copied()
        .unwrap_or("");
    let expected_echo = "> for (i in 1:50) cat('abcd\\n')\n";
    let first_without_optional_echo = first.strip_prefix(expected_echo).unwrap_or(first);
    assert!(
        !first_without_optional_echo.is_empty(),
        "expected first page content, got: {first:?}"
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
    let full_text = result_text(&result);
    if backend_unavailable(&full_text) {
        eprintln!("pager_page_size backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }
    session.cancel().await?;

    let chunks = text_chunks(&result);
    assert!(
        !chunks.iter().any(|text| text.contains("--More--")),
        "did not expect pager footer"
    );

    Ok(())
}
