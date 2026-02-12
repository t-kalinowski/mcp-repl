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

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn r_respects_rprofile_and_renviron_on_startup() -> TestResult<()> {
    let home_dir = tempfile::tempdir()?;
    std::fs::write(
        home_dir.path().join(".Renviron"),
        "MCP_CONSOLE_RENVIRON_TEST=RENVIRON_OK_9f6f9f68\n",
    )?;
    std::fs::write(
        home_dir.path().join(".Rprofile"),
        "options(mcp_console_rprofile_test = \"RPROFILE_OK_6a8d0df6\")\n",
    )?;

    let mut session = common::spawn_server_with_env_vars(vec![(
        "HOME".to_string(),
        home_dir.path().to_string_lossy().to_string(),
    )])
    .await?;

    let result = session
        .write_stdin_raw_with(
            r#"
cat("RPROFILE=", getOption("mcp_console_rprofile_test"), "\n", sep = "")
cat("RENVIRON=", Sys.getenv("MCP_CONSOLE_RENVIRON_TEST"), "\n", sep = "")
"#,
            Some(10.0),
        )
        .await?;
    let text = result_text(&result);

    assert!(
        text.contains("RPROFILE=RPROFILE_OK_6a8d0df6"),
        "expected .Rprofile option to be set, got: {text:?}"
    );
    assert!(
        text.contains("RENVIRON=RENVIRON_OK_9f6f9f68"),
        "expected .Renviron variable to be set, got: {text:?}"
    );

    session.cancel().await?;
    Ok(())
}
