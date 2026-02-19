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

    let home = home_dir.path().to_string_lossy().to_string();
    let mut env_vars = vec![
        ("HOME".to_string(), home.clone()),
        ("R_USER".to_string(), home.clone()),
    ];
    #[cfg(windows)]
    {
        env_vars.push(("USERPROFILE".to_string(), home.clone()));
        if home.len() >= 3
            && home.as_bytes()[1] == b':'
            && (home.as_bytes()[2] == b'\\' || home.as_bytes()[2] == b'/')
        {
            env_vars.push(("HOMEDRIVE".to_string(), home[..2].to_string()));
            env_vars.push(("HOMEPATH".to_string(), home[2..].to_string()));
        }
    }

    let mut session = common::spawn_server_with_env_vars(env_vars).await?;

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
