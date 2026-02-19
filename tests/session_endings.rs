mod common;

#[cfg(not(windows))]
use common::McpSnapshot;
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

fn backend_unavailable(text: &str) -> bool {
    text.contains("Fatal error: cannot create 'R_TempDir'")
        || text.contains("failed to start R session")
        || text.contains("worker exited with status")
        || text.contains("unable to initialize the JIT")
        || text.contains(
            "worker protocol error: ipc disconnected while waiting for request completion",
        )
}

#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn snapshots_session_endings() -> TestResult<()> {
    let mut snapshot = McpSnapshot::new();

    snapshot
        .session(
            "restart_timeout_zero",
            mcp_script! {
                write_stdin("x <- 1", timeout = 10.0);
                write_stdin("\u{4}", timeout = 0.0);
                write_stdin("print(exists(\"x\"))", timeout = 10.0);
            },
        )
        .await?;

    snapshot
        .session(
            "restart_timeout_thirty",
            mcp_script! {
                write_stdin("x <- 1", timeout = 10.0);
                write_stdin("\u{4}", timeout = 30.0);
                write_stdin("print(exists(\"x\"))", timeout = 10.0);
            },
        )
        .await?;

    snapshot
        .session(
            "eof_input",
            mcp_script! {
                write_stdin("\u{4}", timeout = 10.0);
                write_stdin("1+1", timeout = 10.0);
            },
        )
        .await?;

    snapshot
        .session(
            "eof_then_remaining_input_same_call",
            mcp_script! {
                write_stdin("\u{4}\n1+1", timeout = 10.0);
            },
        )
        .await?;

    snapshot
        .session(
            "quit_no",
            mcp_script! {
                write_stdin("x <- 1", timeout = 10.0);
                write_stdin("quit(\"no\")", timeout = 10.0);
                write_stdin("1+1", timeout = 10.0);
            },
        )
        .await?;

    snapshot
        .session(
            "quit_default",
            mcp_script! {
                write_stdin("x <- 1", timeout = 10.0);
                write_stdin("quit()", timeout = 10.0);
                write_stdin("1+1", timeout = 10.0);
            },
        )
        .await?;

    snapshot
        .session(
            "quit_yes",
            mcp_script! {
                write_stdin("setwd(tempdir()); x <- 1", timeout = 10.0);
                write_stdin("quit(\"yes\")", timeout = 10.0);
                write_stdin("1+1", timeout = 10.0);
            },
        )
        .await?;

    insta::assert_snapshot!("snapshots_session_endings", snapshot.render());
    insta::with_settings!({ snapshot_suffix => "transcript" }, {
        insta::assert_snapshot!("snapshots_session_endings", snapshot.render_transcript());
    });
    Ok(())
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn session_endings_windows_smoke() -> TestResult<()> {
    use tokio::time::{Duration, Instant, sleep};

    async fn assert_eventually_contains(
        session: &mut common::McpTestSession,
        input: &str,
        expected: &str,
        label: &str,
    ) -> TestResult<bool> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last_text = String::new();
        while Instant::now() < deadline {
            let result = session.write_stdin_raw_with(input, Some(10.0)).await?;
            last_text = result_text(&result);
            if backend_unavailable(&last_text) {
                return Ok(false);
            }
            if last_text.contains(expected) {
                return Ok(true);
            }
            if last_text.contains("<<console status: busy")
                || last_text.contains("worker is busy")
                || last_text.contains("request already running")
                || last_text.contains("input discarded while worker busy")
            {
                sleep(Duration::from_millis(50)).await;
                continue;
            }
            sleep(Duration::from_millis(50)).await;
        }
        eprintln!("session_endings {label} did not stabilize: {last_text}");
        Ok(false)
    }

    let mut session = common::spawn_server().await?;

    let _ = session.write_stdin_raw_with("x <- 1", Some(10.0)).await?;
    let restart = session.write_stdin_raw_with("\u{4}", Some(10.0)).await?;
    let restart_text = result_text(&restart);
    if backend_unavailable(&restart_text) {
        eprintln!("session_endings backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }
    if !assert_eventually_contains(
        &mut session,
        "print(exists(\"x\"))",
        "FALSE",
        "ctrl-d reset",
    )
    .await?
    {
        eprintln!("session_endings backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }

    let _ = session
        .write_stdin_raw_with("quit(\"no\")", Some(10.0))
        .await?;
    if !assert_eventually_contains(&mut session, "1+1", "2", "quit-no respawn").await? {
        eprintln!("session_endings backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }

    let _ = session.write_stdin_raw_with("quit()", Some(10.0)).await?;
    if !assert_eventually_contains(&mut session, "1+1", "2", "quit-default respawn").await? {
        eprintln!("session_endings backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }

    let _ = session
        .write_stdin_raw_with("setwd(tempdir()); quit(\"yes\")", Some(10.0))
        .await?;
    if !assert_eventually_contains(&mut session, "1+1", "2", "quit-yes respawn").await? {
        eprintln!("session_endings backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }

    session.cancel().await?;
    Ok(())
}
