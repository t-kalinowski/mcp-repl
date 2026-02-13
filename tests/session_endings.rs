#![cfg(unix)]

mod common;

use common::{McpSnapshot, TestResult};

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
