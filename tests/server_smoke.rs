#![cfg(unix)]

mod common;

use common::{McpSnapshot, TestResult};

#[tokio::test(flavor = "multi_thread")]
async fn sends_input_to_r_console() -> TestResult<()> {
    let mut snapshot = McpSnapshot::new();
    snapshot
        .session(
            "default",
            mcp_script! {
                write_stdin("1+1", timeout = 10.0);
            },
        )
        .await?;

    insta::assert_snapshot!("sends_input_to_r_console", snapshot.render());
    insta::with_settings!({ snapshot_suffix => "transcript" }, {
        insta::assert_snapshot!("sends_input_to_r_console", snapshot.render_transcript());
    });
    Ok(())
}
