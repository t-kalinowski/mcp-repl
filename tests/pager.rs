#![cfg(unix)]

mod common;

use common::{McpSnapshot, TestResult};

#[tokio::test(flavor = "multi_thread")]
async fn paginates_large_output() -> TestResult<()> {
    let mut snapshot = McpSnapshot::new();
    snapshot
        .session("default", mcp_script! {
            write_stdin("line <- paste(rep(\"x\", 200), collapse = \"\"); for (i in 1:200) cat(sprintf(\"line%04d %s\\n\", i, line))", timeout = 30.0);
            write_stdin("1+1", timeout = 10.0);
            write_stdin(":next", timeout = 30.0);
            write_stdin(":tail", timeout = 30.0);
            write_stdin("1+1", timeout = 10.0);
        })
        .await?;

    insta::assert_snapshot!("paginates_large_output", snapshot.render());
    insta::with_settings!({ snapshot_suffix => "transcript" }, {
        insta::assert_snapshot!("paginates_large_output", snapshot.render_transcript());
    });
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn pager_search_and_counts() -> TestResult<()> {
    let mut snapshot = McpSnapshot::new();
    snapshot
        .session("default", mcp_script! {
            write_stdin("line <- paste(rep(\"x\", 200), collapse = \"\"); for (i in 1:200) cat(sprintf(\"line%04d %s\\n\", i, line))", timeout = 30.0);
            write_stdin(":/line01", timeout = 30.0);
            write_stdin(":n", timeout = 30.0);
            write_stdin(":next 2", timeout = 30.0);
            write_stdin(":tail 2", timeout = 30.0);
            write_stdin("1+1", timeout = 10.0);
        })
        .await?;

    insta::assert_snapshot!("pager_search_and_counts", snapshot.render());
    insta::with_settings!({ snapshot_suffix => "transcript" }, {
        insta::assert_snapshot!("pager_search_and_counts", snapshot.render_transcript());
    });
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn pager_search_preserves_whitespace() -> TestResult<()> {
    let mut snapshot = McpSnapshot::new();
    snapshot
        .session("default", mcp_script! {
            write_stdin("line <- paste(rep(\"x\", 200), collapse = \"\"); for (i in 1:200) { suffix <- if (i == 25) \" r\" else if (i == 75) \"r \" else \"\"; cat(sprintf(\"line%04d %s%s\\n\", i, line, suffix)) }", timeout = 30.0);
            write_stdin(":where  r", timeout = 30.0);
            write_stdin(":/ r", timeout = 30.0);
            write_stdin(format!(":where r{}", " "), timeout = 30.0);
            write_stdin(format!(":/r{}", " "), timeout = 30.0);
            write_stdin(":q", timeout = 30.0);
        })
        .await?;

    insta::assert_snapshot!("pager_search_preserves_whitespace", snapshot.render());
    insta::with_settings!({ snapshot_suffix => "transcript" }, {
        insta::assert_snapshot!(
            "pager_search_preserves_whitespace",
            snapshot.render_transcript()
        );
    });
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn pager_search_case_insensitive_prefix_parsing() -> TestResult<()> {
    let mut snapshot = McpSnapshot::new();
    snapshot
        .session("default", mcp_script! {
            write_stdin("line <- paste(rep(\"x\", 200), collapse = \"\"); for (i in 1:200) cat(sprintf(\"line%04d %s\\n\", i, line))", timeout = 30.0);
            write_stdin(":where -i LINE01", timeout = 30.0);
            write_stdin(":/i LINE01", timeout = 30.0);
            write_stdin(":/iLINE01", timeout = 30.0);
            write_stdin(":q", timeout = 30.0);
        })
        .await?;

    insta::assert_snapshot!(
        "pager_search_case_insensitive_prefix_parsing",
        snapshot.render()
    );
    insta::with_settings!({ snapshot_suffix => "transcript" }, {
        insta::assert_snapshot!(
            "pager_search_case_insensitive_prefix_parsing",
            snapshot.render_transcript()
        );
    });
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn pager_matches_with_headings() -> TestResult<()> {
    let mut snapshot = McpSnapshot::new();
    snapshot
        .session("default", mcp_script! {
            write_stdin("cat('# Title\\n\\n## Alpha\\n'); for (i in 1:20) cat(sprintf('alpha line %02d foo\\n', i)); cat('\\n## Beta\\n'); for (i in 1:20) cat(sprintf('beta line %02d foo\\n', i))", timeout = 30.0);
            write_stdin(":matches foo", timeout = 30.0);
            write_stdin(":matches -C 1 foo", timeout = 30.0);
            write_stdin(":q", timeout = 30.0);
        })
        .await?;

    insta::assert_snapshot!("pager_matches_with_headings", snapshot.render());
    insta::with_settings!({ snapshot_suffix => "transcript" }, {
        insta::assert_snapshot!(
            "pager_matches_with_headings",
            snapshot.render_transcript()
        );
    });
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn pager_hits_mode() -> TestResult<()> {
    let mut snapshot = McpSnapshot::new();
    snapshot
        .session("default", mcp_script! {
            write_stdin("cat('# Title\\n'); for (i in 1:40) cat(sprintf('filler %02d xxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n', i)); cat('## Alpha\\n'); for (i in 1:3) cat(sprintf('alpha configure %02d\\n', i)); cat('## Beta\\n'); for (i in 1:3) cat(sprintf('beta configure %02d\\n', i))", timeout = 30.0);
            write_stdin(":hits configure", timeout = 30.0);
            write_stdin(":n", timeout = 30.0);
            write_stdin(":q", timeout = 30.0);
        })
        .await?;

    insta::assert_snapshot!("pager_hits_mode", snapshot.render());
    insta::with_settings!({ snapshot_suffix => "transcript" }, {
        insta::assert_snapshot!("pager_hits_mode", snapshot.render_transcript());
    });
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn pager_whitespace_only_input_advances_page() -> TestResult<()> {
    let mut snapshot = McpSnapshot::new();
    snapshot
        .session("default", mcp_script! {
            write_stdin("line <- paste(rep(\"x\", 200), collapse = \"\"); for (i in 1:200) cat(sprintf(\"line%04d %s\\n\", i, line))", timeout = 30.0);
            write_stdin("   ", timeout = 30.0);
            write_stdin(":q", timeout = 30.0);
        })
        .await?;

    insta::assert_snapshot!(
        "pager_whitespace_only_input_advances_page",
        snapshot.render()
    );
    insta::with_settings!({ snapshot_suffix => "transcript" }, {
        insta::assert_snapshot!(
            "pager_whitespace_only_input_advances_page",
            snapshot.render_transcript()
        );
    });
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn pager_dedup_on_seek() -> TestResult<()> {
    let mut snapshot = McpSnapshot::new();
    snapshot
        .session("default", mcp_script! {
            write_stdin("line <- paste(rep(\"x\", 120), collapse = \"\"); for (i in 1:40) cat(sprintf(\"line%02d %s\\n\", i, line))", timeout = 30.0);
            write_stdin(":next", timeout = 30.0);
            write_stdin(":seek 0", timeout = 30.0);
            write_stdin(":next", timeout = 30.0);
            write_stdin(":q", timeout = 30.0);
        })
        .await?;

    insta::assert_snapshot!("pager_dedup_on_seek", snapshot.render());
    insta::with_settings!({ snapshot_suffix => "transcript" }, {
        insta::assert_snapshot!("pager_dedup_on_seek", snapshot.render_transcript());
    });
    Ok(())
}
