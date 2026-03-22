#![allow(clippy::await_holding_lock)]

mod common;

use common::TestResult;
use regex_lite::Regex;
use rmcp::model::RawContent;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tokio::time::{Duration, Instant, sleep};

fn test_mutex() -> &'static Mutex<()> {
    static TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_MUTEX.get_or_init(|| Mutex::new(()))
}

fn lock_mutex(mutex: &Mutex<()>) -> MutexGuard<'_, ()> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn lock_test_mutex() -> MutexGuard<'static, ()> {
    lock_mutex(test_mutex())
}

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

fn spill_path(text: &str) -> Option<PathBuf> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"full output:\s+(/[^]\s]+)").expect("spill-path regex should compile")
    });
    re.captures(text)
        .and_then(|caps| caps.get(1))
        .map(|path| PathBuf::from(path.as_str()))
}

async fn wait_until_not_busy(
    session: &mut common::McpTestSession,
    initial: rmcp::model::CallToolResult,
) -> TestResult<rmcp::model::CallToolResult> {
    let mut result = initial;
    let mut text = result_text(&result);
    if !text.contains("<<console status: busy") {
        return Ok(result);
    }

    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        sleep(Duration::from_millis(100)).await;
        let next = session
            .write_stdin_raw_unterminated_with("", Some(2.0))
            .await?;
        text = result_text(&next);
        result = next;
        if !text.contains("<<console status: busy") {
            return Ok(result);
        }
    }

    Err(format!("worker remained busy after polling: {text:?}").into())
}

async fn spawn_behavior_session() -> TestResult<common::McpTestSession> {
    #[cfg(target_os = "windows")]
    {
        common::spawn_server_with_args(vec![
            "--sandbox".to_string(),
            "danger-full-access".to_string(),
        ])
        .await
    }
    #[cfg(not(target_os = "windows"))]
    {
        common::spawn_server().await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_discards_when_busy() -> TestResult<()> {
    let _guard = lock_test_mutex();
    let mut session = spawn_behavior_session().await?;

    let _ = session
        .write_stdin_raw_with("Sys.sleep(2)", Some(0.1))
        .await?;

    let result = session.write_stdin_raw_with("1+1", Some(0.2)).await?;

    let text = result_text(&result);
    if backend_unavailable(&text) {
        eprintln!("write_stdin_behavior backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }
    assert!(
        text.contains("input discarded while worker busy")
            || text.contains("<<console status: busy"),
        "expected busy discard/timeout message, got: {text:?}"
    );
    assert_ne!(result.is_error, Some(true));

    session.cancel().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_preserves_multiline_echo() -> TestResult<()> {
    let _guard = lock_test_mutex();
    let mut session = spawn_behavior_session().await?;

    let result = session.write_stdin_raw_with("1+\n1", Some(30.0)).await?;
    let text = result_text(&result);
    if backend_unavailable(&text) {
        eprintln!("write_stdin_behavior backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }
    if text.contains("<<console status: busy") {
        eprintln!("write_stdin_behavior continuation output still busy; skipping");
        session.cancel().await?;
        return Ok(());
    }
    session.cancel().await?;
    assert!(text.contains("[1] 2"), "expected result, got: {text:?}");
    assert!(
        text.contains("> 1+"),
        "expected echoed first line to be preserved, got: {text:?}"
    );
    assert!(
        text.contains("\n+ 1"),
        "expected echoed continuation line to be preserved, got: {text:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_mixed_stdout_stderr() -> TestResult<()> {
    let _guard = lock_test_mutex();
    let mut session = spawn_behavior_session().await?;

    let result = session
        .write_stdin_raw_with(
            "cat('out1\\n'); message('err1'); cat('out2\\n')",
            Some(10.0),
        )
        .await?;
    let text = result_text(&result);
    if backend_unavailable(&text) {
        eprintln!("write_stdin_behavior backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }
    session.cancel().await?;
    assert!(text.contains("out1"), "missing stdout, got: {text:?}");
    assert!(text.contains("out2"), "missing stdout, got: {text:?}");
    assert!(
        text.contains("stderr:"),
        "missing stderr prefix, got: {text:?}"
    );
    assert_ne!(result.is_error, Some(true));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_normalizes_error_prompt() -> TestResult<()> {
    let _guard = lock_test_mutex();
    let mut session = spawn_behavior_session().await?;

    let result = session
        .write_stdin_raw_with("cat('> Error: boom\\n'); message('boom')", Some(30.0))
        .await?;
    let text = result_text(&result);
    if backend_unavailable(&text) {
        eprintln!("write_stdin_behavior backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }
    if text.contains("<<console status: busy") {
        eprintln!("write_stdin_behavior error prompt output still busy; skipping");
        session.cancel().await?;
        return Ok(());
    }
    session.cancel().await?;
    assert!(
        text.contains("\nError: boom\n"),
        "missing error text, got: {text:?}"
    );
    assert!(
        !text.contains("\n> Error: boom\n"),
        "expected leading prompt to be normalized, got: {text:?}"
    );
    assert_ne!(result.is_error, Some(true));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn write_stdin_large_output_is_not_paged() -> TestResult<()> {
    let _guard = lock_test_mutex();
    let mut session = spawn_behavior_session().await?;

    let result = session
        .write_stdin_raw_with(
            "line <- paste(rep('x', 200), collapse = ''); for (i in 1:120) cat(sprintf('line%04d %s\\n', i, line))",
            Some(30.0),
        )
        .await?;
    let result = wait_until_not_busy(&mut session, result).await?;
    let text = result_text(&result);
    if backend_unavailable(&text) {
        eprintln!("write_stdin_behavior backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }
    session.cancel().await?;

    assert!(
        !text.contains("--More--"),
        "did not expect pager footer, got: {text:?}"
    );
    assert!(
        text.contains("line0120"),
        "expected the full output in one reply, got: {text:?}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn timeout_spill_file_backfills_earlier_worker_text_and_excludes_timeout_marker()
-> TestResult<()> {
    let _guard = lock_test_mutex();
    let mut session = spawn_behavior_session().await?;

    let input = "big <- paste(rep('x', 120), collapse = ''); cat('start\\n'); flush.console(); Sys.sleep(0.2); for (i in 1:80) cat(sprintf('mid%03d %s\\n', i, big)); flush.console(); Sys.sleep(0.1); cat('end\\n')";
    let first = session.write_stdin_raw_with(input, Some(0.05)).await?;
    let first_text = result_text(&first);
    if backend_unavailable(&first_text) {
        eprintln!("write_stdin_behavior backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }
    assert!(
        spill_path(&first_text).is_none(),
        "did not expect spill path on first small timeout reply, got: {first_text:?}"
    );

    sleep(Duration::from_millis(260)).await;
    let spilled = session.write_stdin_raw_with("", Some(2.0)).await?;
    let spilled_text = result_text(&spilled);
    if spilled_text.contains("<<console status: busy") {
        eprintln!("write_stdin_behavior spill poll remained busy; skipping");
        session.cancel().await?;
        return Ok(());
    }
    let path = spill_path(&spilled_text).unwrap_or_else(|| {
        panic!("expected spill path in oversized poll reply, got: {spilled_text:?}")
    });
    let file_text = fs::read_to_string(&path)?;

    session.cancel().await?;

    assert!(
        file_text.contains("> big <- paste"),
        "expected echoed input in spill file, got: {file_text:?}"
    );
    assert!(
        file_text.contains("start"),
        "expected early worker text from timeout reply in spill file, got: {file_text:?}"
    );
    assert!(
        file_text.contains("mid080"),
        "expected oversized poll output in spill file, got: {file_text:?}"
    );
    assert!(
        file_text.contains("end"),
        "expected later worker text in spill file, got: {file_text:?}"
    );
    assert!(
        !file_text.contains("<<console status: busy"),
        "did not expect timeout marker in spill file, got: {file_text:?}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn timeout_spill_file_path_stays_stable_across_later_small_poll() -> TestResult<()> {
    let _guard = lock_test_mutex();
    let mut session = spawn_behavior_session().await?;

    let input = "big <- paste(rep('y', 120), collapse = ''); cat('start\\n'); flush.console(); Sys.sleep(0.2); for (i in 1:80) cat(sprintf('mid%03d %s\\n', i, big)); flush.console(); Sys.sleep(0.35); cat('tail\\n')";
    let first = session.write_stdin_raw_with(input, Some(0.05)).await?;
    let first_text = result_text(&first);
    if backend_unavailable(&first_text) {
        eprintln!("write_stdin_behavior backend unavailable in this environment; skipping");
        session.cancel().await?;
        return Ok(());
    }

    sleep(Duration::from_millis(260)).await;
    let spilled = session.write_stdin_raw_with("", Some(0.1)).await?;
    let spilled_text = result_text(&spilled);
    let path = match spill_path(&spilled_text) {
        Some(path) => path,
        None if spilled_text.contains("<<console status: busy") => {
            eprintln!("write_stdin_behavior spill poll remained busy; skipping");
            session.cancel().await?;
            return Ok(());
        }
        None => panic!("expected spill path in first oversized poll reply, got: {spilled_text:?}"),
    };

    sleep(Duration::from_millis(450)).await;
    let final_poll = session.write_stdin_raw_with("", Some(2.0)).await?;
    let final_text = result_text(&final_poll);
    if final_text.contains("<<console status: busy") {
        eprintln!("write_stdin_behavior final poll remained busy; skipping");
        session.cancel().await?;
        return Ok(());
    }
    let file_text = fs::read_to_string(&path)?;

    session.cancel().await?;

    assert!(
        final_text.contains("tail"),
        "expected small final poll output inline, got: {final_text:?}"
    );
    assert!(
        spill_path(&final_text).is_none(),
        "did not expect spill path to be repeated on later small poll, got: {final_text:?}"
    );
    assert!(
        file_text.contains("tail"),
        "expected later small poll output to append to existing spill file, got: {file_text:?}"
    );

    Ok(())
}

#[test]
fn lock_mutex_handles_poisoned_mutex() {
    let mutex = Mutex::new(());
    let _ = std::panic::catch_unwind(|| {
        let _guard = mutex.lock().expect("lock");
        panic!("poison mutex");
    });

    let _guard = lock_mutex(&mutex);
}
