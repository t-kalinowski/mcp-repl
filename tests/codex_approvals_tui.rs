mod common;

use common::TestResult;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix_impl {
    use super::{TestResult, common};
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use serde_json::Value;
    use std::io::{ErrorKind, Read, Write};
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{Receiver, RecvTimeoutError};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use vt100::Parser;

    const TEST_MARKER: &str = "SANDBOX_TEST_1";
    const WARMUP_MARKER: &str = "WARMUP_TEST";
    const CALL_ID: &str = "call-1";

    pub(super) async fn run_codex_tui_initial_sandbox_state() -> TestResult<Vec<Step>> {
        if !codex_available() {
            eprintln!("codex not found on PATH; skipping");
            return Ok(Vec::new());
        }
        if !common::sandbox_exec_available() {
            eprintln!("sandbox-exec unavailable; skipping");
            return Ok(Vec::new());
        }
        if !loopback_bind_available().await {
            eprintln!("loopback TCP bind unavailable; skipping");
            return Ok(Vec::new());
        }

        let repo_root = std::env::current_dir()?;
        let mcp_console = resolve_mcp_console_path()?;
        let temp_dir = tempfile::tempdir()?;
        let codex_home = temp_dir.path().join("codex-home");
        std::fs::create_dir_all(&codex_home)?;
        let sandbox_log_dir = tempfile::tempdir_in(&repo_root)?;
        let sandbox_log = sandbox_log_dir.path().join("sandbox-state.log");
        let r_code = sandbox_run_code();
        let tool_args = serde_json::json!({
            "input": format!("{r_code}\n"),
        })
        .to_string();
        let mock_server = MockResponsesServer::start(tool_name(), tool_args.clone()).await?;
        let config = codex_config(&mcp_console, &repo_root);
        std::fs::write(codex_home.join("config.toml"), config)?;
        let mut driver = CodexPtyDriver::spawn(
            &codex_home,
            &repo_root,
            &mock_server.base_url(),
            &sandbox_log,
        )?;
        driver.drain(Duration::from_millis(800));
        driver.ensure_running("after startup")?;
        let mut steps = Vec::new();
        driver.wait_for_warmup(Duration::from_secs(10))?;
        steps.push(Step::new("warmup", driver.snapshot_screen()));
        wait_for_log_contains(&sandbox_log, "workspace-write", Duration::from_secs(10))?;

        driver.send_line(&format!("{TEST_MARKER}: run the sandbox write test"))?;
        if let Err(err) = driver.wait_for_contains("WRITE_OK", Duration::from_secs(20)) {
            let request_count = mock_server.request_count().await;
            let last_request = mock_server.last_request().await;
            let request_paths = mock_server.request_paths().await;
            let _ = driver.kill();
            return Err(format!(
                "{err}\nrequests: {request_count}\nrequest_paths: {request_paths:?}\nlast_request: {last_request:?}"
            )
            .into());
        }
        driver.wait_for_contains("Tool call 1 completed", Duration::from_secs(20))?;
        steps.push(Step::new(
            "after workspace-write call",
            driver.snapshot_screen(),
        ));

        driver.kill()?;
        let outputs = mock_server.function_call_outputs().await;
        assert!(
            outputs.iter().any(|out| out.contains("WRITE_OK")),
            "expected workspace-write call to succeed, outputs: {outputs:?}"
        );

        Ok(steps)
    }

    async fn loopback_bind_available() -> bool {
        TcpListener::bind("127.0.0.1:0").await.is_ok()
    }

    fn codex_available() -> bool {
        std::process::Command::new("codex")
            .arg("--version")
            .output()
            .is_ok()
    }

    fn resolve_mcp_console_path() -> TestResult<PathBuf> {
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_mcp-repl") {
            return Ok(PathBuf::from(path));
        }
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_mcp-console") {
            return Ok(PathBuf::from(path));
        }

        let mut path = std::env::current_exe()?;
        path.pop();
        path.pop();
        for candidate in ["mcp-repl", "mcp-console"] {
            let mut candidate_path = path.clone();
            candidate_path.push(candidate);
            if cfg!(windows) {
                candidate_path.set_extension("exe");
            }
            if candidate_path.exists() {
                return Ok(candidate_path);
            }
        }
        Err("unable to locate mcp-repl test binary".into())
    }

    fn tool_name() -> String {
        "mcp__r__repl".to_string()
    }

    fn codex_config(mcp_console: &Path, repo_root: &Path) -> String {
        let mcp_console = toml_escape(&mcp_console.display().to_string());
        let repo_root = toml_escape(&repo_root.display().to_string());
        format!(
            r#"model_provider = "ollama"
model = "gpt-5.1-codex-mini"
disable_paste_burst = true

[notice]
hide_full_access_warning = true

[tui]
alternate_screen = "never"
animations = false

[features]
steer = true
remote_models = true
responses_websockets = false

[mcp_servers.r]
command = "{mcp_console}"
env_vars = ["MCP_CONSOLE_SANDBOX_STATE_LOG"]
[projects."{repo_root}"]
trust_level = "trusted"
"#
        )
    }

    fn toml_escape(value: &str) -> String {
        value.replace('\\', "\\\\").replace('"', "\\\"")
    }

    fn sandbox_run_code() -> String {
        "target <- tempfile(\"mcp-console-codex\")\ntryCatch({\n  writeLines(\"ok\", target)\n  cat(\"WRITE_OK\\n\")\n  unlink(target)\n}, error = function(e) {\n  message(\"WRITE_ERROR:\", conditionMessage(e))\n})"
            .to_string()
    }

    pub(super) struct Step {
        label: String,
        screen: String,
    }

    impl Step {
        fn new(label: &str, screen: String) -> Self {
            Self {
                label: label.to_string(),
                screen,
            }
        }
    }

    pub(super) fn render_steps(steps: &[Step]) -> String {
        let mut out = String::new();
        for (index, step) in steps.iter().enumerate() {
            if index > 0 {
                out.push('\n');
            }
            out.push_str(&format!("== {} ==\n", step.label));
            out.push_str(&normalize_screen(&step.screen));
            out.push('\n');
        }
        out.trim_end().to_string()
    }

    fn normalize_screen(screen: &str) -> String {
        fn is_prompt_line(line: &str) -> bool {
            line.as_bytes().starts_with(&[0xE2, 0x80, 0xBA])
        }

        fn normalize_codex_version(line: &str) -> String {
            let Some(start) = line.find("OpenAI Codex (v") else {
                return line.to_string();
            };
            let version_start = start + "OpenAI Codex (".len();
            let Some(version_end_rel) = line[version_start..].find(')') else {
                return line.to_string();
            };
            let version_end = version_start + version_end_rel;
            let mut out = line.to_string();
            let original_len = out.len();
            out.replace_range(version_start..version_end, "vN.NN.N");
            if out.len() < original_len {
                let pad = original_len - out.len();
                if let Some(border_idx) = out.rfind('│') {
                    out.insert_str(border_idx, &" ".repeat(pad));
                } else {
                    out.push_str(&" ".repeat(pad));
                }
            } else if out.len() > original_len {
                let mut excess = out.len() - original_len;
                if let Some(border_idx) = out.rfind('│') {
                    let mut start = border_idx;
                    let bytes = out.as_bytes();
                    while excess > 0 && start > 0 && bytes[start - 1] == b' ' {
                        start -= 1;
                        excess -= 1;
                    }
                    if start < border_idx {
                        out.replace_range(start..border_idx, "");
                    }
                }
            }
            out
        }

        fn is_horizontal_rule(line: &str) -> bool {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return false;
            }
            if trimmed.contains("Worked for ") {
                return true;
            }
            trimmed.chars().all(|ch| ch == '─')
        }

        let mut lines: Vec<String> = Vec::new();
        let mut skipping_underdev_warning = false;
        let mut skipping_wrapped_tool_args = false;
        for raw in screen.lines() {
            let line = raw.trim_end().to_string();

            if skipping_wrapped_tool_args {
                let trimmed = line.trim_start();
                let indent = line.len().saturating_sub(trimmed.len());
                if trimmed.is_empty() || indent >= 4 {
                    continue;
                }
                skipping_wrapped_tool_args = false;
            }

            if skipping_underdev_warning {
                if line.starts_with("  ") {
                    continue;
                }
                skipping_underdev_warning = false;
            }

            let trimmed = line.trim_start();
            if trimmed.starts_with("└ r.repl(") {
                // This line may wrap differently between Codex versions; keep the structure but
                // omit the unstable argument rendering.
                lines.push("  └ r.repl(<omitted>)".to_string());
                skipping_wrapped_tool_args = true;
                continue;
            }
            if trimmed.starts_with("⚠ Under-development features enabled:") {
                skipping_underdev_warning = true;
                continue;
            }

            let normalized_for_checks =
                normalize_temp_paths(&normalize_codex_home_path(&normalize_codex_version(&line)));
            let trimmed_normalized = normalized_for_checks.trim_start();
            if normalized_for_checks.starts_with("  ")
                && trimmed_normalized == "<CODEX_HOME>/config.toml."
            {
                continue;
            }

            if trimmed.starts_with("guides/") {
                continue;
            }
            if trimmed.contains("developers.openai.com/mcp") {
                continue;
            }
            if trimmed.contains("directory:") {
                continue;
            }
            if trimmed == "experimental!" {
                continue;
            }
            if trimmed.starts_with("Tip:") {
                continue;
            }
            if trimmed.starts_with("• Starting MCP servers") || trimmed.starts_with("• Working")
            {
                continue;
            }
            if trimmed.starts_with("⚠ MCP startup incomplete")
                || trimmed.starts_with("⚠ MCP client for `mcp-console` failed to start")
            {
                continue;
            }
            if is_prompt_line(trimmed)
                && !trimmed.contains(WARMUP_MARKER)
                && !trimmed.contains(TEST_MARKER)
            {
                continue;
            }
            if is_horizontal_rule(trimmed) {
                continue;
            }
            if lines.is_empty() && trimmed.is_empty() {
                continue;
            }
            if lines.is_empty() && trimmed.starts_with("╰") {
                continue;
            }
            if lines.is_empty() && trimmed.contains(WARMUP_MARKER) {
                continue;
            }

            lines.push(normalize_temp_paths(&normalize_codex_home_path(
                &normalize_codex_version(&line),
            )));
        }

        // Codex output can vary a bit between versions (extra blank lines), so make the snapshot
        // resilient by collapsing consecutive empty lines.
        let mut collapsed: Vec<String> = Vec::with_capacity(lines.len());
        let mut previous_was_empty = false;
        for line in lines {
            let is_empty = line.trim().is_empty();
            if is_empty && previous_was_empty {
                continue;
            }
            previous_was_empty = is_empty;
            collapsed.push(line);
        }
        let mut lines = collapsed;

        if let Some(first_nonempty) = lines.iter().position(|line| !line.trim().is_empty())
            && first_nonempty > 0
        {
            lines.drain(0..first_nonempty);
        }

        while matches!(lines.last(), Some(line) if line.trim().is_empty()) {
            lines.pop();
        }

        if lines.len() >= 2 {
            let last_line = lines[lines.len() - 1].trim_start();
            if last_line.contains("context left") {
                lines.pop();
                if let Some(prev) = lines.last()
                    && is_prompt_line(prev)
                {
                    lines.pop();
                }
            }
        }

        if matches!(lines.last(), Some(line) if is_prompt_line(line)) {
            lines.pop();
        }

        let normalized: Vec<String> = lines.into_iter().map(|line| scrub_seconds(&line)).collect();
        normalized.join("\n").trim_end().to_string()
    }

    fn scrub_seconds(line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch.is_ascii_digit() {
                let mut digits = String::new();
                digits.push(ch);
                while let Some(next) = chars.peek()
                    && next.is_ascii_digit()
                {
                    digits.push(*next);
                    chars.next();
                }
                if matches!(chars.peek(), Some('s')) {
                    chars.next();
                    out.push_str("Ns");
                } else {
                    out.push_str(&digits);
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    fn normalize_codex_home_path(line: &str) -> String {
        let needle = "codex-home/config.toml";
        let Some(path_end) = line.find(needle) else {
            return line.to_string();
        };

        let mut path_start = path_end;
        while path_start > 0 {
            let ch = line.as_bytes()[path_start - 1];
            if ch == b' ' {
                break;
            }
            path_start -= 1;
        }

        let mut normalized = line.to_string();
        let replacement = "<CODEX_HOME>/config.toml";
        normalized.replace_range(path_start..path_end + needle.len(), replacement);
        normalized
    }

    fn normalize_temp_paths(line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut idx = 0;
        let bytes = line.as_bytes();
        while let Some(pos) = line[idx..].find("/tmp/.tmp") {
            let abs_pos = idx + pos;
            out.push_str(&line[idx..abs_pos]);
            let mut end = abs_pos + "/tmp/.tmp".len();
            while end < bytes.len() {
                let ch = bytes[end];
                if ch.is_ascii_whitespace() || ch == b'/' {
                    break;
                }
                end += 1;
            }
            let mut had_slash = false;
            if end < bytes.len() && bytes[end] == b'/' {
                had_slash = true;
                end += 1;
            }
            out.push_str("/tmp/<TMP>");
            if had_slash {
                out.push('/');
            }
            idx = end;
        }
        out.push_str(&line[idx..]);
        out
    }

    fn wait_for_log_contains(path: &Path, needle: &str, timeout: Duration) -> TestResult<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(contents) = std::fs::read_to_string(path)
                && contents.contains(needle)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let contents = std::fs::read_to_string(path)
                    .map_err(|err| format!("sandbox log read failed: {err}"))
                    .unwrap_or_else(|err| err);
                return Err(format!(
                    "timeout waiting for sandbox log to contain {needle}\nlog path: {path:?}\nlog contents:\n{contents}"
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn detect_cursor_request(
        chunk: &[u8],
        carry: &mut Vec<u8>,
        writer: &Arc<Mutex<Box<dyn Write + Send>>>,
    ) {
        let mut data = Vec::with_capacity(carry.len() + chunk.len());
        data.extend_from_slice(carry);
        data.extend_from_slice(chunk);
        let mut idx = 0;
        while idx + 3 < data.len() {
            if data[idx..idx + 4] == [0x1b, 0x5b, 0x36, 0x6e]
                && let Ok(mut guard) = writer.lock()
            {
                let _ = guard.write_all(b"\x1b[1;1R");
                let _ = guard.flush();
            }
            idx += 1;
        }
        let keep = data.len().saturating_sub(3);
        carry.clear();
        carry.extend_from_slice(&data[keep..]);
    }

    struct CodexPtyDriver {
        child: Box<dyn portable_pty::Child + Send>,
        writer: Arc<Mutex<Box<dyn Write + Send>>>,
        rx: Receiver<Vec<u8>>,
        parser: Parser,
        _master: Box<dyn portable_pty::MasterPty + Send>,
        _slave: Box<dyn portable_pty::SlavePty + Send>,
    }

    impl CodexPtyDriver {
        fn spawn(
            codex_home: &Path,
            repo_root: &Path,
            base_url: &str,
            sandbox_log: &Path,
        ) -> TestResult<Self> {
            let pty_system = native_pty_system();
            let pair = pty_system
                .openpty(PtySize {
                    rows: 32,
                    cols: 110,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|err| format!("openpty failed: {err}"))?;

            let mut cmd = CommandBuilder::new("codex");
            cmd.arg("--sandbox");
            cmd.arg("workspace-write");
            cmd.arg("--ask-for-approval");
            cmd.arg("on-request");
            cmd.arg("--cd");
            cmd.arg(repo_root);
            cmd.arg(WARMUP_MARKER);
            cmd.env("CODEX_HOME", codex_home);
            cmd.env("TERM", "xterm-256color");
            cmd.env("CODEX_OSS_BASE_URL", base_url);
            cmd.env("MCP_CONSOLE_SANDBOX_STATE_LOG", sandbox_log);
            if let Ok(path) = std::env::var("PATH") {
                cmd.env("PATH", path);
            }
            if let Ok(home) = std::env::var("HOME") {
                cmd.env("HOME", home);
            }

            let child = pair
                .slave
                .spawn_command(cmd)
                .map_err(|err| format!("spawn codex failed: {err}"))?;
            let reader = pair
                .master
                .try_clone_reader()
                .map_err(|err| format!("clone reader failed: {err}"))?;
            let writer = pair
                .master
                .take_writer()
                .map_err(|err| format!("take writer failed: {err}"))?;
            let writer = Arc::new(Mutex::new(writer));
            let reader_writer = Arc::clone(&writer);
            let (tx, rx) = std::sync::mpsc::channel();

            std::thread::spawn(move || {
                let mut reader = reader;
                let mut buf = [0u8; 8192];
                let mut carry = Vec::new();
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            detect_cursor_request(&buf[..n], &mut carry, &reader_writer);
                            if tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                        Err(err) if err.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            });

            Ok(Self {
                child,
                writer,
                rx,
                parser: Parser::new(32, 110, 0),
                _master: pair.master,
                _slave: pair.slave,
            })
        }

        fn send(&mut self, text: &str) -> TestResult<()> {
            let mut writer = self.writer.lock().map_err(|_| "pty lock failed")?;
            writer
                .write_all(text.as_bytes())
                .map_err(|err| format!("pty write failed: {err}"))?;
            writer
                .flush()
                .map_err(|err| format!("pty flush failed: {err}"))?;
            Ok(())
        }

        fn send_line(&mut self, text: &str) -> TestResult<()> {
            self.send_slow(text, Duration::from_millis(12))
                .map_err(|err| format!("pty write line failed: {err}"))?;
            self.send("\r")
                .map_err(|err| format!("pty write enter failed: {err}"))?;
            Ok(())
        }

        fn send_slow(&mut self, text: &str, delay: Duration) -> TestResult<()> {
            for ch in text.chars() {
                let mut buf = [0u8; 4];
                let slice = ch.encode_utf8(&mut buf);
                self.send(slice)?;
                std::thread::sleep(delay);
            }
            Ok(())
        }

        fn drain(&mut self, duration: Duration) {
            let deadline = Instant::now() + duration;
            while Instant::now() < deadline {
                match self.rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(chunk) => self.parser.process(&chunk),
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        }

        fn wait_for_contains(&mut self, needle: &str, timeout: Duration) -> TestResult<()> {
            let ok = self.wait_for_screen(timeout, |screen| screen.contains(needle));
            if ok {
                Ok(())
            } else {
                Err(format!(
                    "timeout waiting for screen to contain {needle}\n{}",
                    normalize_screen(&self.snapshot_screen())
                )
                .into())
            }
        }

        fn wait_for_warmup(&mut self, timeout: Duration) -> TestResult<()> {
            let deadline = Instant::now() + timeout;
            let mut dismissed_upgrade = false;
            loop {
                self.drain(Duration::from_millis(100));
                let snapshot = self.snapshot_screen();
                if snapshot.contains("Warmup complete") {
                    return Ok(());
                }
                if !dismissed_upgrade
                    && (snapshot.contains("Codex just got an upgrade")
                        || snapshot.contains("Use existing model"))
                {
                    self.send("\u{1b}[B")?;
                    self.send("\r")?;
                    dismissed_upgrade = true;
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "timeout waiting for screen to contain Warmup complete\n{}",
                        normalize_screen(&self.snapshot_screen())
                    )
                    .into());
                }
            }
        }

        fn wait_for_screen(
            &mut self,
            timeout: Duration,
            mut predicate: impl FnMut(&str) -> bool,
        ) -> bool {
            let deadline = Instant::now() + timeout;
            loop {
                self.drain(Duration::from_millis(100));
                let snapshot = self.snapshot_screen();
                if predicate(&snapshot) {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
            }
        }

        fn snapshot_screen(&self) -> String {
            self.parser.screen().contents()
        }

        fn ensure_running(&mut self, context: &str) -> TestResult<()> {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|err| format!("codex wait failed: {err}"))?
            {
                return Err(format!(
                    "codex exited {context}: {status:?}\n{}",
                    normalize_screen(&self.snapshot_screen())
                )
                .into());
            }
            Ok(())
        }

        fn kill(mut self) -> TestResult<()> {
            let _ = self.child.kill();
            let _ = self.child.wait();
            Ok(())
        }
    }

    struct MockResponsesServer {
        addr: SocketAddr,
        state: Arc<tokio::sync::Mutex<MockState>>,
    }

    struct MockState {
        tool_name: String,
        tool_args: String,
        requests: Vec<Value>,
        request_paths: Vec<String>,
        phase: MockPhase,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum MockPhase {
        Init,
        WaitingCall,
        CallDone,
    }

    impl MockResponsesServer {
        async fn start(tool_name: String, tool_args: String) -> TestResult<Self> {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let state = Arc::new(tokio::sync::Mutex::new(MockState {
                tool_name,
                tool_args,
                requests: Vec::new(),
                request_paths: Vec::new(),
                phase: MockPhase::Init,
            }));
            let state_clone = Arc::clone(&state);
            tokio::spawn(async move {
                loop {
                    let (socket, _) = match listener.accept().await {
                        Ok(pair) => pair,
                        Err(_) => break,
                    };
                    let state = Arc::clone(&state_clone);
                    tokio::spawn(async move {
                        let _ = handle_connection(socket, state).await;
                    });
                }
            });

            Ok(Self { addr, state })
        }

        fn base_url(&self) -> String {
            format!("http://{}/v1", self.addr)
        }

        async fn request_count(&self) -> usize {
            let state = self.state.lock().await;
            state.request_paths.len()
        }

        async fn last_request(&self) -> Option<Value> {
            let state = self.state.lock().await;
            state.requests.last().cloned()
        }

        async fn request_paths(&self) -> Vec<String> {
            let state = self.state.lock().await;
            state.request_paths.clone()
        }

        async fn function_call_outputs(&self) -> Vec<String> {
            let state = self.state.lock().await;
            collect_function_call_outputs(&state.requests)
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        state: Arc<tokio::sync::Mutex<MockState>>,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).await? == 0 {
            return Ok(());
        }
        let request_line = request_line.trim_end();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");

        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':')
                && key.eq_ignore_ascii_case("content-length")
            {
                content_length = value.trim().parse::<usize>().unwrap_or(0);
            }
        }

        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).await?;
        }

        {
            let mut locked = state.lock().await;
            locked.request_paths.push(format!("{method} {path}"));
        }

        let response_body = if method == "GET" && path.contains("/models") {
            models_response()
        } else if method == "POST" && path.contains("/responses") {
            let body_json = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
            {
                let mut locked = state.lock().await;
                locked.requests.push(body_json.clone());
                response_for_request(&body_json, &mut locked)
            }
        } else {
            r#"{"error":"unsupported"}"#.to_string()
        };

        let is_event_stream = method == "POST" && path.contains("/responses");
        let content_type = if is_event_stream {
            "text/event-stream"
        } else {
            "application/json"
        };
        let status = if is_event_stream || path.contains("/models") {
            "HTTP/1.1 200 OK\r\n"
        } else {
            "HTTP/1.1 404 Not Found\r\n"
        };
        let response = format!(
            "{status}Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len()
        );
        let stream = reader.get_mut();
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
        Ok(())
    }

    fn models_response() -> String {
        serde_json::json!({
            "models": [{
                "slug": "gpt-5.1-codex-mini",
                "display_name": "gpt-5.1-codex-mini",
                "description": "mock model",
                "default_reasoning_level": "low",
                "supported_reasoning_levels": [{"effort": "low", "description": "low"}],
                "shell_type": "shell_command",
                "visibility": "list",
                "supported_in_api": true,
                "priority": 1,
                "upgrade": null,
                "base_instructions": "test instructions",
                "model_instructions_template": null,
                "supports_reasoning_summaries": false,
                "support_verbosity": false,
                "default_verbosity": null,
                "apply_patch_tool_type": null,
                "truncation_policy": {"mode": "bytes", "limit": 10000},
                "supports_parallel_tool_calls": false,
                "context_window": 8000,
                "auto_compact_token_limit": null,
                "effective_context_window_percent": 95,
                "experimental_supported_tools": [],
            }]
        })
        .to_string()
    }

    fn response_for_request(body: &Value, state: &mut MockState) -> String {
        if has_user_marker(body, WARMUP_MARKER) {
            return response_body_with_items(vec![message_item("Warmup complete")], "resp-warmup");
        }
        match state.phase {
            MockPhase::Init => {
                if has_user_marker(body, TEST_MARKER) {
                    state.phase = MockPhase::WaitingCall;
                    return response_body_with_items(
                        vec![function_call_item(
                            &state.tool_name,
                            CALL_ID,
                            &state.tool_args,
                        )],
                        "resp-call-1",
                    );
                }
            }
            MockPhase::WaitingCall => {
                if has_function_call_output(body, CALL_ID) {
                    state.phase = MockPhase::CallDone;
                    return response_body_with_items(
                        vec![message_item("Tool call 1 completed")],
                        "resp-tool-1",
                    );
                }
            }
            MockPhase::CallDone => {}
        }
        response_body_with_items(vec![message_item("ready")], "resp-ready")
    }

    fn response_body_with_items(items: Vec<Value>, response_id: &str) -> String {
        let mut body = String::new();
        for item in items {
            let event = serde_json::json!({
                "type": "response.output_item.done",
                "item": item,
            });
            body.push_str(&format!("data: {event}\n\n"));
        }
        let completed = serde_json::json!({
            "type": "response.completed",
            "response": { "id": response_id },
        });
        body.push_str(&format!("data: {completed}\n\n"));
        body
    }

    fn function_call_item(tool_name: &str, call_id: &str, args: &str) -> Value {
        serde_json::json!({
            "type": "function_call",
            "name": tool_name,
            "arguments": args,
            "call_id": call_id,
        })
    }

    fn message_item(text: &str) -> Value {
        serde_json::json!({
            "type": "message",
            "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": text,
            }],
        })
    }

    fn has_user_marker(body: &Value, marker: &str) -> bool {
        let Some(items) = body.get("input").and_then(Value::as_array) else {
            return false;
        };
        let Some(item) = items.iter().rev().find(|item| {
            item.get("type").and_then(Value::as_str) == Some("message")
                && item.get("role").and_then(Value::as_str) == Some("user")
        }) else {
            return false;
        };
        item.get("content")
            .and_then(Value::as_array)
            .map(|content| {
                content.iter().any(|part| {
                    part.get("type").and_then(Value::as_str) == Some("input_text")
                        && part
                            .get("text")
                            .and_then(Value::as_str)
                            .map(|text| text.contains(marker))
                            .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    fn has_function_call_output(body: &Value, call_id: &str) -> bool {
        let Some(items) = body.get("input").and_then(Value::as_array) else {
            return false;
        };
        items.iter().any(|item| {
            item.get("type").and_then(Value::as_str) == Some("function_call_output")
                && item.get("call_id").and_then(Value::as_str) == Some(call_id)
        })
    }

    fn collect_function_call_outputs(requests: &[Value]) -> Vec<String> {
        let mut outputs = Vec::new();
        for request in requests {
            let Some(items) = request.get("input").and_then(Value::as_array) else {
                continue;
            };
            for item in items {
                if item.get("type").and_then(Value::as_str) != Some("function_call_output") {
                    continue;
                }
                if let Some(output) = item.get("output") {
                    if let Some(text) = output.as_str() {
                        outputs.push(text.to_string());
                    } else if let Some(content) = output.get("content").and_then(Value::as_str) {
                        outputs.push(content.to_string());
                    }
                }
            }
        }
        outputs
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::TestResult;

    #[tokio::test(flavor = "multi_thread")]
    async fn codex_tui_initial_sandbox_state() -> TestResult<()> {
        let steps = super::unix_impl::run_codex_tui_initial_sandbox_state().await?;
        if steps.is_empty() {
            return Ok(());
        }
        insta::assert_snapshot!(
            "codex_tui_initial_sandbox_state",
            super::unix_impl::render_steps(&steps)
        );
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::TestResult;

    #[tokio::test(flavor = "multi_thread")]
    async fn codex_tui_initial_sandbox_state() -> TestResult<()> {
        let steps = super::unix_impl::run_codex_tui_initial_sandbox_state().await?;
        if steps.is_empty() {
            return Ok(());
        }
        insta::assert_snapshot!(
            "codex_tui_initial_sandbox_state",
            super::unix_impl::render_steps(&steps)
        );
        Ok(())
    }
}

#[cfg(target_os = "windows")]
#[test]
fn codex_tui_initial_sandbox_state_windows_stub() -> TestResult<()> {
    eprintln!("codex TUI sandbox state test is not implemented on Windows; skipping");
    Ok(())
}
