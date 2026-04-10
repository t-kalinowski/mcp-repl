use std::io::{BufRead, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use crate::input_protocol::parse_input_frame_header;
use crate::ipc::{
    ServerToWorkerIpcMessage, connect_from_env, emit_backend_info, emit_request_end, set_global_ipc,
};
use crate::r_session::RSession;
use crate::worker_protocol::WORKER_MODE_ARG;

struct WorkerState {
    busy: AtomicBool,
    shutting_down: AtomicBool,
    stdin_wait: Mutex<()>,
    stdin_wait_cvar: Condvar,
}

impl WorkerState {
    fn try_mark_busy(&self) -> bool {
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    fn mark_idle(&self) {
        let _guard = self.stdin_wait.lock().unwrap();
        self.busy.store(false, Ordering::SeqCst);
        self.stdin_wait_cvar.notify_all();
    }

    fn begin_shutdown(&self) {
        let _guard = self.stdin_wait.lock().unwrap();
        self.shutting_down.store(true, Ordering::SeqCst);
        self.stdin_wait_cvar.notify_all();
    }

    fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    fn wait_until_stdin_read_allowed(&self) -> bool {
        let mut guard = self.stdin_wait.lock().unwrap();
        while self.busy.load(Ordering::SeqCst) && !self.is_shutting_down() {
            guard = self.stdin_wait_cvar.wait(guard).unwrap();
        }
        !self.is_shutting_down()
    }

    #[cfg(test)]
    fn wait_until_stdin_read_allowed_with_pre_wait_hook<F>(&self, mut before_wait: F) -> bool
    where
        F: FnMut(),
    {
        let mut guard = self.stdin_wait.lock().unwrap();
        let mut hook_ran = false;
        while self.busy.load(Ordering::SeqCst) && !self.is_shutting_down() {
            if !hook_ran {
                hook_ran = true;
                before_wait();
            }
            guard = self.stdin_wait_cvar.wait(guard).unwrap();
        }
        !self.is_shutting_down()
    }
}

impl Default for WorkerState {
    fn default() -> Self {
        Self {
            busy: AtomicBool::new(false),
            shutting_down: AtomicBool::new(false),
            stdin_wait: Mutex::new(()),
            stdin_wait_cvar: Condvar::new(),
        }
    }
}

struct QueuedRequest {
    text: String,
}

pub fn is_worker_mode() -> bool {
    let bare = std::ffi::OsStr::new(WORKER_MODE_ARG);
    let flag = std::ffi::OsString::from(format!("--{WORKER_MODE_ARG}"));
    std::env::args_os().any(|arg| arg == bare || arg == flag)
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    crate::diagnostics::startup_log("worker: run begin");
    let state = Arc::new(WorkerState::default());
    let (request_tx, request_rx) = mpsc::sync_channel(1);
    init_ipc(state.clone()).map_err(|err| {
        eprintln!("worker ipc init error: {err}");
        err
    })?;
    emit_backend_info("r", true);
    let request_state = state.clone();
    let _request_thread = thread::Builder::new()
        .name("worker-requests".to_string())
        .spawn(move || request_loop(request_rx, request_state))
        .map_err(|err| format!("failed to spawn worker request thread: {err}"))?;

    let stdin_state = state.clone();
    let stdin_requests = request_tx.clone();
    let _stdin_thread = thread::Builder::new()
        .name("worker-stdin".to_string())
        .spawn(move || {
            if let Err(err) = stdin_loop(stdin_state, stdin_requests) {
                eprintln!("worker stdin error: {err}");
            }
        })
        .map_err(|err| format!("failed to spawn worker stdin thread: {err}"))?;

    crate::diagnostics::startup_log("worker: starting R session");
    if let Err(err) = RSession::start_on_current_thread() {
        eprintln!("failed to start R session: {err}");
        return Err(std::io::Error::other(err).into());
    }
    crate::diagnostics::startup_log("worker: R session exited");

    Ok(())
}

fn wait_for_r_session() -> Result<&'static RSession, String> {
    loop {
        if let Ok(session) = RSession::global() {
            return Ok(session);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn init_ipc(state: Arc<WorkerState>) -> Result<(), Box<dyn std::error::Error>> {
    let conn = connect_from_env(Duration::from_secs(2))?;
    set_global_ipc(conn.clone());
    if let Err(err) = thread::Builder::new()
        .name("worker-ipc".to_string())
        .spawn(move || {
            loop {
                match conn.recv(None) {
                    Some(ServerToWorkerIpcMessage::StdinWrite { .. }) => {}
                    Some(ServerToWorkerIpcMessage::Interrupt) => {
                        let _ = crate::r_session::request_interrupt();
                        crate::r_session::clear_pending_input();
                    }
                    Some(ServerToWorkerIpcMessage::SessionEnd) => {
                        state.begin_shutdown();
                        let _ = crate::r_session::request_interrupt();
                        crate::r_session::clear_pending_input();
                        let _ = crate::r_session::request_shutdown();
                    }
                    None => {
                        // Without IPC, the worker cannot participate in turn accounting (prompt,
                        // request boundaries, etc). Exit immediately so the server can respawn.
                        std::process::exit(0);
                    }
                }
            }
        })
    {
        eprintln!("worker ipc thread error: {err}");
    }
    Ok(())
}

fn stdin_loop(
    state: Arc<WorkerState>,
    request_tx: mpsc::SyncSender<QueuedRequest>,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = std::io::stdin();
    let mut reader = std::io::BufReader::new(stdin);
    let mut line = String::new();
    loop {
        // On Windows, leaving another thread blocked on fd 0 during an active request can hang
        // embedded runtimes such as CPython when they probe stdin during initialization.
        if !state.wait_until_stdin_read_allowed() {
            break;
        }
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            state.begin_shutdown();
            if !crate::r_session::request_shutdown() {
                crate::ipc::emit_session_end();
                std::process::exit(0);
            }
            break;
        }

        // Once shutdown is requested, stop consuming stdin immediately.
        // Remaining bytes can stay unread because this worker is terminating.
        if state.is_shutting_down() {
            break;
        }

        if let Some(len) = parse_input_frame_header(&line) {
            let mut buffer = vec![0u8; len];
            reader.read_exact(&mut buffer)?;
            let text = String::from_utf8_lossy(&buffer).to_string();
            handle_write_stdin(text, state.clone(), &request_tx);
        } else {
            handle_write_stdin(line.clone(), state.clone(), &request_tx);
        }
    }

    Ok(())
}

fn request_loop(rx: mpsc::Receiver<QueuedRequest>, state: Arc<WorkerState>) {
    for request in rx {
        let result = write_stdin_request(request.text);
        if let Err(err) = result {
            emit_stderr_message(&err.message);
            emit_request_end();
        }
        state.mark_idle();
    }
}
fn handle_write_stdin(
    text: String,
    state: Arc<WorkerState>,
    request_tx: &mpsc::SyncSender<QueuedRequest>,
) {
    if state.is_shutting_down() {
        return;
    }

    if !state.try_mark_busy() {
        emit_stderr_message("worker is busy; request already running");
        return;
    }

    if let Err(err) = request_tx.try_send(QueuedRequest { text }) {
        state.mark_idle();
        let message = match err {
            mpsc::TrySendError::Full(_) => "worker is busy; request already running".to_string(),
            mpsc::TrySendError::Disconnected(_) => {
                "worker execution thread exited unexpectedly".to_string()
            }
        };
        emit_stderr_message(&message);
        emit_request_end();
    }
}

struct WorkerExecError {
    message: String,
}

impl WorkerExecError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

fn write_stdin_request(text: String) -> Result<(), WorkerExecError> {
    let session = wait_for_r_session()
        .map_err(|err| WorkerExecError::new(format!("failed to start R session: {err}")))?;

    let reply_rx = session.send_request(text).map_err(WorkerExecError::new)?;

    match reply_rx.recv() {
        Ok(_reply) => Ok(()),
        Err(err) => Err(WorkerExecError::new(format!(
            "R session reply error: {err}"
        ))),
    }
}

fn emit_stderr_message(message: &str) {
    crate::output_stream::write_stderr_bytes(message.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::time::Instant;

    #[test]
    fn stdin_wait_blocks_while_request_is_busy() {
        let state = Arc::new(WorkerState::default());
        assert!(
            state.try_mark_busy(),
            "expected first busy transition to succeed"
        );

        let entered_wait = Arc::new(AtomicBool::new(false));
        let wait_finished = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_entered_wait = Arc::clone(&entered_wait);
        let thread_wait_finished = Arc::clone(&wait_finished);
        let waiter = thread::spawn(move || {
            thread_entered_wait.store(true, Ordering::SeqCst);
            let allowed = thread_state.wait_until_stdin_read_allowed();
            thread_wait_finished.store(allowed, Ordering::SeqCst);
        });

        while !entered_wait.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(20));
        assert!(
            !wait_finished.load(Ordering::SeqCst),
            "stdin wait should stay blocked until the active request finishes"
        );

        state.mark_idle();
        waiter.join().expect("waiter thread should join");
        assert!(
            wait_finished.load(Ordering::SeqCst),
            "stdin wait should resume once the request becomes idle"
        );
    }

    #[test]
    fn stdin_wait_exits_when_shutdown_begins() {
        let state = Arc::new(WorkerState::default());
        assert!(
            state.try_mark_busy(),
            "expected first busy transition to succeed"
        );

        let thread_state = Arc::clone(&state);
        let waiter = thread::spawn(move || thread_state.wait_until_stdin_read_allowed());

        thread::sleep(Duration::from_millis(20));
        state.begin_shutdown();

        let allowed = waiter.join().expect("waiter thread should join");
        assert!(
            !allowed,
            "stdin wait should stop instead of blocking forever once shutdown begins"
        );
    }

    #[test]
    fn stdin_wait_does_not_miss_idle_notification_during_wait_handoff() {
        let state = Arc::new(WorkerState::default());
        assert!(
            state.try_mark_busy(),
            "expected first busy transition to succeed"
        );

        let (result_tx, result_rx) = mpsc::channel();
        let waiter_state = Arc::clone(&state);
        let notifier_state = Arc::clone(&state);
        let waiter = thread::spawn(move || {
            let allowed = waiter_state.wait_until_stdin_read_allowed_with_pre_wait_hook(|| {
                let notifier_state = Arc::clone(&notifier_state);
                let _notifier = thread::spawn(move || notifier_state.mark_idle());
                let deadline = Instant::now() + Duration::from_millis(50);
                while Instant::now() < deadline {
                    thread::yield_now();
                }
            });
            result_tx
                .send(allowed)
                .expect("wait result should be reported");
        });

        let timely_result = result_rx.recv_timeout(Duration::from_millis(200));
        if timely_result.is_err() {
            state.begin_shutdown();
        }
        let allowed = timely_result
            .or_else(|_| result_rx.recv_timeout(Duration::from_secs(1)))
            .expect("waiter should eventually unblock");
        waiter.join().expect("waiter thread should join");

        assert!(
            allowed,
            "stdin wait should resume promptly when idle is signaled during the wait handoff"
        );
    }
}
