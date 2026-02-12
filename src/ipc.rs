use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
#[cfg(target_family = "unix")]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const IPC_READ_FD_ENV: &str = "MCP_CONSOLE_IPC_READ_FD";
pub const IPC_WRITE_FD_ENV: &str = "MCP_CONSOLE_IPC_WRITE_FD";
const MAX_PROMPT_HISTORY: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerToWorkerIpcMessage {
    StdinWrite { text: String },
    Interrupt,
    SessionEnd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerToServerIpcMessage {
    BackendInfo {
        language: String,
        #[serde(default)]
        supports_images: bool,
    },
    ReadlineStart {
        prompt: String,
    },
    ReadlineResult {
        prompt: String,
        line: String,
    },
    PlotImage {
        id: String,
        mime_type: String,
        data: String,
        is_new: bool,
    },
    RequestEnd,
    SessionEnd,
}

#[derive(Default)]
struct ServerIpcInbox {
    queue: VecDeque<WorkerToServerIpcMessage>,
    last_prompt: Option<String>,
    prompt_history: VecDeque<String>,
    echo_events: VecDeque<IpcEchoEvent>,
    session_end: bool,
    disconnected: bool,
}

#[derive(Default)]
struct WorkerIpcInbox {
    queue: VecDeque<ServerToWorkerIpcMessage>,
    disconnected: bool,
}

#[derive(Debug, Clone)]
pub struct IpcEchoEvent {
    pub prompt: String,
    pub line: String,
}

#[derive(Clone)]
pub struct IpcPlotImage {
    pub id: String,
    pub mime_type: String,
    pub data: String,
    pub is_new: bool,
}

#[derive(Default, Clone)]
pub struct IpcHandlers {
    pub on_plot_image: Option<Arc<dyn Fn(IpcPlotImage) + Send + Sync>>,
}

#[derive(Clone)]
pub struct ServerIpcConnection {
    sender: mpsc::Sender<ServerToWorkerIpcMessage>,
    inbox: Arc<Mutex<ServerIpcInbox>>,
    cvar: Arc<Condvar>,
}

#[derive(Clone)]
pub struct WorkerIpcConnection {
    sender: mpsc::Sender<WorkerToServerIpcMessage>,
    inbox: Arc<Mutex<WorkerIpcInbox>>,
    cvar: Arc<Condvar>,
}

#[derive(Clone, Default)]
pub struct IpcHandle {
    inner: Arc<Mutex<Option<ServerIpcConnection>>>,
}

impl IpcHandle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, conn: ServerIpcConnection) {
        let mut guard = self.inner.lock().unwrap();
        *guard = Some(conn);
    }

    pub fn get(&self) -> Option<ServerIpcConnection> {
        let guard = self.inner.lock().unwrap();
        guard.clone()
    }
}

impl ServerIpcConnection {
    fn new(transport: IpcTransport, handlers: IpcHandlers) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let inbox = Arc::new(Mutex::new(ServerIpcInbox::default()));
        let cvar = Arc::new(Condvar::new());

        let reader_inbox = inbox.clone();
        let reader_cvar = cvar.clone();
        let plot_handler = handlers.on_plot_image.clone();
        let IpcTransport { reader, writer } = transport;
        thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        let mut guard = reader_inbox.lock().unwrap();
                        guard.disconnected = true;
                        reader_cvar.notify_all();
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        let mut guard = reader_inbox.lock().unwrap();
                        guard.disconnected = true;
                        reader_cvar.notify_all();
                        break;
                    }
                }
                let trimmed = line.trim_end_matches(['\n', '\r']);
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(message) = serde_json::from_str::<WorkerToServerIpcMessage>(trimmed) {
                    match message {
                        WorkerToServerIpcMessage::ReadlineStart { prompt } => {
                            let mut guard = reader_inbox.lock().unwrap();
                            if guard
                                .prompt_history
                                .back()
                                .is_none_or(|last| last != &prompt)
                            {
                                guard.prompt_history.push_back(prompt.clone());
                                if guard.prompt_history.len() > MAX_PROMPT_HISTORY {
                                    guard.prompt_history.pop_front();
                                }
                            }
                            guard.last_prompt = Some(prompt);
                            reader_cvar.notify_all();
                        }
                        WorkerToServerIpcMessage::ReadlineResult { prompt, line } => {
                            let mut guard = reader_inbox.lock().unwrap();
                            guard.echo_events.push_back(IpcEchoEvent { prompt, line });
                            reader_cvar.notify_all();
                        }
                        WorkerToServerIpcMessage::SessionEnd => {
                            let mut guard = reader_inbox.lock().unwrap();
                            guard.session_end = true;
                            guard.queue.push_back(WorkerToServerIpcMessage::SessionEnd);
                            reader_cvar.notify_all();
                        }
                        WorkerToServerIpcMessage::PlotImage {
                            id,
                            mime_type,
                            data,
                            is_new,
                        } => {
                            if let Some(handler) = plot_handler.as_ref() {
                                handler(IpcPlotImage {
                                    id,
                                    mime_type,
                                    data,
                                    is_new,
                                });
                            } else {
                                let mut guard = reader_inbox.lock().unwrap();
                                guard.queue.push_back(WorkerToServerIpcMessage::PlotImage {
                                    id,
                                    mime_type,
                                    data,
                                    is_new,
                                });
                                reader_cvar.notify_all();
                            }
                        }
                        other => {
                            let mut guard = reader_inbox.lock().unwrap();
                            guard.queue.push_back(other);
                            reader_cvar.notify_all();
                        }
                    }
                }
            }
        });

        spawn_writer(rx, writer);

        Ok(Self {
            sender: tx,
            inbox,
            cvar,
        })
    }

    pub fn send(
        &self,
        message: ServerToWorkerIpcMessage,
    ) -> Result<(), mpsc::SendError<ServerToWorkerIpcMessage>> {
        self.sender.send(message)
    }

    pub fn clear_prompt_history(&self) {
        let mut guard = self.inbox.lock().unwrap();
        guard.prompt_history.clear();
    }

    pub fn clear_echo_events(&self) {
        let mut guard = self.inbox.lock().unwrap();
        guard.echo_events.clear();
    }

    pub fn clear_request_end_events(&self) {
        let mut guard = self.inbox.lock().unwrap();
        guard
            .queue
            .retain(|msg| !matches!(msg, WorkerToServerIpcMessage::RequestEnd));
    }

    pub fn take_prompt_history(&self) -> Vec<String> {
        let mut guard = self.inbox.lock().unwrap();
        guard.prompt_history.drain(..).collect()
    }

    pub fn take_echo_events(&self) -> Vec<IpcEchoEvent> {
        let mut guard = self.inbox.lock().unwrap();
        guard.echo_events.drain(..).collect()
    }

    pub fn wait_for_request_end(&self, timeout: Duration) -> Result<(), IpcWaitError> {
        let deadline = Instant::now() + timeout;
        let mut guard = self.inbox.lock().unwrap();
        loop {
            if take_request_end(&mut guard) {
                if take_session_end(&mut guard) {
                    return Err(IpcWaitError::SessionEnd);
                }
                return Ok(());
            }
            if take_session_end(&mut guard) {
                return Err(IpcWaitError::SessionEnd);
            }
            if guard.disconnected {
                return Err(IpcWaitError::Disconnected);
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(IpcWaitError::Timeout);
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_guard, timeout_res) = self.cvar.wait_timeout(guard, remaining).unwrap();
            guard = next_guard;
            if timeout_res.timed_out() {
                return Err(IpcWaitError::Timeout);
            }
        }
    }

    pub fn wait_for_prompt(&self, timeout: Duration) -> Result<String, IpcWaitError> {
        let deadline = Instant::now() + timeout;
        let mut guard = self.inbox.lock().unwrap();
        loop {
            if take_session_end(&mut guard) {
                return Err(IpcWaitError::SessionEnd);
            }
            if guard.disconnected {
                return Err(IpcWaitError::Disconnected);
            }
            if let Some(prompt) = guard.last_prompt.take() {
                return Ok(prompt);
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(IpcWaitError::Timeout);
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_guard, timeout_res) = self.cvar.wait_timeout(guard, remaining).unwrap();
            guard = next_guard;
            if timeout_res.timed_out() {
                return Err(IpcWaitError::Timeout);
            }
        }
    }

    pub fn try_take_prompt(&self) -> Option<String> {
        let mut guard = self.inbox.lock().unwrap();
        guard.last_prompt.take()
    }

    pub fn wait_for_backend_info(
        &self,
        timeout: Duration,
    ) -> Result<WorkerToServerIpcMessage, IpcWaitError> {
        let deadline = Instant::now() + timeout;
        let mut guard = self.inbox.lock().unwrap();
        loop {
            if let Some(info) = take_backend_info(&mut guard) {
                let _ = take_session_end(&mut guard);
                return Ok(info);
            }
            if take_session_end(&mut guard) {
                return Err(IpcWaitError::SessionEnd);
            }
            if guard.disconnected {
                return Err(IpcWaitError::Disconnected);
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(IpcWaitError::Timeout);
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_guard, timeout_res) = self.cvar.wait_timeout(guard, remaining).unwrap();
            guard = next_guard;
            if timeout_res.timed_out() {
                return Err(IpcWaitError::Timeout);
            }
        }
    }

    pub fn try_take_request_end(&self) -> bool {
        let mut guard = self.inbox.lock().unwrap();
        take_request_end(&mut guard)
    }
}

impl WorkerIpcConnection {
    fn new(transport: IpcTransport) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let inbox = Arc::new(Mutex::new(WorkerIpcInbox::default()));
        let cvar = Arc::new(Condvar::new());

        let reader_inbox = inbox.clone();
        let reader_cvar = cvar.clone();
        let IpcTransport { reader, writer } = transport;
        thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        let mut guard = reader_inbox.lock().unwrap();
                        guard.disconnected = true;
                        reader_cvar.notify_all();
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        let mut guard = reader_inbox.lock().unwrap();
                        guard.disconnected = true;
                        reader_cvar.notify_all();
                        break;
                    }
                }
                let trimmed = line.trim_end_matches(['\n', '\r']);
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(message) = serde_json::from_str::<ServerToWorkerIpcMessage>(trimmed) {
                    let mut guard = reader_inbox.lock().unwrap();
                    guard.queue.push_back(message);
                    reader_cvar.notify_all();
                }
            }
        });

        spawn_writer(rx, writer);

        Ok(Self {
            sender: tx,
            inbox,
            cvar,
        })
    }

    pub fn send(
        &self,
        message: WorkerToServerIpcMessage,
    ) -> Result<(), mpsc::SendError<WorkerToServerIpcMessage>> {
        self.sender.send(message)
    }

    pub fn recv(&self, timeout: Option<Duration>) -> Option<ServerToWorkerIpcMessage> {
        let mut guard = self.inbox.lock().unwrap();
        if let Some(message) = guard.queue.pop_front() {
            return Some(message);
        }
        if guard.disconnected {
            return None;
        }

        match timeout {
            None => loop {
                guard = self.cvar.wait(guard).unwrap();
                if let Some(message) = guard.queue.pop_front() {
                    return Some(message);
                }
                if guard.disconnected {
                    return None;
                }
            },
            Some(timeout) => {
                let deadline = Instant::now() + timeout;
                loop {
                    let now = Instant::now();
                    if now >= deadline {
                        return None;
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    let (next_guard, timeout_res) =
                        self.cvar.wait_timeout(guard, remaining).unwrap();
                    guard = next_guard;
                    if let Some(message) = guard.queue.pop_front() {
                        return Some(message);
                    }
                    if guard.disconnected {
                        return None;
                    }
                    if timeout_res.timed_out() {
                        return None;
                    }
                }
            }
        }
    }
}

fn spawn_writer<T>(rx: mpsc::Receiver<T>, mut writer: Box<dyn Write + Send>)
where
    T: Serialize + Send + 'static,
{
    thread::spawn(move || {
        for message in rx {
            if let Ok(payload) = serde_json::to_string(&message) {
                if writer.write_all(payload.as_bytes()).is_err() {
                    break;
                }
                if writer.write_all(b"\n").is_err() {
                    break;
                }
                let _ = writer.flush();
            }
        }
    });
}

#[derive(Debug)]
pub enum IpcWaitError {
    Timeout,
    SessionEnd,
    Disconnected,
}

pub struct IpcServer {
    #[cfg(target_family = "unix")]
    server_read: Option<std::io::PipeReader>,
    #[cfg(target_family = "unix")]
    server_write: Option<std::io::PipeWriter>,
    #[cfg(target_family = "unix")]
    child_fds: Option<IpcChildFds>,
}

#[cfg(target_family = "unix")]
pub(crate) struct IpcChildFds {
    pub(crate) read_fd: RawFd,
    pub(crate) write_fd: RawFd,
}

impl IpcServer {
    pub fn bind() -> io::Result<Self> {
        #[cfg(target_family = "unix")]
        {
            let (server_read, server_write, child_read, child_write) = create_pipe_pair()?;
            Ok(Self {
                server_read: Some(server_read),
                server_write: Some(server_write),
                child_fds: Some(IpcChildFds {
                    read_fd: child_read,
                    write_fd: child_write,
                }),
            })
        }
        #[cfg(not(target_family = "unix"))]
        {
            // Windows does not support passing anonymous pipe handles to a child
            // process using stable stdlib APIs. We avoid fallbacks (like TCP)
            // because network is typically disabled in the sandbox.
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPC sideband requires Unix-style pipe handle inheritance; not supported on Windows",
            ))
        }
    }

    #[cfg(target_family = "unix")]
    pub fn connect(self, handle: IpcHandle, handlers: IpcHandlers) -> io::Result<()> {
        let Some(server_read) = self.server_read else {
            return Err(io::Error::other("missing ipc read pipe"));
        };
        let Some(server_write) = self.server_write else {
            return Err(io::Error::other("missing ipc write pipe"));
        };
        let conn = ServerIpcConnection::new(
            IpcTransport {
                reader: Box::new(server_read),
                writer: Box::new(server_write),
            },
            handlers,
        )?;
        handle.set(conn);
        crate::diagnostics::startup_log("ipc: connected");
        Ok(())
    }

    #[cfg(target_family = "unix")]
    pub fn take_child_fds(&mut self) -> Option<IpcChildFds> {
        self.child_fds.take()
    }
}

struct IpcTransport {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
}

#[cfg(target_family = "unix")]
fn set_cloexec(fd: RawFd, enabled: bool) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let new_flags = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, new_flags) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_family = "unix")]
fn create_pipe_pair() -> io::Result<(std::io::PipeReader, std::io::PipeWriter, RawFd, RawFd)> {
    let (server_read, child_write) = std::io::pipe()?;
    let (child_read, server_write) = std::io::pipe()?;

    let child_read_fd = child_read.into_raw_fd();
    let child_write_fd = child_write.into_raw_fd();

    set_cloexec(child_read_fd, false)?;
    set_cloexec(child_write_fd, false)?;
    set_cloexec(server_read.as_raw_fd(), true)?;
    set_cloexec(server_write.as_raw_fd(), true)?;

    Ok((server_read, server_write, child_read_fd, child_write_fd))
}

pub fn connect_from_env(_timeout: Duration) -> io::Result<WorkerIpcConnection> {
    #[cfg(target_family = "unix")]
    {
        let read_fd = std::env::var(IPC_READ_FD_ENV)
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "IPC read fd missing"))?;
        let write_fd = std::env::var(IPC_WRITE_FD_ENV)
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "IPC write fd missing"))?;
        let read_fd: RawFd = read_fd
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPC read fd"))?;
        let write_fd: RawFd = write_fd
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPC write fd"))?;
        set_cloexec(read_fd, true)?;
        set_cloexec(write_fd, true)?;
        let reader = unsafe { File::from_raw_fd(read_fd) };
        let writer = unsafe { File::from_raw_fd(write_fd) };
        WorkerIpcConnection::new(IpcTransport {
            reader: Box::new(reader),
            writer: Box::new(writer),
        })
    }
    #[cfg(not(target_family = "unix"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPC sideband requires Unix-style pipe handle inheritance; not supported on Windows",
        ))
    }
}

static IPC_GLOBAL: OnceLock<WorkerIpcConnection> = OnceLock::new();

pub fn set_global_ipc(conn: WorkerIpcConnection) {
    let _ = IPC_GLOBAL.set(conn);
}

pub fn global_ipc() -> Option<&'static WorkerIpcConnection> {
    IPC_GLOBAL.get()
}

pub fn emit_readline_start(prompt: &str) {
    if let Some(ipc) = global_ipc() {
        let _ = ipc.send(WorkerToServerIpcMessage::ReadlineStart {
            prompt: prompt.to_string(),
        });
    }
}

pub fn emit_readline_result(prompt: &str, line: &str) {
    if let Some(ipc) = global_ipc() {
        let _ = ipc.send(WorkerToServerIpcMessage::ReadlineResult {
            prompt: prompt.to_string(),
            line: line.to_string(),
        });
    }
}

pub fn emit_plot_image(id: &str, mime_type: &str, data: &str, is_new: bool) {
    if let Some(ipc) = global_ipc() {
        let _ = ipc.send(WorkerToServerIpcMessage::PlotImage {
            id: id.to_string(),
            mime_type: mime_type.to_string(),
            data: data.to_string(),
            is_new,
        });
    }
}

pub fn emit_backend_info(language: &str, supports_images: bool) {
    if let Some(ipc) = global_ipc() {
        let _ = ipc.send(WorkerToServerIpcMessage::BackendInfo {
            language: language.to_string(),
            supports_images,
        });
    }
}

pub fn emit_request_end() {
    if let Some(ipc) = global_ipc() {
        let _ = ipc.send(WorkerToServerIpcMessage::RequestEnd);
    }
}

pub fn emit_session_end() {
    if let Some(ipc) = global_ipc() {
        let _ = ipc.send(WorkerToServerIpcMessage::SessionEnd);
    }
}

fn take_session_end(guard: &mut ServerIpcInbox) -> bool {
    if !guard.session_end {
        return false;
    }
    guard.session_end = false;
    if let Some(idx) = guard
        .queue
        .iter()
        .position(|msg| matches!(msg, WorkerToServerIpcMessage::SessionEnd))
    {
        guard.queue.remove(idx);
    }
    true
}

fn take_request_end(guard: &mut ServerIpcInbox) -> bool {
    let idx = guard
        .queue
        .iter()
        .position(|msg| matches!(msg, WorkerToServerIpcMessage::RequestEnd));
    let Some(idx) = idx else {
        return false;
    };
    guard.queue.remove(idx);
    true
}

fn take_backend_info(guard: &mut ServerIpcInbox) -> Option<WorkerToServerIpcMessage> {
    let idx = guard
        .queue
        .iter()
        .position(|msg| matches!(msg, WorkerToServerIpcMessage::BackendInfo { .. }))?;
    guard.queue.remove(idx)
}
