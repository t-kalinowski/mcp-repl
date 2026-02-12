use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::hash::{Hash, Hasher};
use std::os::raw::{c_char, c_int, c_uchar};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::thread;

use crate::ipc;
#[cfg(target_family = "unix")]
use crate::sandbox::R_SESSION_TMPDIR_ENV;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use harp::command::{r_command, r_home_setup};
use harp::exec::{RFunction, RFunctionExt};
use harp::library::RLibraries;

#[cfg(target_family = "unix")]
use libr::{
    R_Consolefile, R_Outputfile, ptr_R_Busy, ptr_R_ReadConsole, ptr_R_ShowMessage, ptr_R_Suicide,
    ptr_R_WriteConsole, ptr_R_WriteConsoleEx,
};
#[cfg(target_family = "windows")]
use libr::{
    R_DefParamsEx, R_SetParams, R_common_command_line, Rboolean_FALSE, Rstart, UImode_RGui,
    cmdlineoptions, get_R_HOME, getRUser, readconsolecfg,
};
#[cfg(target_family = "windows")]
use std::mem::MaybeUninit;

const MCP_CONSOLE_R_SCRIPT: &str = include_str!("../r/mcp_console.R");

#[derive(Debug)]
pub struct SessionReply;

pub struct RSession {
    sender: mpsc::Sender<RRequest>,
    init: Arc<SessionInit>,
}

impl RSession {
    pub fn global() -> Result<&'static RSession, String> {
        SESSION
            .get()
            .ok_or_else(|| "R session not initialized".to_string())
    }

    pub fn start_on_current_thread() -> Result<(), String> {
        let (request_tx, request_rx) = mpsc::channel();
        let init = Arc::new(SessionInit::new());
        let session = RSession {
            sender: request_tx,
            init: init.clone(),
        };
        let session_set = SESSION.set(session);
        if session_set.is_err() {
            return Err("R session already initialized".to_string());
        }
        run_session_on_current_thread(request_rx, init)
    }

    pub fn wait_until_ready(&self) -> Result<(), String> {
        self.init.wait_ready()
    }

    pub fn send_request(&self, input: String) -> Result<mpsc::Receiver<SessionReply>, String> {
        self.wait_until_ready()?;
        let (reply_tx, reply_rx) = mpsc::channel();
        let request = RRequest {
            input,
            reply: reply_tx,
        };
        self.sender
            .send(request)
            .map_err(|_| "R session is unavailable".to_string())?;
        Ok(reply_rx)
    }
}

struct RRequest {
    input: String,
    reply: mpsc::Sender<SessionReply>,
}

#[derive(Debug)]
enum InitState {
    Pending,
    Ready,
    Failed(String),
}

#[derive(Debug)]
struct SessionInit {
    state: Mutex<InitState>,
    cvar: Condvar,
}

impl SessionInit {
    fn new() -> Self {
        Self {
            state: Mutex::new(InitState::Pending),
            cvar: Condvar::new(),
        }
    }

    fn mark_ready(&self) {
        let mut guard = self.state.lock().unwrap();
        *guard = InitState::Ready;
        self.cvar.notify_all();
    }

    fn mark_failed(&self, message: String) {
        let mut guard = self.state.lock().unwrap();
        *guard = InitState::Failed(message);
        self.cvar.notify_all();
    }

    fn wait_ready(&self) -> Result<(), String> {
        let mut guard = self.state.lock().unwrap();
        loop {
            match &*guard {
                InitState::Pending => {
                    guard = self.cvar.wait(guard).unwrap();
                }
                InitState::Ready => return Ok(()),
                InitState::Failed(message) => return Err(message.clone()),
            }
        }
    }
}

pub fn request_shutdown() -> bool {
    let Some(state) = SESSION_STATE.get() else {
        return false;
    };
    let mut guard = state.inner.lock().unwrap();
    guard.shutdown = true;
    state.cvar.notify_all();
    true
}

pub(crate) fn clear_pending_input() -> bool {
    let Some(state) = SESSION_STATE.get() else {
        return false;
    };
    let mut guard = state.inner.lock().unwrap();
    let had_pending = !guard.input_queue.is_empty();
    guard.input_queue.clear();
    had_pending
}

fn run_session_on_current_thread(
    requests: mpsc::Receiver<RRequest>,
    init: Arc<SessionInit>,
) -> Result<(), String> {
    crate::diagnostics::startup_log("r-session: init begin");
    let state = Arc::new(SessionState::new());
    if SESSION_STATE.set(state.clone()).is_err() {
        let message = "R session state already initialized".to_string();
        init.mark_failed(message.clone());
        return Err(message);
    }

    let init_start = std::time::Instant::now();
    let init_result = initialize_r();
    if let Err(err) = init_result {
        init.mark_failed(err.clone());
        return Err(err);
    }
    crate::diagnostics::startup_log(format!(
        "r-session: init complete ({} ms)",
        crate::diagnostics::elapsed_ms(init_start.elapsed())
    ));

    init.mark_ready();

    let request_state = state.clone();
    thread::Builder::new()
        .name("r-session-requests".to_string())
        .spawn(move || handle_requests(requests, request_state))
        .expect("failed to spawn request handler thread");

    unsafe {
        libr::run_Rmainloop();
    }

    Ok(())
}

struct SessionState {
    inner: Mutex<SessionStateInner>,
    cvar: Condvar,
}

struct SessionStateInner {
    input_queue: VecDeque<String>,
    active_request: Option<ActiveRequest>,
    shutdown: bool,
    session_end_emitted: bool,
}

struct ActiveRequest {
    reply: mpsc::Sender<SessionReply>,
    plot_hashes: HashMap<String, u64>,
}

impl SessionState {
    fn new() -> Self {
        Self {
            inner: Mutex::new(SessionStateInner {
                input_queue: VecDeque::new(),
                active_request: None,
                shutdown: false,
                session_end_emitted: false,
            }),
            cvar: Condvar::new(),
        }
    }
}

fn handle_requests(requests: mpsc::Receiver<RRequest>, state: Arc<SessionState>) {
    for request in requests {
        let mut guard = state.inner.lock().unwrap();
        while guard.active_request.is_some() {
            guard = state.cvar.wait(guard).unwrap();
        }
        let is_eof = is_eof_input(&request.input);
        guard.active_request = Some(ActiveRequest {
            reply: request.reply,
            plot_hashes: HashMap::new(),
        });
        if is_eof {
            guard.shutdown = true;
        } else {
            queue_input(&mut guard.input_queue, &request.input);
        }
        state.cvar.notify_all();
    }

    let mut guard = state.inner.lock().unwrap();
    guard.shutdown = true;
    state.cvar.notify_all();
}

fn initialize_r() -> Result<(), String> {
    let start = std::time::Instant::now();
    let r_home = r_home_setup().map_err(|err| format!("failed to set up R_HOME: {err}"))?;
    crate::diagnostics::startup_log(format!(
        "r-session: r_home_setup {} ms",
        crate::diagnostics::elapsed_ms(start.elapsed())
    ));
    configure_r_env_vars(&r_home);
    #[cfg(target_family = "unix")]
    configure_r_tempdir();

    let libs_start = std::time::Instant::now();
    let libraries = RLibraries::from_r_home_path(&r_home);
    libraries.initialize_pre_setup_r();
    crate::diagnostics::startup_log(format!(
        "r-session: libraries pre-setup {} ms",
        crate::diagnostics::elapsed_ms(libs_start.elapsed())
    ));

    // Mirror the default R startup as closely as possible: delegate to R's
    // own initialization logic (Rf_initialize_R + command-line parsing) and
    // avoid disabling user/site startup files.
    //
    // We keep the console quiet and interactive, and preserve the existing
    // behavior of not restoring/saving the workspace automatically.
    let args = vec![
        "--quiet".to_string(),
        "--interactive".to_string(),
        "--no-restore".to_string(),
        "--no-save".to_string(),
    ];
    let setup_start = std::time::Instant::now();
    setup_r(&args)?;
    crate::diagnostics::startup_log(format!(
        "r-session: setup_r {} ms",
        crate::diagnostics::elapsed_ms(setup_start.elapsed())
    ));

    let post_start = std::time::Instant::now();
    libraries.initialize_post_setup_r();
    crate::diagnostics::startup_log(format!(
        "r-session: libraries post-setup {} ms",
        crate::diagnostics::elapsed_ms(post_start.elapsed())
    ));

    unsafe {
        harp::CONSOLE_THREAD_ID = Some(thread::current().id());
        harp::routines::r_register_routines();
    }
    harp::initialize();
    let help_start = std::time::Instant::now();
    configure_r_help_output()?;
    crate::diagnostics::startup_log(format!(
        "r-session: help output setup {} ms",
        crate::diagnostics::elapsed_ms(help_start.elapsed())
    ));

    crate::diagnostics::startup_log(format!(
        "r-session: initialize_r total {} ms",
        crate::diagnostics::elapsed_ms(start.elapsed())
    ));
    Ok(())
}

fn configure_r_help_output() -> Result<(), String> {
    eval_in_global_env(MCP_CONSOLE_R_SCRIPT)
}

fn eval_in_global_env(code: &str) -> Result<(), String> {
    let mut parse = RFunction::from("parse");
    parse.param("text", code);
    let exprs = parse
        .call()
        .map_err(|err| format!("failed to parse R startup code: {err}"))?;

    let mut globalenv_fn = RFunction::from("globalenv");
    let globalenv = globalenv_fn
        .call()
        .map_err(|err| format!("failed to resolve globalenv(): {err}"))?;

    let mut eval = RFunction::from("eval");
    eval.add(exprs);
    eval.param("envir", globalenv);
    eval.call()
        .map_err(|err| format!("failed to eval R startup code: {err}"))?;
    Ok(())
}

fn configure_r_env_vars(r_home: &Path) {
    unsafe {
        std::env::set_var("R_DISABLE_HTTPD", "1");
    }

    let share = r_home.join("share");
    let include = r_home.join("include");
    let doc = r_home.join("doc");

    let ok = share.try_exists().unwrap_or(false)
        && include.try_exists().unwrap_or(false)
        && doc.try_exists().unwrap_or(false);

    if ok {
        unsafe {
            std::env::set_var("R_SHARE_DIR", share);
            std::env::set_var("R_INCLUDE_DIR", include);
            std::env::set_var("R_DOC_DIR", doc);
        }
        return;
    }

    // Fallback for non-standard R layouts.
    let result = r_command(|command| {
        command
            .stdin(std::process::Stdio::null())
            .arg("--vanilla")
            .arg("--slave")
            .arg("-e")
            .arg(r#"cat(paste(R.home("share"), R.home("include"), R.home("doc"), sep=";"))"#);
    });

    if let Ok(output) = result
        && let Ok(vars) = String::from_utf8(output.stdout)
    {
        let vars: Vec<&str> = vars.trim().split(';').collect();
        if vars.len() == 3 {
            unsafe {
                std::env::set_var("R_SHARE_DIR", vars[0]);
                std::env::set_var("R_INCLUDE_DIR", vars[1]);
                std::env::set_var("R_DOC_DIR", vars[2]);
            }
        } else {
            eprintln!("Unexpected output for R env vars");
        }
    } else {
        eprintln!("Failed to discover R env vars");
    }
}

#[cfg(target_family = "unix")]
fn configure_r_tempdir() {
    let Some(tmpdir) = std::env::var_os(R_SESSION_TMPDIR_ENV) else {
        return;
    };
    if tmpdir.is_empty() {
        return;
    }
    let path = PathBuf::from(&tmpdir);
    if !path.is_absolute() {
        eprintln!(
            "Ignoring non-absolute R session temp dir: {}",
            path.to_string_lossy()
        );
        return;
    }
    if path.as_path() == std::path::Path::new("/") {
        eprintln!("Refusing to use '/' as R session temp dir");
        return;
    }

    unsafe {
        std::env::set_var("TMPDIR", &tmpdir);
    }
}

#[cfg(target_family = "unix")]
fn setup_r(args: &[String]) -> Result<(), String> {
    unsafe {
        let (owned_args, mut c_args) = build_c_args_owned(args);
        let _ = R_MAIN_ARGS.set(owned_args);
        libr::Rf_initialize_R(c_args.len() as i32, c_args.as_mut_ptr());

        libr::set(libr::R_Interactive, 1);
        libr::set(R_Consolefile, std::ptr::null_mut());
        libr::set(R_Outputfile, std::ptr::null_mut());

        libr::set(ptr_R_WriteConsole, None);
        libr::set(ptr_R_WriteConsoleEx, Some(r_write_console));
        libr::set(ptr_R_ReadConsole, Some(r_read_console));
        libr::set(ptr_R_ShowMessage, Some(r_show_message));
        libr::set(ptr_R_Busy, Some(r_busy));
        libr::set(ptr_R_Suicide, Some(r_suicide));

        libr::setup_Rmainloop();
    }

    Ok(())
}

#[cfg(target_family = "windows")]
fn setup_r(args: &[String]) -> Result<(), String> {
    unsafe {
        libr::set(libr::R_SignalHandlers, 1);

        let r_home = get_r_home();
        let r_home = CString::new(r_home).map_err(|err| err.to_string())?;
        let r_home = r_home.as_ptr() as *mut c_char;

        let user_home = get_user_home();
        let user_home = CString::new(user_home).map_err(|err| err.to_string())?;
        let user_home = user_home.as_ptr() as *mut c_char;

        let (_tmp_owned, mut c_args) = build_c_args_owned(&[]);
        cmdlineoptions(c_args.len() as i32, c_args.as_mut_ptr());

        let mut params_struct = MaybeUninit::uninit();
        let params: Rstart = params_struct.as_mut_ptr();

        R_DefParamsEx(params, 0);

        let (owned_args, mut c_args) = build_c_args_owned(args);
        let _ = R_MAIN_ARGS.set(owned_args);
        let mut c_args_len = c_args.len() as c_int;
        R_common_command_line(
            &mut c_args_len,
            c_args.as_mut_ptr() as *mut *mut c_char,
            params,
        );

        (*params).R_Interactive = 1;
        (*params).CharacterMode = UImode_RGui;
        // Keep startup behavior aligned with R defaults. R_common_command_line
        // already adjusts these based on the provided command-line arguments.
        (*params).set_NoRenviron(Rboolean_FALSE);

        (*params).WriteConsole = None;
        (*params).WriteConsoleEx = Some(r_write_console);
        (*params).ReadConsole = Some(r_read_console);
        (*params).ShowMessage = Some(r_show_message);
        (*params).YesNoCancel = Some(r_yes_no_cancel);
        (*params).Busy = Some(r_busy);
        (*params).Suicide = Some(r_suicide);
        (*params).CallBack = Some(r_callback);

        (*params).rhome = r_home;
        (*params).home = user_home;

        R_SetParams(params);
        libr::graphapp::GA_initapp(0, std::ptr::null_mut());
        readconsolecfg();
        libr::setup_Rmainloop();
    }

    Ok(())
}

fn build_c_args_owned(args: &[String]) -> (Vec<CString>, Vec<*mut c_char>) {
    let mut owned = Vec::with_capacity(args.len() + 1);
    owned.push(CString::new("mcp-console").expect("argv[0] must not contain NUL"));
    for arg in args {
        owned.push(CString::new(arg.as_str()).expect("argv must not contain NUL"));
    }
    let ptrs = owned
        .iter()
        .map(|arg| arg.as_ptr() as *mut c_char)
        .collect();
    (owned, ptrs)
}

static SESSION_STATE: OnceLock<Arc<SessionState>> = OnceLock::new();
static SESSION: OnceLock<RSession> = OnceLock::new();
static R_MAIN_ARGS: OnceLock<Vec<CString>> = OnceLock::new();

fn session_state() -> &'static Arc<SessionState> {
    SESSION_STATE
        .get()
        .expect("R session state was not initialized")
}

fn queue_input(queue: &mut VecDeque<String>, input: &str) {
    if input.is_empty() {
        return;
    }
    let normalized = input.replace("\r\n", "\n");
    let mut lines: Vec<String> = normalized
        .split_inclusive('\n')
        .map(str::to_string)
        .collect();
    if !normalized.ends_with('\n') {
        if let Some(last) = lines.last_mut() {
            last.push('\n');
        } else {
            lines.push("\n".to_string());
        }
    }
    queue.extend(lines);
}

fn is_eof_input(input: &str) -> bool {
    let trimmed = input.trim_matches(|ch| ch == '\n' || ch == '\r');
    let mut saw_eot = false;
    for ch in trimmed.chars() {
        match ch {
            '\u{4}' => saw_eot = true,
            _ => return false,
        }
    }
    saw_eot
}

fn write_stdout_bytes(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    crate::output_stream::write_stdout_bytes(bytes);
}

fn write_stderr_bytes(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    crate::output_stream::write_stderr_bytes(bytes);
}

fn complete_active_request(
    state: &Arc<SessionState>,
    active: Option<ActiveRequest>,
    emit_session_end: bool,
) {
    if let Some(active) = active {
        let _ = active.reply.send(SessionReply);
        state.cvar.notify_all();
    }
    if emit_session_end {
        ipc::emit_session_end();
    }
}

#[unsafe(no_mangle)]
pub extern "C-unwind" fn r_write_console(buf: *const c_char, buflen: c_int, otype: c_int) {
    if buf.is_null() || buflen <= 0 {
        return;
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf as *const u8, buflen as usize) };
    if otype == 0 {
        write_stdout_bytes(bytes);
    } else {
        write_stderr_bytes(bytes);
    }
}

#[unsafe(no_mangle)]
pub extern "C-unwind" fn r_show_message(buf: *const c_char) {
    if buf.is_null() {
        return;
    }
    let message = unsafe { CStr::from_ptr(buf) }.to_string_lossy();
    write_stderr_bytes(message.as_bytes());
    write_stderr_bytes(b"\n");
}

#[unsafe(no_mangle)]
pub extern "C-unwind" fn r_busy(_which: c_int) {}

#[unsafe(no_mangle)]
pub extern "C-unwind" fn r_suicide(buf: *const c_char) {
    let message = if buf.is_null() {
        "R requested shutdown."
    } else {
        unsafe { CStr::from_ptr(buf) }
            .to_str()
            .unwrap_or("R requested shutdown.")
    };
    let state = session_state();
    let mut guard = state.inner.lock().unwrap();
    let should_emit = !guard.session_end_emitted;
    guard.session_end_emitted = true;
    let active = guard.active_request.take();
    drop(guard);
    complete_active_request(state, active, should_emit);
    panic!("{message}");
}

#[unsafe(no_mangle)]
pub extern "C-unwind" fn r_read_console(
    prompt: *const c_char,
    buf: *mut c_uchar,
    buflen: c_int,
    _add_history: c_int,
) -> c_int {
    if buflen <= 0 {
        return 0;
    }
    let prompt_text = if prompt.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(prompt) }
                .to_string_lossy()
                .to_string(),
        )
    };
    ipc::emit_readline_start(prompt_text.as_deref().unwrap_or(""));
    let is_save_prompt = prompt_text
        .as_deref()
        .map(|text| text.to_ascii_lowercase().contains("save workspace image"))
        .unwrap_or(false);
    let state = session_state();

    loop {
        let mut guard = state.inner.lock().unwrap();

        if is_save_prompt {
            let active = guard.active_request.take();
            let should_emit = guard.shutdown && !guard.session_end_emitted;
            if guard.shutdown {
                guard.session_end_emitted = true;
            }
            drop(guard);
            complete_active_request(state, active, should_emit);
            if !buf.is_null() {
                let response = b"n\n";
                let max = (buflen as usize).saturating_sub(1);
                if max > 0 {
                    let bytes = if response.len() > max {
                        &response[..max]
                    } else {
                        response
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
                        *buf.add(bytes.len()) = 0;
                    }
                    return 1;
                }
            }
            return 0;
        }

        if guard.shutdown {
            let should_emit = !guard.session_end_emitted;
            guard.session_end_emitted = true;
            let active = guard.active_request.take();
            drop(guard);
            complete_active_request(state, active, should_emit);
            if !buf.is_null() {
                unsafe { *buf = 0 };
            }
            return 0;
        }

        if let Some(line) = guard.input_queue.pop_front() {
            let mut bytes = line.into_bytes();
            if bytes.is_empty() || *bytes.last().unwrap() != b'\n' {
                bytes.push(b'\n');
            }

            let max = (buflen as usize).saturating_sub(1);
            let (head, tail) = if bytes.len() > max {
                bytes.split_at(max)
            } else {
                (bytes.as_slice(), &[][..])
            };

            if !tail.is_empty() {
                let remainder = String::from_utf8_lossy(tail).to_string();
                guard.input_queue.push_front(remainder);
            }
            drop(guard);

            let prompt = prompt_text.as_deref().unwrap_or("");
            let line_text = String::from_utf8_lossy(head).to_string();
            let mut echoed = String::with_capacity(prompt.len() + line_text.len());
            echoed.push_str(prompt);
            echoed.push_str(&line_text);
            ipc::emit_readline_result(prompt, &line_text);
            if !echoed.is_empty() {
                write_stdout_bytes(echoed.as_bytes());
            }

            if !buf.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(head.as_ptr(), buf, head.len());
                    *buf.add(head.len()) = 0;
                }
            }

            return 1;
        }

        if let Some(active) = guard.active_request.take() {
            drop(guard);
            complete_active_request(state, Some(active), false);
            continue;
        }

        guard = state.cvar.wait(guard).unwrap();
    }
}

pub(crate) fn push_plot_image(
    plot_id: String,
    bytes: Vec<u8>,
    mime_type: String,
    is_new: bool,
) -> Result<(), String> {
    let state = session_state();
    let mut guard = state
        .inner
        .lock()
        .map_err(|_| "session state lock poisoned".to_string())?;
    let Some(active) = guard.active_request.as_mut() else {
        return Ok(());
    };

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    let hash = hasher.finish();

    if active.plot_hashes.get(&plot_id) == Some(&hash) {
        return Ok(());
    }

    active.plot_hashes.insert(plot_id.clone(), hash);
    let mime_type = if mime_type.trim().is_empty() {
        "image/png".to_string()
    } else {
        mime_type
    };
    let data = STANDARD.encode(bytes);
    ipc::emit_plot_image(&plot_id, &mime_type, &data, is_new);

    Ok(())
}

#[cfg(target_family = "windows")]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn r_yes_no_cancel(_question: *const c_char) -> c_int {
    0
}

#[cfg(target_family = "windows")]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn r_callback() {}

#[cfg(target_family = "windows")]
fn get_r_home() -> String {
    let r_path = unsafe { get_R_HOME() };
    if r_path.is_null() {
        panic!("get_R_HOME failed to report an R home.");
    }
    unsafe { CStr::from_ptr(r_path) }
        .to_string_lossy()
        .to_string()
}

#[cfg(target_family = "windows")]
fn get_user_home() -> String {
    let r_path = unsafe { getRUser() };
    if r_path.is_null() {
        panic!("getRUser failed to report a user home directory.");
    }
    unsafe { CStr::from_ptr(r_path) }
        .to_string_lossy()
        .to_string()
}
