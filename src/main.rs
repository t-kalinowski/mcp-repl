mod backend;
mod debug_repl;
mod diagnostics;
mod html_to_markdown;
mod input_protocol;
mod install;
mod ipc;
mod output_capture;
mod output_stream;
mod pager;
mod r_controls;
mod r_graphics;
mod r_htmd;
mod r_session;
mod sandbox;
mod server;
#[cfg(target_os = "windows")]
mod windows_sandbox;
mod worker;
mod worker_process;
mod worker_protocol;

use crate::backend::{Backend, backend_from_env};
use crate::sandbox::{INITIAL_SANDBOX_STATE_ENV, SandboxPolicy, SandboxStateUpdate};

enum CliCommand {
    RunServer(CliOptions),
    Install(install::InstallOptions),
}

struct CliOptions {
    sandbox_state: Option<String>,
    debug_repl: bool,
    backend: Backend,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_family = "unix")]
    // The worker and server may still write output to stdout/stderr. If a downstream reader
    // disconnects and closes its read end, future writes can raise SIGPIPE and terminate the
    // process on Unix. Ignore SIGPIPE so we surface broken-pipe errors normally instead of
    // crashing.
    ignore_sigpipe();
    crate::diagnostics::startup_log("main: entry");
    #[cfg(target_os = "linux")]
    if sandbox::invoked_as_codex_linux_sandbox() {
        sandbox::run_linux_sandbox_main();
    }
    #[cfg(target_os = "windows")]
    if sandbox::invoked_as_codex_windows_sandbox() {
        sandbox::run_windows_sandbox_main();
    }

    if worker::is_worker_mode() {
        crate::diagnostics::startup_log("main: worker mode");
        return worker::run();
    }

    match parse_cli_args()? {
        CliCommand::RunServer(options) => {
            if let Some(state) = options.sandbox_state {
                // `std::env::set_var` is `unsafe` in Rust 2024 because mutating process-global
                // environment variables can violate assumptions in other threads / libraries.
                unsafe {
                    std::env::set_var(INITIAL_SANDBOX_STATE_ENV, state);
                }
            }
            if options.debug_repl {
                crate::diagnostics::startup_log("main: debug repl mode");
                return debug_repl::run(options.backend);
            }
            crate::diagnostics::startup_log("main: server mode");
            server::run(options.backend).await
        }
        CliCommand::Install(options) => install::run(options),
    }
}

#[cfg(target_family = "unix")]
fn ignore_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

fn parse_cli_args() -> Result<CliCommand, Box<dyn std::error::Error>> {
    let mut parser = ArgParser::new();
    if let Some(arg) = parser.peek() {
        match arg {
            "install" => {
                parser.next();
                return Ok(CliCommand::Install(parse_install_args(
                    &mut parser,
                    Vec::new(),
                    true,
                )?));
            }
            "install-codex" => {
                parser.next();
                return Ok(CliCommand::Install(parse_install_args(
                    &mut parser,
                    vec![install::InstallTarget::Codex],
                    false,
                )?));
            }
            "install-claude" => {
                parser.next();
                return Ok(CliCommand::Install(parse_install_args(
                    &mut parser,
                    vec![install::InstallTarget::Claude],
                    false,
                )?));
            }
            _ => {}
        }
    }

    let mut sandbox_state = None;
    let mut debug_repl = false;
    let mut backend = backend_from_env()?;
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "--sandbox-state" => {
                let value = parser.next_value("--sandbox-state")?;
                sandbox_state = Some(sandbox_state_arg(value)?);
            }
            _ if arg.starts_with("--sandbox-state=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --sandbox-state".into());
                }
                sandbox_state = Some(sandbox_state_arg(value.to_string())?);
            }
            "--backend" => {
                let value = parser.next_value("--backend")?;
                backend = Some(Backend::parse(&value).map_err(|err| err.to_string())?);
            }
            _ if arg.starts_with("--backend=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --backend".into());
                }
                backend = Some(Backend::parse(value).map_err(|err| err.to_string())?);
            }
            "--debug-repl" => {
                debug_repl = true;
            }
            _ => {
                return Err(format!("unknown argument: {arg}").into());
            }
        }
    }

    Ok(CliCommand::RunServer(CliOptions {
        sandbox_state,
        debug_repl,
        backend: backend.unwrap_or(Backend::R),
    }))
}

struct ArgParser {
    args: Vec<String>,
    index: usize,
}

impl ArgParser {
    fn new() -> Self {
        Self {
            args: std::env::args().skip(1).collect(),
            index: 0,
        }
    }

    fn next(&mut self) -> Option<String> {
        let value = self.args.get(self.index)?.clone();
        self.index += 1;
        Some(value)
    }

    fn peek(&self) -> Option<&str> {
        self.args.get(self.index).map(String::as_str)
    }

    fn next_value(&mut self, flag: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.next()
            .ok_or_else(|| format!("missing value for {flag}").into())
    }
}

fn parse_install_args(
    parser: &mut ArgParser,
    mut targets: Vec<install::InstallTarget>,
    allow_positional_targets: bool,
) -> Result<install::InstallOptions, Box<dyn std::error::Error>> {
    let mut server_name = "mcp-console".to_string();
    let mut command = None;
    let mut args = Vec::new();

    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_install_usage();
                std::process::exit(0);
            }
            "--server-name" => {
                server_name = parser.next_value("--server-name")?;
            }
            _ if arg.starts_with("--server-name=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --server-name".into());
                }
                server_name = value.to_string();
            }
            "--command" => {
                command = Some(parser.next_value("--command")?);
            }
            _ if arg.starts_with("--command=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --command".into());
                }
                command = Some(value.to_string());
            }
            "--arg" => {
                args.push(parser.next_value("--arg")?);
            }
            _ if arg.starts_with("--arg=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --arg".into());
                }
                args.push(value.to_string());
            }
            _ => {
                if let Some(flag) = arg.strip_prefix('-') {
                    return Err(format!("unknown install option: -{flag}").into());
                }
                if !allow_positional_targets {
                    return Err(format!("unexpected install argument: {arg}").into());
                }
                targets.push(
                    install::InstallTarget::parse(&arg)
                        .map_err(|err| -> Box<dyn std::error::Error> { err.into() })?,
                );
            }
        }
    }

    Ok(install::InstallOptions {
        targets,
        server_name,
        command,
        args,
    })
}

fn sandbox_state_arg(raw: String) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        let parsed: SandboxStateUpdate = serde_json::from_str(trimmed)?;
        let payload = serde_json::to_string(&parsed)?;
        return Ok(payload);
    }

    let policy = match trimmed {
        "read-only" => SandboxPolicy::ReadOnly,
        "workspace-write" => SandboxPolicy::WorkspaceWrite {
            writable_roots: Vec::new(),
            network_access: false,
            exclude_tmpdir_env_var: false,
            exclude_slash_tmp: false,
        },
        "danger-full-access" => SandboxPolicy::DangerFullAccess,
        _ => {
            return Err(format!(
                "invalid --sandbox-state value: {trimmed} (expected JSON or read-only|workspace-write|danger-full-access)"
            )
            .into());
        }
    };

    let update = SandboxStateUpdate {
        sandbox_policy: policy,
        sandbox_cwd: None,
        codex_linux_sandbox_exe: None,
    };
    let payload = serde_json::to_string(&update)?;
    Ok(payload)
}

fn print_usage() {
    println!(
        "Usage:\n\
mcp-console [--debug-repl] [--backend <r|python>] [--sandbox-state <json|mode>]\n\
mcp-console install [codex] [claude] [--server-name <name>] [--command <path>] [--arg <value>]...\n\
mcp-console install-codex [--server-name <name>] [--command <path>] [--arg <value>]...\n\
mcp-console install-claude [--server-name <name>] [--command <path>] [--arg <value>]...\n\n\
--debug-repl: run an interactive debug REPL over stdio\n\
--backend: choose REPL backend (default: r; env MCP_CONSOLE_BACKEND)\n\
--sandbox-state: JSON-encoded SandboxStateUpdate or one of\n\
                read-only | workspace-write | danger-full-access\n\
install: update MCP config for existing agent homes only (does not create ~/.codex or ~/.claude)"
    );
}

fn print_install_usage() {
    println!(
        "Usage:\n\
mcp-console install [codex] [claude] [--server-name <name>] [--command <path>] [--arg <value>]...\n\
mcp-console install-codex [--server-name <name>] [--command <path>] [--arg <value>]...\n\
mcp-console install-claude [--server-name <name>] [--command <path>] [--arg <value>]...\n\n\
If no target is specified for `install`, all existing agent homes are used:\n\
- codex: $CODEX_HOME or ~/.codex\n\
- claude: ~/.claude\n\
Missing homes are not created."
    );
}
