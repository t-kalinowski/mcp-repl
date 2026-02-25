mod backend;
mod debug_repl;
mod diagnostics;
mod event_log;
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

use std::path::PathBuf;

use crate::backend::{Backend, backend_from_env};
use crate::sandbox::{INITIAL_SANDBOX_STATE_ENV, SandboxPolicy, SandboxStateUpdate};

const SANDBOX_STATE_INHERIT: &str = "inherit";

enum CliCommand {
    RunServer(CliOptions),
    Install(install::InstallOptions),
}

struct CliOptions {
    sandbox_state: Option<String>,
    debug_repl: bool,
    backend: Backend,
    debug_events_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SandboxModeArg {
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
}

impl SandboxModeArg {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "read-only" => Ok(Self::ReadOnly),
            "workspace-write" => Ok(Self::WorkspaceWrite),
            "danger-full-access" => Ok(Self::DangerFullAccess),
            _ => Err(format!(
                "invalid sandbox mode: {value} (expected read-only|workspace-write|danger-full-access)"
            )),
        }
    }
}

#[derive(Debug, Default)]
struct SandboxCliArgs {
    sandbox_state: Option<String>,
    mode: Option<SandboxModeArg>,
    network_access: Option<bool>,
    writable_roots: Vec<PathBuf>,
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
            event_log::initialize(
                options.debug_events_dir,
                event_log::StartupContext {
                    mode: if options.debug_repl {
                        "debug_repl".to_string()
                    } else {
                        "server".to_string()
                    },
                    backend: match options.backend {
                        Backend::R => "r".to_string(),
                        Backend::Python => "python".to_string(),
                    },
                    debug_repl: options.debug_repl,
                    sandbox_state: std::env::var(INITIAL_SANDBOX_STATE_ENV).ok(),
                },
            )?;
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
    if let Some(arg) = parser.peek()
        && arg == "install"
    {
        parser.next();
        return Ok(CliCommand::Install(parse_install_args(
            &mut parser,
            Vec::new(),
        )?));
    }

    let mut sandbox_args = SandboxCliArgs::default();
    let mut debug_repl = false;
    let mut debug_events_dir = None;
    let mut backend = backend_from_env()?;
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "--sandbox-state" => {
                let value = parser.next_value("--sandbox-state")?;
                sandbox_args.sandbox_state = Some(sandbox_state_arg(value)?);
            }
            _ if arg.starts_with("--sandbox-state=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --sandbox-state".into());
                }
                sandbox_args.sandbox_state = Some(sandbox_state_arg(value.to_string())?);
            }
            "--sandbox-mode" => {
                let value = parser.next_value("--sandbox-mode")?;
                sandbox_args.mode =
                    Some(SandboxModeArg::parse(&value).map_err(|err| err.to_string())?);
            }
            _ if arg.starts_with("--sandbox-mode=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --sandbox-mode".into());
                }
                sandbox_args.mode =
                    Some(SandboxModeArg::parse(value).map_err(|err| err.to_string())?);
            }
            "--sandbox-network-access" => {
                let value = parser.next_value("--sandbox-network-access")?;
                sandbox_args.network_access =
                    Some(parse_sandbox_network_access(&value).map_err(|err| err.to_string())?);
            }
            _ if arg.starts_with("--sandbox-network-access=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --sandbox-network-access".into());
                }
                sandbox_args.network_access =
                    Some(parse_sandbox_network_access(value).map_err(|err| err.to_string())?);
            }
            "--writable-root" => {
                let value = parser.next_value("--writable-root")?;
                sandbox_args
                    .writable_roots
                    .push(parse_writable_root(&value)?);
            }
            _ if arg.starts_with("--writable-root=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --writable-root".into());
                }
                sandbox_args
                    .writable_roots
                    .push(parse_writable_root(value)?);
            }
            "--debug-repl" => {
                debug_repl = true;
            }
            "--debug-events-dir" => {
                let value = parser.next_value("--debug-events-dir")?;
                if value.trim().is_empty() {
                    return Err("missing value for --debug-events-dir".into());
                }
                debug_events_dir = Some(PathBuf::from(value));
            }
            _ if arg.starts_with("--debug-events-dir=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.trim().is_empty() {
                    return Err("missing value for --debug-events-dir".into());
                }
                debug_events_dir = Some(PathBuf::from(value));
            }
            _ => match parse_backend_arg(&arg, &mut parser)? {
                Some(parsed_backend) => backend = Some(parsed_backend),
                None => return Err(format!("unknown argument: {arg}").into()),
            },
        }
    }

    let sandbox_state = sandbox_state_from_cli_args(sandbox_args)?;

    Ok(CliCommand::RunServer(CliOptions {
        sandbox_state,
        debug_repl,
        backend: backend.unwrap_or(Backend::R),
        debug_events_dir,
    }))
}

fn parse_backend_arg(
    arg: &str,
    parser: &mut ArgParser,
) -> Result<Option<Backend>, Box<dyn std::error::Error>> {
    if arg == "--interpreter" {
        let value = parser.next_value("--interpreter")?;
        return Ok(Some(Backend::parse(&value).map_err(|err| err.to_string())?));
    }
    if arg == "--backend" {
        let value = parser.next_value("--backend")?;
        return Ok(Some(Backend::parse(&value).map_err(|err| err.to_string())?));
    }
    if let Some(value) = arg.strip_prefix("--interpreter=") {
        if value.is_empty() {
            return Err("missing value for --interpreter".into());
        }
        return Ok(Some(Backend::parse(value).map_err(|err| err.to_string())?));
    }
    if let Some(value) = arg.strip_prefix("--backend=") {
        if value.is_empty() {
            return Err("missing value for --backend".into());
        }
        return Ok(Some(Backend::parse(value).map_err(|err| err.to_string())?));
    }
    Ok(None)
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
) -> Result<install::InstallOptions, Box<dyn std::error::Error>> {
    let mut server_name = install::DEFAULT_R_SERVER_NAME.to_string();
    let mut server_name_explicit = false;
    let mut command = None;
    let mut args = Vec::new();
    let mut interpreters: Vec<install::InstallInterpreter> = Vec::new();

    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_install_usage();
                std::process::exit(0);
            }
            "--interpreter" => {
                let value = parser.next_value("--interpreter")?;
                parse_install_interpreters_value(&value, &mut interpreters)?;
            }
            _ if arg.starts_with("--interpreter=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --interpreter".into());
                }
                parse_install_interpreters_value(value, &mut interpreters)?;
            }
            "--client" => {
                let value = parser.next_value("--client")?;
                parse_install_targets_value(&value, &mut targets)?;
            }
            _ if arg.starts_with("--client=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --client".into());
                }
                parse_install_targets_value(value, &mut targets)?;
            }
            "--server-name" => {
                server_name = parser.next_value("--server-name")?;
                server_name_explicit = true;
            }
            _ if arg.starts_with("--server-name=") => {
                let value = arg.split_once('=').map(|(_, value)| value).unwrap_or("");
                if value.is_empty() {
                    return Err("missing value for --server-name".into());
                }
                server_name = value.to_string();
                server_name_explicit = true;
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
                targets.push(
                    install::InstallTarget::parse(&arg)
                        .map_err(|err| -> Box<dyn std::error::Error> { err.into() })?,
                );
            }
        }
    }

    Ok(install::InstallOptions {
        targets,
        interpreters,
        server_name,
        server_name_explicit,
        command,
        args,
    })
}

fn parse_install_interpreters_value(
    raw: &str,
    interpreters: &mut Vec<install::InstallInterpreter>,
) -> Result<(), Box<dyn std::error::Error>> {
    for part in raw.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            return Err("empty --interpreter value (expected r|python)".into());
        }
        interpreters.push(
            install::InstallInterpreter::parse(trimmed)
                .map_err(|err| -> Box<dyn std::error::Error> { err.into() })?,
        );
    }
    Ok(())
}

fn parse_install_targets_value(
    raw: &str,
    targets: &mut Vec<install::InstallTarget>,
) -> Result<(), Box<dyn std::error::Error>> {
    for part in raw.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            return Err("empty --client value (expected codex|claude)".into());
        }
        targets.push(
            install::InstallTarget::parse(trimmed)
                .map_err(|err| -> Box<dyn std::error::Error> { err.into() })?,
        );
    }
    Ok(())
}

fn sandbox_state_arg(raw: String) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = raw.trim();
    if trimmed == SANDBOX_STATE_INHERIT {
        return Ok(SANDBOX_STATE_INHERIT.to_string());
    }
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
                "invalid --sandbox-state value: {trimmed} (expected inherit, JSON, or read-only|workspace-write|danger-full-access)"
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

fn parse_sandbox_network_access(raw: &str) -> Result<bool, String> {
    match raw {
        "enabled" => Ok(true),
        "restricted" => Ok(false),
        _ => Err(format!(
            "invalid --sandbox-network-access value: {raw} (expected enabled|restricted)"
        )),
    }
}

fn parse_writable_root(raw: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(
            format!("invalid --writable-root value: {raw} (expected absolute path)").into(),
        );
    }
    Ok(path)
}

fn sandbox_state_from_cli_args(
    args: SandboxCliArgs,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if args.sandbox_state.is_some()
        && (args.mode.is_some() || args.network_access.is_some() || !args.writable_roots.is_empty())
    {
        return Err(
            "cannot combine --sandbox-state with --sandbox-mode/--sandbox-network-access/--writable-root"
                .into(),
        );
    }
    if let Some(state) = args.sandbox_state {
        if state == SANDBOX_STATE_INHERIT {
            return Ok(None);
        }
        return Ok(Some(state));
    }
    if args.mode.is_none() && args.network_access.is_none() && args.writable_roots.is_empty() {
        return Ok(None);
    }

    let mode = args.mode.unwrap_or(SandboxModeArg::WorkspaceWrite);
    let policy = match mode {
        SandboxModeArg::ReadOnly => {
            if args.network_access.is_some() {
                return Err(
                    "--sandbox-network-access is only valid with --sandbox-mode workspace-write"
                        .into(),
                );
            }
            if !args.writable_roots.is_empty() {
                return Err(
                    "--writable-root is only valid with --sandbox-mode workspace-write".into(),
                );
            }
            SandboxPolicy::ReadOnly
        }
        SandboxModeArg::DangerFullAccess => {
            if args.network_access.is_some() {
                return Err(
                    "--sandbox-network-access is only valid with --sandbox-mode workspace-write"
                        .into(),
                );
            }
            if !args.writable_roots.is_empty() {
                return Err(
                    "--writable-root is only valid with --sandbox-mode workspace-write".into(),
                );
            }
            SandboxPolicy::DangerFullAccess
        }
        SandboxModeArg::WorkspaceWrite => SandboxPolicy::WorkspaceWrite {
            writable_roots: args.writable_roots,
            network_access: args.network_access.unwrap_or(false),
            exclude_tmpdir_env_var: false,
            exclude_slash_tmp: false,
        },
    };

    let update = SandboxStateUpdate {
        sandbox_policy: policy,
        sandbox_cwd: None,
        codex_linux_sandbox_exe: None,
    };
    Ok(Some(serde_json::to_string(&update)?))
}

fn print_usage() {
    println!(
        "Usage:\n\
mcp-repl [--debug-repl] [--interpreter <r|python>] [--sandbox-mode <mode>] [--sandbox-network-access <restricted|enabled>] [--writable-root <abs-path>]...\n\
mcp-repl install [codex] [claude] [--client <codex|claude>]... [--interpreter <r|python>[,r|python]...]... [--server-name <name>] [--command <path>] [--arg <value>]...\n\n\
--debug-repl: run an interactive debug REPL over stdio\n\
--debug-events-dir: optional directory for per-startup JSONL debug event logs (env: MCP_REPL_DEBUG_EVENTS_DIR)\n\
--interpreter: choose REPL interpreter (default: r; env MCP_REPL_INTERPRETER, compatibility env MCP_REPL_BACKEND)\n\
--backend: compatibility alias for --interpreter\n\
--sandbox-state: inherit | JSON | read-only | workspace-write | danger-full-access\n\
--sandbox-mode: read-only | workspace-write | danger-full-access (default: workspace-write when sandbox flags are provided)\n\
--sandbox-network-access: restricted | enabled (workspace-write only; default: restricted)\n\
--writable-root: additional absolute writable path (repeatable; workspace-write only)\n\
install: update MCP config for existing agent homes only (does not create ~/.codex or ~/.claude)\n\
install defaults to the full interpreter grid for each selected client (currently r_repl + py_repl)"
    );
}

fn print_install_usage() {
    println!(
        "Usage:\n\
mcp-repl install [codex] [claude] [--client <codex|claude>]... [--interpreter <r|python>[,r|python]...]... [--server-name <name>] [--command <path>] [--arg <value>]...\n\n\
If no target is specified for `install`, all existing agent homes are used:\n\
- codex: $CODEX_HOME or ~/.codex\n\
- claude: ~/.claude\n\
Missing homes are not created.\n\
If no --interpreter is specified, install uses the full interpreter grid for each selected client."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_backend_arg_accepts_interpreter_flag_forms() {
        let mut parser = ArgParser {
            args: vec!["python".to_string()],
            index: 0,
        };
        let parsed = parse_backend_arg("--interpreter", &mut parser).expect("parse flag");
        assert_eq!(parsed, Some(Backend::Python));

        let mut parser = ArgParser {
            args: Vec::new(),
            index: 0,
        };
        let parsed = parse_backend_arg("--interpreter=python", &mut parser).expect("parse flag");
        assert_eq!(parsed, Some(Backend::Python));
    }

    #[test]
    fn parse_backend_arg_accepts_backend_compatibility_forms() {
        let mut parser = ArgParser {
            args: vec!["python".to_string()],
            index: 0,
        };
        let parsed = parse_backend_arg("--backend", &mut parser).expect("parse flag");
        assert_eq!(parsed, Some(Backend::Python));

        let mut parser = ArgParser {
            args: Vec::new(),
            index: 0,
        };
        let parsed = parse_backend_arg("--backend=python", &mut parser).expect("parse flag");
        assert_eq!(parsed, Some(Backend::Python));
    }

    #[test]
    fn parse_sandbox_network_access_accepts_expected_values() {
        assert_eq!(parse_sandbox_network_access("enabled"), Ok(true));
        assert_eq!(parse_sandbox_network_access("restricted"), Ok(false));
    }

    #[test]
    fn parse_install_args_defaults_server_name_to_r_repl() {
        let mut parser = ArgParser {
            args: Vec::new(),
            index: 0,
        };
        let parsed = parse_install_args(&mut parser, Vec::new()).expect("parse install args");
        assert_eq!(parsed.server_name, install::DEFAULT_R_SERVER_NAME);
        assert!(!parsed.server_name_explicit);
        assert!(parsed.interpreters.is_empty());
    }

    #[test]
    fn parse_install_args_accepts_repeatable_interpreters() {
        let mut parser = ArgParser {
            args: vec![
                "--interpreter".to_string(),
                "r".to_string(),
                "--interpreter".to_string(),
                "python".to_string(),
            ],
            index: 0,
        };
        let parsed = parse_install_args(&mut parser, Vec::new()).expect("parse install args");
        assert_eq!(
            parsed.interpreters,
            vec![
                install::InstallInterpreter::R,
                install::InstallInterpreter::Python
            ]
        );
    }

    #[test]
    fn parse_install_args_accepts_comma_separated_interpreters() {
        let mut parser = ArgParser {
            args: vec!["--interpreter=python,r".to_string()],
            index: 0,
        };
        let parsed = parse_install_args(&mut parser, Vec::new()).expect("parse install args");
        assert_eq!(
            parsed.interpreters,
            vec![
                install::InstallInterpreter::Python,
                install::InstallInterpreter::R
            ]
        );
    }

    #[test]
    fn parse_install_args_accepts_client_flag() {
        let mut parser = ArgParser {
            args: vec!["--client".to_string(), "codex,claude".to_string()],
            index: 0,
        };
        let parsed = parse_install_args(&mut parser, Vec::new()).expect("parse install args");
        assert_eq!(
            parsed.targets,
            vec![
                install::InstallTarget::Codex,
                install::InstallTarget::Claude
            ]
        );
    }

    #[test]
    fn parse_install_interpreters_value_rejects_empty_values() {
        let mut interpreters = Vec::new();
        let err = parse_install_interpreters_value("", &mut interpreters).expect_err("empty value");
        assert!(
            err.to_string().contains("empty --interpreter value"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_install_targets_value_rejects_empty_values() {
        let mut targets = Vec::new();
        let err = parse_install_targets_value(",", &mut targets).expect_err("empty value");
        assert!(
            err.to_string().contains("empty --client value"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sandbox_state_arg_accepts_inherit() {
        let parsed = sandbox_state_arg("inherit".to_string()).expect("sandbox state");
        assert_eq!(parsed, "inherit");
    }

    #[test]
    fn sandbox_state_arg_accepts_inherit() {
        let parsed = sandbox_state_arg("inherit".to_string()).expect("sandbox state");
        assert_eq!(parsed, "inherit");
    }

    #[test]
    fn sandbox_state_from_cli_args_workspace_write_defaults_restricted() {
        let state = sandbox_state_from_cli_args(SandboxCliArgs {
            mode: Some(SandboxModeArg::WorkspaceWrite),
            network_access: None,
            writable_roots: vec![PathBuf::from("/tmp/one"), PathBuf::from("/tmp/two")],
            ..Default::default()
        })
        .expect("sandbox state")
        .expect("sandbox payload");

        let parsed: SandboxStateUpdate = serde_json::from_str(&state).expect("parse payload");
        match parsed.sandbox_policy {
            SandboxPolicy::WorkspaceWrite {
                writable_roots,
                network_access,
                ..
            } => {
                assert_eq!(
                    writable_roots,
                    vec![PathBuf::from("/tmp/one"), PathBuf::from("/tmp/two")]
                );
                assert!(!network_access);
            }
            other => panic!("expected workspace-write policy, got {other:?}"),
        }
    }

    #[test]
    fn sandbox_state_from_cli_args_inherit_returns_none() {
        let parsed = sandbox_state_from_cli_args(SandboxCliArgs {
            sandbox_state: Some("inherit".to_string()),
            ..Default::default()
        })
        .expect("sandbox state");
        assert!(parsed.is_none());
    }

    #[test]
    fn sandbox_state_from_cli_args_rejects_mixed_sandbox_state_flags() {
        let err = sandbox_state_from_cli_args(SandboxCliArgs {
            sandbox_state: Some("read-only".to_string()),
            mode: Some(SandboxModeArg::ReadOnly),
            ..Default::default()
        })
        .expect_err("expected conflict");
        assert!(
            err.to_string().contains("cannot combine --sandbox-state"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sandbox_state_from_cli_args_rejects_writable_roots_without_workspace_write() {
        let err = sandbox_state_from_cli_args(SandboxCliArgs {
            mode: Some(SandboxModeArg::ReadOnly),
            writable_roots: vec![PathBuf::from("/tmp/one")],
            ..Default::default()
        })
        .expect_err("expected root rejection");
        assert!(
            err.to_string().contains("--writable-root is only valid"),
            "unexpected error: {err}"
        );
    }
}
