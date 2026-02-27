mod common;

use std::path::PathBuf;
use std::process::Command;

use common::TestResult;
use serde_json::Value as JsonValue;
use toml_edit::DocumentMut;

fn resolve_exe() -> TestResult<PathBuf> {
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

#[test]
fn install_codex_target_defaults_to_r_and_python_servers() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let codex_home = temp.path().join("codex-home");
    std::fs::create_dir_all(&codex_home)?;
    let exe = resolve_exe()?;

    let status = Command::new(exe)
        .arg("install")
        .arg("--client")
        .arg("codex")
        .arg("--command")
        .arg("/usr/local/bin/mcp-repl")
        .env("CODEX_HOME", &codex_home)
        .status()?;
    assert!(
        status.success(),
        "install --client codex failed with status {status}"
    );

    let config_path = codex_home.join("config.toml");
    let text = std::fs::read_to_string(config_path)?;
    let doc = text.parse::<DocumentMut>()?;

    assert!(
        doc["mcp_servers"]["r_repl"].is_table(),
        "expected mcp_servers.r_repl table"
    );
    assert!(
        doc["mcp_servers"]["py_repl"].is_table(),
        "expected mcp_servers.py_repl table"
    );

    let r_args = doc["mcp_servers"]["r_repl"]["args"]
        .as_array()
        .expect("expected r_repl args array");
    let has_sandbox_inherit = r_args
        .iter()
        .zip(r_args.iter().skip(1))
        .any(|(a, b)| a.as_str() == Some("--sandbox") && b.as_str() == Some("inherit"));
    assert!(
        has_sandbox_inherit,
        "expected r_repl args to include `--sandbox inherit`"
    );

    let py_args = doc["mcp_servers"]["py_repl"]["args"]
        .as_array()
        .expect("expected py_repl args array");
    let has_interpreter_python = py_args.iter().zip(py_args.iter().skip(1)).any(|(a, b)| {
        (a.as_str() == Some("--interpreter") || a.as_str() == Some("--backend"))
            && b.as_str() == Some("python")
    });
    assert!(
        has_interpreter_python,
        "expected py_repl args to include python interpreter selection"
    );
    let py_has_sandbox_inherit = py_args
        .iter()
        .zip(py_args.iter().skip(1))
        .any(|(a, b)| a.as_str() == Some("--sandbox") && b.as_str() == Some("inherit"));
    assert!(
        py_has_sandbox_inherit,
        "expected py_repl args to include `--sandbox inherit`"
    );

    Ok(())
}

#[test]
fn install_claude_target_defaults_to_r_and_python_servers() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let claude_home = temp.path().join(".claude");
    std::fs::create_dir_all(&claude_home)?;
    let exe = resolve_exe()?;

    let status = Command::new(exe)
        .arg("install")
        .arg("--client")
        .arg("claude")
        .arg("--command")
        .arg("/usr/local/bin/mcp-repl")
        .env("HOME", temp.path())
        .status()?;
    assert!(
        status.success(),
        "install --client claude failed with status {status}"
    );

    let config_path = claude_home.join("settings.json");
    let text = std::fs::read_to_string(config_path)?;
    let root: JsonValue = serde_json::from_str(&text)?;
    let servers = root["mcpServers"]
        .as_object()
        .expect("expected mcpServers object");
    assert!(servers.contains_key("r_repl"), "expected r_repl server");
    assert!(servers.contains_key("py_repl"), "expected py_repl server");

    let r_args = root["mcpServers"]["r_repl"]["args"]
        .as_array()
        .expect("expected r_repl args array");
    let r_has_workspace_write = r_args
        .iter()
        .zip(r_args.iter().skip(1))
        .any(|(a, b)| a.as_str() == Some("--sandbox") && b.as_str() == Some("workspace-write"));
    assert!(
        r_has_workspace_write,
        "expected r_repl args to include `--sandbox workspace-write`"
    );

    let py_args = root["mcpServers"]["py_repl"]["args"]
        .as_array()
        .expect("expected py_repl args array");
    let py_has_workspace_write = py_args
        .iter()
        .zip(py_args.iter().skip(1))
        .any(|(a, b)| a.as_str() == Some("--sandbox") && b.as_str() == Some("workspace-write"));
    assert!(
        py_has_workspace_write,
        "expected py_repl args to include `--sandbox workspace-write`"
    );
    let py_has_interpreter_python = py_args.iter().zip(py_args.iter().skip(1)).any(|(a, b)| {
        (a.as_str() == Some("--interpreter") || a.as_str() == Some("--backend"))
            && b.as_str() == Some("python")
    });
    assert!(
        py_has_interpreter_python,
        "expected py_repl args to include python interpreter selection"
    );

    Ok(())
}

#[test]
fn install_codex_and_install_claude_commands_are_rejected() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let codex_home = temp.path().join("codex-home");
    let claude_home = temp.path().join(".claude");
    std::fs::create_dir_all(&codex_home)?;
    std::fs::create_dir_all(&claude_home)?;
    let exe = resolve_exe()?;

    for cmd in ["install-codex", "install-claude"] {
        let status = Command::new(&exe)
            .arg(cmd)
            .arg("--command")
            .arg("/usr/local/bin/mcp-repl")
            .env("CODEX_HOME", &codex_home)
            .env("HOME", temp.path())
            .status()?;
        assert!(
            !status.success(),
            "expected `{cmd}` to be rejected, got status {status}"
        );
    }

    Ok(())
}

#[test]
fn install_rejects_empty_client_selector() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let codex_home = temp.path().join("codex-home");
    let claude_home = temp.path().join(".claude");
    std::fs::create_dir_all(&codex_home)?;
    std::fs::create_dir_all(&claude_home)?;
    let exe = resolve_exe()?;

    let status = Command::new(&exe)
        .arg("install")
        .arg("--client")
        .arg(",")
        .arg("--command")
        .arg("/usr/local/bin/mcp-repl")
        .env("CODEX_HOME", &codex_home)
        .env("HOME", temp.path())
        .status()?;

    assert!(
        !status.success(),
        "expected install with empty --client selector to fail"
    );

    Ok(())
}

#[test]
fn install_subcommands_are_rejected() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let codex_home = temp.path().join("codex-home");
    std::fs::create_dir_all(&codex_home)?;
    let exe = resolve_exe()?;

    let codex_status = Command::new(&exe)
        .arg("install-codex")
        .arg("--command")
        .arg("/usr/local/bin/mcp-repl")
        .env("CODEX_HOME", &codex_home)
        .status()?;
    assert!(
        !codex_status.success(),
        "install-codex should fail after subcommand removal"
    );

    let claude_home = temp.path().join(".claude");
    std::fs::create_dir_all(&claude_home)?;
    let claude_status = Command::new(exe)
        .arg("install-claude")
        .arg("--command")
        .arg("/usr/local/bin/mcp-repl")
        .env("HOME", temp.path())
        .status()?;
    assert!(
        !claude_status.success(),
        "install-claude should fail after subcommand removal"
    );

    Ok(())
}
