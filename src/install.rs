use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map as JsonMap, Value as JsonValue};
use toml_edit::{Array, DocumentMut, Item, Table, value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstallTarget {
    Codex,
    Claude,
}

impl InstallTarget {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "codex" => Ok(Self::Codex),
            "claude" => Ok(Self::Claude),
            _ => Err(format!(
                "invalid install target: {raw} (expected codex|claude)"
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub targets: Vec<InstallTarget>,
    pub server_name: String,
    pub command: Option<String>,
    pub args: Vec<String>,
}

pub fn run(options: InstallOptions) -> Result<(), Box<dyn std::error::Error>> {
    let command = options.command.unwrap_or_else(default_command);
    let targets = resolve_target_roots(&options.targets)?;

    for (target, root) in targets {
        match target {
            InstallTarget::Codex => {
                let path = root.join("config.toml");
                upsert_codex_mcp_server(&path, &options.server_name, &command, &options.args)?;
                println!("Updated codex MCP config: {}", path.display());
            }
            InstallTarget::Claude => {
                let path = resolve_claude_config_path(&root);
                upsert_claude_mcp_server(&path, &options.server_name, &command, &options.args)?;
                println!("Updated claude MCP config: {}", path.display());
            }
        }
    }

    Ok(())
}

fn default_command() -> String {
    env::current_exe()
        .ok()
        .and_then(|path| path.into_os_string().into_string().ok())
        .unwrap_or_else(|| "mcp-console".to_string())
}

fn resolve_target_roots(
    requested: &[InstallTarget],
) -> Result<Vec<(InstallTarget, PathBuf)>, Box<dyn std::error::Error>> {
    let mut targets: BTreeSet<InstallTarget> = BTreeSet::new();
    if requested.is_empty() {
        let codex_root = default_codex_home()?;
        if codex_root.is_dir() {
            targets.insert(InstallTarget::Codex);
        }
        let claude_root = default_claude_home()?;
        if claude_root.is_dir() {
            targets.insert(InstallTarget::Claude);
        }
        if targets.is_empty() {
            return Err(
                "no existing agent home found (expected ~/.codex and/or ~/.claude; not creating new directories)"
                    .into(),
            );
        }
    } else {
        targets.extend(requested.iter().copied());
    }

    let mut resolved = Vec::with_capacity(targets.len());
    for target in targets {
        let root = match target {
            InstallTarget::Codex => default_codex_home()?,
            InstallTarget::Claude => default_claude_home()?,
        };
        if !root.is_dir() {
            return Err(format!(
                "{} home does not exist: {} (not creating new directories)",
                target.label(),
                root.display()
            )
            .into());
        }
        resolved.push((target, root));
    }

    Ok(resolved)
}

fn default_codex_home() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = env::var_os("CODEX_HOME") {
        return Ok(PathBuf::from(path));
    }
    Ok(home_dir()?.join(".codex"))
}

fn default_claude_home() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(home_dir()?.join(".claude"))
}

fn home_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    resolve_home_dir_from_env(
        env::var_os("HOME"),
        env::var_os("USERPROFILE"),
        env::var_os("HOMEDRIVE"),
        env::var_os("HOMEPATH"),
    )
    .ok_or_else(|| {
        "cannot determine home directory (expected HOME, USERPROFILE, or HOMEDRIVE+HOMEPATH)".into()
    })
}

fn resolve_home_dir_from_env(
    home: Option<OsString>,
    userprofile: Option<OsString>,
    homedrive: Option<OsString>,
    homepath: Option<OsString>,
) -> Option<PathBuf> {
    if let Some(home) = home.filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(home));
    }

    if let Some(userprofile) = userprofile.filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(userprofile));
    }

    let homedrive = homedrive.filter(|value| !value.is_empty())?;
    let homepath = homepath.filter(|value| !value.is_empty())?;
    let absolute_homepath = PathBuf::from(&homepath);
    if absolute_homepath.is_absolute() {
        return Some(absolute_homepath);
    }
    let needs_separator = !matches!(homepath.to_str(), Some(value) if value.starts_with('\\') || value.starts_with('/'));
    let mut combined = homedrive;
    if needs_separator {
        combined.push("\\");
    }
    combined.push(homepath);
    Some(PathBuf::from(combined))
}

fn resolve_claude_config_path(root: &Path) -> PathBuf {
    let settings = root.join("settings.json");
    if settings.is_file() {
        return settings;
    }
    let config = root.join("config.json");
    if config.is_file() {
        return config;
    }
    settings
}

fn upsert_codex_mcp_server(
    config_path: &Path,
    server_name: &str,
    command: &str,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut doc = if config_path.is_file() {
        let raw = fs::read_to_string(config_path)?;
        raw.parse::<DocumentMut>()
            .map_err(|err| format!("failed to parse TOML {}: {err}", config_path.display()))?
    } else {
        DocumentMut::new()
    };

    if doc.get("mcp_servers").is_none() {
        doc["mcp_servers"] = Item::Table(Table::new());
    }
    if !doc["mcp_servers"].is_table() {
        return Err("`mcp_servers` must be a TOML table".into());
    }

    doc["mcp_servers"][server_name]["command"] = value(command);

    let mut toml_args = Array::default();
    for arg in args {
        toml_args.push(arg.as_str());
    }
    doc["mcp_servers"][server_name]["args"] = Item::Value(toml_args.into());

    atomic_write(config_path, &doc.to_string())?;
    Ok(())
}

fn upsert_claude_mcp_server(
    config_path: &Path,
    server_name: &str,
    command: &str,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut root = if config_path.is_file() {
        let raw = fs::read_to_string(config_path)?;
        serde_json::from_str::<JsonValue>(&raw).map_err(|err| {
            format!(
                "failed to parse JSON claude config {}: {err}",
                config_path.display()
            )
        })?
    } else {
        JsonValue::Object(JsonMap::new())
    };

    let Some(root_obj) = root.as_object_mut() else {
        return Err("claude config root must be a JSON object".into());
    };
    let mcp_servers = root_obj
        .entry("mcpServers".to_string())
        .or_insert_with(|| JsonValue::Object(JsonMap::new()));
    let Some(mcp_obj) = mcp_servers.as_object_mut() else {
        return Err("claude config `mcpServers` must be a JSON object".into());
    };
    mcp_obj.insert(
        server_name.to_string(),
        JsonValue::Object(JsonMap::from_iter([
            (
                "command".to_string(),
                JsonValue::String(command.to_string()),
            ),
            (
                "args".to_string(),
                JsonValue::Array(args.iter().cloned().map(JsonValue::String).collect()),
            ),
        ])),
    );

    let serialized = serde_json::to_string_pretty(&root)?;
    atomic_write(config_path, &(serialized + "\n"))?;
    Ok(())
}

fn atomic_write(path: &Path, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    let Some(parent) = path.parent() else {
        return Err(format!("path has no parent: {}", path.display()).into());
    };
    if !parent.exists() {
        return Err(format!("parent directory does not exist: {}", parent.display()).into());
    }

    let tmp_name = format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config")
    );
    let tmp_path = parent.join(tmp_name);
    fs::write(&tmp_path, contents)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_codex_mcp_server_creates_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("config.toml");
        upsert_codex_mcp_server(
            &config,
            "console",
            "/usr/local/bin/mcp-console",
            &["--backend".to_string(), "python".to_string()],
        )
        .expect("upsert codex");
        let text = fs::read_to_string(config).expect("read config");
        let doc = text.parse::<DocumentMut>().expect("parse generated config");
        assert_eq!(
            doc["mcp_servers"]["console"]["command"].as_str(),
            Some("/usr/local/bin/mcp-console")
        );
        let args = doc["mcp_servers"]["console"]["args"]
            .as_array()
            .expect("args array");
        assert_eq!(args.len(), 2);
        assert_eq!(args.get(0).and_then(|v| v.as_str()), Some("--backend"));
        assert_eq!(args.get(1).and_then(|v| v.as_str()), Some("python"));
    }

    #[test]
    fn resolve_home_dir_prefers_home() {
        let resolved = resolve_home_dir_from_env(
            Some(OsString::from("/tmp/home")),
            Some(OsString::from("/tmp/userprofile")),
            Some(OsString::from("C:")),
            Some(OsString::from(r"\Users\example_user")),
        );
        assert_eq!(resolved, Some(PathBuf::from("/tmp/home")));
    }

    #[test]
    fn resolve_home_dir_falls_back_to_userprofile() {
        let resolved = resolve_home_dir_from_env(
            None,
            Some(OsString::from(r"C:\Users\example_user")),
            Some(OsString::from("C:")),
            Some(OsString::from(r"\Users\other")),
        );
        assert_eq!(resolved, Some(PathBuf::from(r"C:\Users\example_user")));
    }

    #[test]
    fn resolve_home_dir_uses_homedrive_and_homepath_when_needed() {
        let resolved = resolve_home_dir_from_env(
            None,
            None,
            Some(OsString::from("C:")),
            Some(OsString::from(r"\Users\example_user")),
        )
        .expect("home dir");
        assert_eq!(resolved, PathBuf::from(r"C:\Users\example_user"));
    }

    #[test]
    fn resolve_home_dir_returns_none_when_all_sources_missing() {
        let resolved = resolve_home_dir_from_env(None, None, None, None);
        assert!(resolved.is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn resolve_home_dir_uses_absolute_homepath_without_prefixing_homedrive() {
        let resolved = resolve_home_dir_from_env(
            None,
            None,
            Some(OsString::from("D:")),
            Some(OsString::from(r"C:\Users\example_user")),
        )
        .expect("home dir");
        assert_eq!(resolved, PathBuf::from(r"C:\Users\example_user"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn resolve_home_dir_treats_windows_style_homepath_as_relative_on_non_windows() {
        let resolved = resolve_home_dir_from_env(
            None,
            None,
            Some(OsString::from("D:")),
            Some(OsString::from(r"C:\Users\example_user")),
        )
        .expect("home dir");
        assert_eq!(resolved, PathBuf::from(r"D:\C:\Users\example_user"));
    }
}
