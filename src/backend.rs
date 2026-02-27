pub const BACKEND_ENV: &str = "MCP_REPL_BACKEND";
pub const INTERPRETER_ENV: &str = "MCP_REPL_INTERPRETER";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    R,
    Python,
}

impl Backend {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_lowercase().as_str() {
            "r" => Ok(Backend::R),
            "python" => Ok(Backend::Python),
            other => Err(format!(
                "invalid interpreter: {other} (expected 'r' or 'python')"
            )),
        }
    }
}

pub fn backend_from_env() -> Result<Option<Backend>, String> {
    for env_name in [INTERPRETER_ENV, BACKEND_ENV] {
        let Ok(value) = std::env::var(env_name) else {
            continue;
        };
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        return Backend::parse(trimmed).map(Some);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn backend_from_env_reads_interpreter_env_var() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::remove_var(INTERPRETER_ENV);
            std::env::remove_var(BACKEND_ENV);
            std::env::set_var(INTERPRETER_ENV, "python");
        }
        let parsed = backend_from_env().expect("parse env var");
        assert_eq!(parsed, Some(Backend::Python));
        unsafe {
            std::env::remove_var(INTERPRETER_ENV);
        }
    }

    #[test]
    fn backend_from_env_falls_back_to_backend_env_var() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::remove_var(INTERPRETER_ENV);
            std::env::remove_var(BACKEND_ENV);
            std::env::set_var(BACKEND_ENV, "python");
        }
        let parsed = backend_from_env().expect("parse env var");
        assert_eq!(parsed, Some(Backend::Python));
        unsafe {
            std::env::remove_var(BACKEND_ENV);
        }
    }

    #[test]
    fn backend_from_env_prefers_interpreter_env_var_when_both_are_set() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::remove_var(INTERPRETER_ENV);
            std::env::remove_var(BACKEND_ENV);
            std::env::set_var(INTERPRETER_ENV, "python");
            std::env::set_var(BACKEND_ENV, "r");
        }
        let parsed = backend_from_env().expect("parse env var");
        assert_eq!(parsed, Some(Backend::Python));
        unsafe {
            std::env::remove_var(INTERPRETER_ENV);
            std::env::remove_var(BACKEND_ENV);
        }
    }
}
