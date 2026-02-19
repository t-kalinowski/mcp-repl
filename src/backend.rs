pub const BACKEND_ENV: &str = "MCP_REPL_BACKEND";

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
                "invalid backend: {other} (expected 'r' or 'python')"
            )),
        }
    }
}

pub fn backend_from_env() -> Result<Option<Backend>, String> {
    let Ok(value) = std::env::var(BACKEND_ENV) else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Backend::parse(trimmed).map(Some)
}
