use std::time::Duration;

use rmcp::model::ErrorData as McpError;

const DEFAULT_TOOL_TIMEOUT_SECS: f64 = 60.0;
const SAFETY_MARGIN: f64 = 1.05;
const MIN_SERVER_GRACE: Duration = Duration::from_secs(1);
const TOOL_CALL_MARGIN_MIN: Duration = Duration::from_millis(200);
const TOOL_CALL_MARGIN_MAX: Duration = Duration::from_secs(2);
const TOOL_CALL_MARGIN_FRACTION: f64 = 0.05;
const TOOL_CALL_MARGIN_THRESHOLD: Duration = Duration::from_secs(2);

pub(crate) const SANDBOX_UPDATE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn parse_timeout(
    timeout: Option<f64>,
    tool_name: &str,
    allow_zero: bool,
) -> Result<Duration, McpError> {
    let value = timeout.unwrap_or(DEFAULT_TOOL_TIMEOUT_SECS);
    let invalid = if allow_zero {
        !value.is_finite() || value < 0.0
    } else {
        !value.is_finite() || value <= 0.0
    };
    if invalid {
        return Err(McpError::invalid_params(
            if allow_zero {
                format!("timeout for {tool_name} must be a non-negative number of seconds")
            } else {
                format!("timeout for {tool_name} must be a positive number of seconds")
            },
            None,
        ));
    }
    Ok(Duration::from_secs_f64(value))
}

pub(crate) fn apply_safety_margin(duration: Duration) -> Duration {
    let scaled = Duration::from_secs_f64(duration.as_secs_f64() * SAFETY_MARGIN);
    let min = duration.saturating_add(MIN_SERVER_GRACE);
    if scaled < min { min } else { scaled }
}

pub(crate) fn apply_tool_call_margin(duration: Duration) -> Duration {
    // The MCP client may enforce its own deadline (often 60s). If we block until exactly the
    // requested timeout, the client can time out the RPC and report it as a tool-call failure.
    // Return slightly before the requested timeout to keep a clean boundary:
    // - MCP errors: protocol/validation/internal failures (returned via McpError).
    // - Backend/runtime errors: included in tool output, not as MCP tool failures.
    if duration < TOOL_CALL_MARGIN_THRESHOLD {
        return duration;
    }
    let mut margin = duration.mul_f64(TOOL_CALL_MARGIN_FRACTION);
    if margin < TOOL_CALL_MARGIN_MIN {
        margin = TOOL_CALL_MARGIN_MIN;
    }
    if margin > TOOL_CALL_MARGIN_MAX {
        margin = TOOL_CALL_MARGIN_MAX;
    }
    duration.saturating_sub(margin)
}
