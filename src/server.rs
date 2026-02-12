use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Content, CustomNotification, CustomRequest, CustomResult, ErrorCode,
    ErrorData as McpError, JsonObject, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::{RoleServer, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread;

mod response;
#[cfg(test)]
mod tests;
mod timeouts;

use self::response::{finalize_batch, worker_reply_to_contents};
use self::timeouts::{
    SANDBOX_UPDATE_TIMEOUT, apply_safety_margin, apply_tool_call_margin, parse_timeout,
};

use crate::backend::Backend;
use crate::sandbox::{SANDBOX_STATE_CAPABILITY, SANDBOX_STATE_METHOD, SandboxStateUpdate};
use crate::worker_process::{WorkerError, WorkerManager};

#[derive(Clone)]
struct ConsoleToolServer {
    worker: Arc<Mutex<WorkerManager>>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl ConsoleToolServer {
    fn new(backend: Backend) -> Result<Self, WorkerError> {
        let worker = WorkerManager::new(backend)?;
        Ok(Self {
            worker: Arc::new(Mutex::new(worker)),
            tool_router: Self::tool_router(),
        })
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_06_18,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_experimental_with(sandbox_capabilities())
                .build(),
            ..ServerInfo::default()
        }
    }

    async fn run_worker<T, F>(&self, f: F) -> Result<T, McpError>
    where
        F: FnOnce(&mut WorkerManager) -> T + Send + 'static,
        T: Send + 'static,
    {
        let worker = self.worker.clone();
        tokio::task::spawn_blocking(move || {
            let mut worker = worker.lock().unwrap();
            f(&mut worker)
        })
        .await
        .map_err(|err| McpError::internal_error(err.to_string(), None))
    }

    #[doc = include_str!("../docs/tool-descriptions/write_stdin_tool.md")]
    #[tool(name = "write_stdin")]
    async fn write_stdin(
        &self,
        params: Parameters<WriteStdinArgs>,
    ) -> Result<CallToolResult, McpError> {
        let WriteStdinArgs { chars, timeout } = params.0;
        let timeout = parse_timeout(timeout, "write_stdin", true)?;
        let worker_timeout = apply_tool_call_margin(timeout);
        let server_timeout = apply_safety_margin(timeout);
        let result = self
            .run_worker(move |worker| {
                worker.write_stdin(chars, worker_timeout, server_timeout, None, false)
            })
            .await?;

        let mut contents = Vec::new();
        let mut is_error = false;
        match result {
            Ok(reply) => {
                let (mut reply_contents, reply_error) = worker_reply_to_contents(reply);
                is_error |= reply_error;
                contents.append(&mut reply_contents);
                Ok(finalize_batch(contents, is_error))
            }
            Err(err) => {
                eprintln!("worker write stdin error: {err}");
                contents.push(Content::text(format!("worker error: {err}")));
                is_error = true;
                Ok(finalize_batch(contents, is_error))
            }
        }
    }
}

#[tool_handler]
impl ServerHandler for ConsoleToolServer {
    fn get_info(&self) -> ServerInfo {
        ConsoleToolServer::get_info(self)
    }

    async fn on_custom_request(
        &self,
        request: CustomRequest,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<CustomResult, McpError> {
        if std::env::var_os("MCP_CONSOLE_DEBUG_MCP").is_some() {
            eprintln!("custom request: {}", request.method);
        }
        crate::sandbox::log_sandbox_state_event(&request.method, request.params.as_ref());
        if request.method != SANDBOX_STATE_METHOD {
            return Err(McpError::new(
                ErrorCode::METHOD_NOT_FOUND,
                request.method,
                None,
            ));
        }

        let update = request
            .params_as::<SandboxStateUpdate>()
            .map_err(|err| McpError::invalid_params(err.to_string(), None))?
            .ok_or_else(|| McpError::invalid_params("missing sandbox state params", None))?;

        let result = self
            .run_worker(move |worker| worker.update_sandbox_state(update, SANDBOX_UPDATE_TIMEOUT))
            .await?;
        if let Err(err) = result {
            return Err(McpError::internal_error(err.to_string(), None));
        }

        Ok(CustomResult::new(json!({})))
    }

    async fn on_custom_notification(
        &self,
        notification: CustomNotification,
        _context: rmcp::service::NotificationContext<RoleServer>,
    ) {
        crate::sandbox::log_sandbox_state_event(&notification.method, notification.params.as_ref());
        if notification.method != SANDBOX_STATE_METHOD {
            return;
        }

        let update = match notification.params_as::<SandboxStateUpdate>() {
            Ok(Some(update)) => update,
            Ok(None) => {
                eprintln!("sandbox update missing params");
                return;
            }
            Err(err) => {
                eprintln!("sandbox update parse error: {err}");
                return;
            }
        };

        match self
            .run_worker(move |worker| worker.update_sandbox_state(update, SANDBOX_UPDATE_TIMEOUT))
            .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                eprintln!("sandbox update failed: {err}");
            }
            Err(err) => {
                eprintln!("sandbox update failed: {err}");
            }
        }
    }
}

#[derive(Deserialize, JsonSchema)]
struct WriteStdinArgs {
    chars: String,
    timeout: Option<f64>,
}

fn sandbox_capabilities() -> BTreeMap<String, JsonObject> {
    let mut capability = JsonObject::new();
    capability.insert("version".to_string(), json!("1.0.0"));
    let mut experimental = BTreeMap::new();
    experimental.insert(SANDBOX_STATE_CAPABILITY.to_string(), capability);
    experimental
}

pub async fn run(backend: Backend) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("starting mcp-console server");
    let service = ConsoleToolServer::new(backend)?;
    let worker = service.worker.clone();
    let shutdown_worker = service.worker.clone();
    thread::spawn(move || {
        let mut worker = worker.lock().unwrap();
        if let Err(err) = worker.warm_start() {
            eprintln!("worker warm start error: {err}");
        }
    });

    let result: Result<(), Box<dyn std::error::Error>> = async {
        let running = rmcp::serve_server(service, rmcp::transport::stdio()).await?;
        running
            .waiting()
            .await
            .map(|_| ())
            .map_err(|err| err.into())
    }
    .await;
    {
        let mut worker = shutdown_worker.lock().unwrap();
        worker.shutdown();
    }
    result
}
