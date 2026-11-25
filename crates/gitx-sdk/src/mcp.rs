use crate::agent_repo::{AgentIdentity, AgentRepo, CommitContext};
use gitx_core::{DomainId, Result};
use gitx_crypto::scan_content;
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use ulid::Ulid;

/// MCP protocol version advertised by [`McpServer`].
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

const JSONRPC_PARSE_ERROR: i64 = -32700;
const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

/// JSON-RPC 2.0 Model Context Protocol (MCP) server exposing [`AgentRepo`] tools to AI coding agents.
pub struct McpServer {
    repo: AgentRepo,
    default_workspace: String,
    default_agent: AgentIdentity,
    initialized: bool,
}

impl McpServer {
    pub fn new(repo: AgentRepo) -> Self {
        Self {
            repo,
            default_workspace: "default".to_string(),
            default_agent: AgentIdentity::new("gitx-mcp", "agent", "mcp-session"),
            initialized: false,
        }
    }

    pub fn with_default_workspace(mut self, workspace: impl Into<String>) -> Self {
        self.default_workspace = workspace.into();
        self
    }

    pub fn with_default_agent(mut self, agent: AgentIdentity) -> Self {
        self.default_agent = agent;
        self
    }

    pub fn repo(&self) -> &AgentRepo {
        &self.repo
    }

    pub fn repo_mut(&mut self) -> &mut AgentRepo {
        &mut self.repo
    }

    pub fn into_repo(self) -> AgentRepo {
        self.repo
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Process a single line of JSON-RPC 2.0 input.
    ///
    /// Returns `None` for empty lines and JSON-RPC notifications (such as `notifications/initialized`).
    pub fn handle_json_line(&mut self, line: &str) -> Option<String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(err) => {
                return Some(error_response(
                    Value::Null,
                    JSONRPC_PARSE_ERROR,
                    &format!("parse error: {err}"),
                ));
            }
        };

        if req.jsonrpc != "2.0" {
            let id = req.id.unwrap_or(Value::Null);
            return Some(error_response(
                id,
                JSONRPC_INVALID_REQUEST,
                "invalid jsonrpc version; expected '2.0'",
            ));
        }

        // Notifications have no `id` and must not elicit a response.
        let Some(id) = req.id else {
            if req.method == "notifications/initialized" {
                self.initialized = true;
            }
            return None;
        };

        match req.method.as_str() {
            "initialize" => {
                let result = json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": {
                        "name": "gitx-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                });
                Some(ok_response(id, result))
            }
            "notifications/initialized" => {
                self.initialized = true;
                Some(ok_response(id, json!({})))
            }
            "ping" => Some(ok_response(id, json!({}))),
            "tools/list" => Some(ok_response(id, json!({ "tools": tool_definitions() }))),
            "tools/call" => Some(self.handle_tool_call(id, &req.params)),
            other => Some(error_response(
                id,
                JSONRPC_METHOD_NOT_FOUND,
                &format!("method not found: '{other}'"),
            )),
        }
    }

    /// Run a newline-delimited JSON-RPC 2.0 MCP session over `reader` and `writer` until EOF.
    pub fn run_stdio(&mut self, reader: impl BufRead, mut writer: impl Write) -> Result<()> {
        for line_res in reader.lines() {
            let line = line_res?;
            if let Some(resp) = self.handle_json_line(&line) {
                writeln!(writer, "{resp}")?;
                writer.flush()?;
            }
        }
        Ok(())
    }

    fn handle_tool_call(&mut self, id: Value, params: &Value) -> String {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return error_response(id, JSONRPC_INVALID_PARAMS, "missing tool 'name'");
        };
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));

        let outcome = match name {
            "gitx_list_files" => self.tool_list_files(&args),
            "gitx_read_file" => self.tool_read_file(&args),
            "gitx_write_file" => self.tool_write_file(&args),
            "gitx_delete_file" => self.tool_delete_file(&args),
            "gitx_diff" => self.tool_diff(&args),
            "gitx_grep" => self.tool_grep(&args),
            "gitx_create_workspace" => self.tool_create_workspace(&args),
            "gitx_commit" => self.tool_commit(&args),
            "gitx_land" => self.tool_land(&args),
            "gitx_checkpoint_save" => self.tool_checkpoint_save(&args),
            "gitx_checkpoint_undo" => self.tool_checkpoint_undo(&args),
            "gitx_why" => self.tool_why(&args),
            "gitx_secret_scan" => self.tool_secret_scan(&args),
            _ => {
                return error_response(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    &format!("unknown tool '{name}'"),
                );
            }
        };

        match outcome {
            Ok(payload) => ok_response(id, tool_result_ok(payload)),
            Err(err_msg) => ok_response(id, tool_result_err(&err_msg)),
        }
    }

    fn workspace_arg<'a>(&'a self, args: &'a Value) -> &'a str {
        args.get("workspace")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(self.default_workspace.as_str())
    }

    fn agent_from_args(&self, args: &Value) -> AgentIdentity {
        AgentIdentity {
            harness: args
                .get("harness")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| self.default_agent.harness.clone()),
            model: args
                .get("model")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| self.default_agent.model.clone()),
            session_id: args
                .get("session_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| self.default_agent.session_id.clone()),
        }
    }

    fn tool_list_files(&self, args: &Value) -> std::result::Result<Value, String> {
        let ws = self.workspace_arg(args);
        let files = self.repo.list_files_at(ws).map_err(|e| e.to_string())?;
        Ok(json!({
            "workspace": ws,
            "files": files,
        }))
    }

    fn tool_read_file(&self, args: &Value) -> std::result::Result<Value, String> {
        let ws = self.workspace_arg(args);
        let path = require_str(args, "path")?;
        let bytes = self
            .repo
            .read_file_at(ws, path)
            .map_err(|e| e.to_string())?;
        let content = String::from_utf8_lossy(&bytes).into_owned();
        Ok(json!({
            "workspace": ws,
            "path": path,
            "size": bytes.len(),
            "content": content,
        }))
    }

    fn tool_write_file(&mut self, args: &Value) -> std::result::Result<Value, String> {
        let ws = self.workspace_arg(args).to_string();
        let path = require_str(args, "path")?;
        let content = require_str(args, "content")?;
        let warnings = self
            .repo
            .write_file(&ws, path, content.as_bytes())
            .map_err(|e| e.to_string())?;
        Ok(json!({
            "workspace": ws,
            "path": path,
            "bytes_written": content.len(),
            "secret_warnings": warnings,
        }))
    }

    fn tool_delete_file(&mut self, args: &Value) -> std::result::Result<Value, String> {
        let ws = self.workspace_arg(args).to_string();
        let path = require_str(args, "path")?;
        self.repo
            .delete_file(&ws, path)
            .map_err(|e| e.to_string())?;
        Ok(json!({
            "workspace": ws,
            "path": path,
            "deleted": true,
        }))
    }

    fn tool_diff(&self, args: &Value) -> std::result::Result<Value, String> {
        let ws = self.workspace_arg(args);
        let diff = match args.get("base_ref").and_then(Value::as_str) {
            Some(base_ref) if !base_ref.is_empty() => self
                .repo
                .diff_against(ws, base_ref)
                .map_err(|e| e.to_string())?,
            _ => self.repo.diff(ws).map_err(|e| e.to_string())?,
        };
        Ok(json!({
            "workspace": ws,
            "diff": diff,
        }))
    }

    fn tool_grep(&self, args: &Value) -> std::result::Result<Value, String> {
        let ws = self.workspace_arg(args);
        let query = args
            .get("query")
            .or_else(|| args.get("pattern"))
            .and_then(Value::as_str)
            .ok_or_else(|| "missing required string argument 'query'".to_string())?;
        let matches = self.repo.grep(ws, query).map_err(|e| e.to_string())?;
        Ok(json!({
            "workspace": ws,
            "query": query,
            "matches": matches,
        }))
    }

    fn tool_create_workspace(&mut self, args: &Value) -> std::result::Result<Value, String> {
        let name = require_str(args, "name")?;
        let base_ref = args
            .get("base_ref")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("master");
        let ws_ref = self
            .repo
            .create_workspace(name, base_ref)
            .map_err(|e| e.to_string())?;
        Ok(json!({
            "workspace": ws_ref,
        }))
    }

    fn tool_commit(&mut self, args: &Value) -> std::result::Result<Value, String> {
        let ws = self.workspace_arg(args).to_string();
        let message = require_str(args, "message")?;
        let agent = self.agent_from_args(args);

        let context = match args.get("prompt").and_then(Value::as_str) {
            Some(prompt) if !prompt.is_empty() => {
                let mut ctx = CommitContext::prompt(prompt);
                if let Some(vis) = args.get("visibility").and_then(Value::as_str) {
                    let domain = DomainId::new(vis).map_err(|e| e.to_string())?;
                    ctx = ctx.with_visibility(domain);
                }
                Some(ctx)
            }
            _ => None,
        };

        let outcome = self
            .repo
            .commit(&ws, message, agent, context)
            .map_err(|e| e.to_string())?;

        Ok(json!({
            "workspace": ws,
            "changeset_id": outcome.changeset.id.to_hex(),
            "change_id": outcome.changeset.change_id.to_string(),
            "committer": outcome.changeset.committer,
            "context_record_id": outcome.context_record.as_ref().map(|r| r.id.to_string()),
            "secret_warnings": outcome.secret_warnings,
        }))
    }

    fn tool_land(&mut self, args: &Value) -> std::result::Result<Value, String> {
        let ws = self.workspace_arg(args).to_string();
        let target = args
            .get("target")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("master");
        let outcome = self.repo.land(&ws, target).map_err(|e| e.to_string())?;
        Ok(json!({
            "workspace": ws,
            "target": outcome.land_record.target,
            "land_seq": outcome.land_record.land_seq,
            "new_head": outcome.land_record.new_head.to_hex(),
            "auto_merged": outcome.auto_merged,
            "landed_changes": outcome
                .land_record
                .landed_changes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "conflict_paths": outcome.conflict_paths,
        }))
    }

    fn tool_checkpoint_save(&mut self, args: &Value) -> std::result::Result<Value, String> {
        let ws = self.workspace_arg(args).to_string();
        let summary = args
            .get("prompt_summary")
            .or_else(|| args.get("summary"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let agent = self.agent_from_args(args);
        let cp = self
            .repo
            .save_checkpoint(&ws, agent, summary)
            .map_err(|e| e.to_string())?;
        Ok(json!({
            "checkpoint": cp,
        }))
    }

    fn tool_checkpoint_undo(&mut self, args: &Value) -> std::result::Result<Value, String> {
        let ws = self.workspace_arg(args).to_string();
        let cp_id = match args.get("checkpoint_id").and_then(Value::as_str) {
            Some(raw) if !raw.is_empty() => {
                let parsed = Ulid::from_string(raw)
                    .map_err(|e| format!("invalid checkpoint_id '{raw}': {e}"))?;
                Some(parsed)
            }
            _ => None,
        };

        let outcome = self
            .repo
            .undo_checkpoint(&ws, cp_id)
            .map_err(|e| e.to_string())?;
        Ok(json!({
            "workspace": ws,
            "reverted_checkpoint_id": outcome.reverted_checkpoint.id.to_string(),
            "restored_to_checkpoint": outcome.restored_to_checkpoint.map(|u| u.to_string()),
            "clean_paths": outcome.clean_paths,
            "conflict_paths": outcome.conflict_paths,
        }))
    }

    fn tool_why(&self, args: &Value) -> std::result::Result<Value, String> {
        let ws = self.workspace_arg(args);
        let path = require_str(args, "path")?;
        let line = args
            .get("line")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|&n| n >= 1)
            .ok_or_else(|| "missing or invalid 1-based integer argument 'line'".to_string())?;

        let matches = self.repo.why(ws, path, line).map_err(|e| e.to_string())?;
        Ok(json!({
            "workspace": ws,
            "path": path,
            "line": line,
            "matches": matches,
        }))
    }

    fn tool_secret_scan(&self, args: &Value) -> std::result::Result<Value, String> {
        if let Some(content) = args.get("content").and_then(Value::as_str) {
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("inline.txt");
            let findings = scan_content(path, content.as_bytes());
            return Ok(json!({
                "path": path,
                "has_secrets": !findings.is_empty(),
                "findings": findings,
            }));
        }

        let ws = self.workspace_arg(args);
        let path = args.get("path").and_then(Value::as_str);
        let findings = self
            .repo
            .scan_secrets(ws, path)
            .map_err(|e| e.to_string())?;
        Ok(json!({
            "workspace": ws,
            "path": path,
            "has_secrets": !findings.is_empty(),
            "findings": findings,
        }))
    }
}

fn require_str<'a>(args: &'a Value, key: &str) -> std::result::Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing required string argument '{key}'"))
}

fn ok_response(id: Value, result: Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
    .to_string()
}

fn error_response(id: Value, code: i64, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        },
    })
    .to_string()
}

fn tool_result_ok(payload: Value) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": payload.to_string(),
            }
        ],
        "isError": false,
    })
}

fn tool_result_err(message: &str) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": message,
            }
        ],
        "isError": true,
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "gitx_list_files",
            "description": "List all readable files in an in-memory workspace or revision.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Workspace name or revision ref (default: 'default')." }
                }
            }
        },
        {
            "name": "gitx_read_file",
            "description": "Read a file from an in-memory workspace or revision with ACL enforcement.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Workspace name or revision ref." },
                    "path": { "type": "string", "description": "Repository-relative file path." }
                },
                "required": ["path"]
            }
        },
        {
            "name": "gitx_write_file",
            "description": "Write a file into an in-memory workspace and run the zero-trust secret scanner.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Target workspace name." },
                    "path": { "type": "string", "description": "Repository-relative file path." },
                    "content": { "type": "string", "description": "UTF-8 file content to write." }
                },
                "required": ["path", "content"]
            }
        },
        {
            "name": "gitx_delete_file",
            "description": "Delete a file from an in-memory workspace.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Target workspace name." },
                    "path": { "type": "string", "description": "Repository-relative file path." }
                },
                "required": ["path"]
            }
        },
        {
            "name": "gitx_diff",
            "description": "Render a unified diff of uncommitted changes in a workspace (or against base_ref).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Workspace name." },
                    "base_ref": { "type": "string", "description": "Optional base bookmark or revision hash." }
                }
            }
        },
        {
            "name": "gitx_grep",
            "description": "Search readable files in an in-memory workspace for a substring query.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Workspace name." },
                    "query": { "type": "string", "description": "Substring to search for." }
                },
                "required": ["query"]
            }
        },
        {
            "name": "gitx_create_workspace",
            "description": "Create an instant O(1) in-memory workspace off a bookmark, workspace, or revision.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Unique workspace name." },
                    "base_ref": { "type": "string", "description": "Base bookmark, workspace, or revision (default: 'master')." }
                },
                "required": ["name"]
            }
        },
        {
            "name": "gitx_commit",
            "description": "Commit workspace changes with AI agent provenance and optional durable 'Why' prompt context.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Workspace name." },
                    "message": { "type": "string", "description": "Commit description." },
                    "prompt": { "type": "string", "description": "Optional user prompt stored as a durable ContextRecord." },
                    "visibility": { "type": "string", "description": "Optional Visibility Domain for the context record (default: 'public')." },
                    "harness": { "type": "string", "description": "Agent harness name." },
                    "model": { "type": "string", "description": "Agent model identifier." },
                    "session_id": { "type": "string", "description": "Agent session identifier." }
                },
                "required": ["message"]
            }
        },
        {
            "name": "gitx_land",
            "description": "Transactionally land committed workspace changes onto a target bookmark with 3-way semantic auto-merge.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Workspace name." },
                    "target": { "type": "string", "description": "Target bookmark (default: 'master')." }
                }
            }
        },
        {
            "name": "gitx_checkpoint_save",
            "description": "Save a sub-commit checkpoint of a workspace's in-memory tree state.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Workspace name." },
                    "prompt_summary": { "type": "string", "description": "Short summary of the agent step." },
                    "harness": { "type": "string", "description": "Agent harness name." },
                    "model": { "type": "string", "description": "Agent model identifier." },
                    "session_id": { "type": "string", "description": "Agent session identifier." }
                }
            }
        },
        {
            "name": "gitx_checkpoint_undo",
            "description": "Surgically undo an agent checkpoint while preserving concurrent non-overlapping human edits.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Workspace name." },
                    "checkpoint_id": { "type": "string", "description": "Optional checkpoint ULID (defaults to latest checkpoint)." }
                }
            }
        },
        {
            "name": "gitx_why",
            "description": "Explain why a specific line exists by relocating durable prompt/context anchors.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Workspace name or revision ref." },
                    "path": { "type": "string", "description": "Repository-relative file path." },
                    "line": { "type": "integer", "minimum": 1, "description": "1-based line number." }
                },
                "required": ["path", "line"]
            }
        },
        {
            "name": "gitx_secret_scan",
            "description": "Scan inline content, a single workspace file, or an entire workspace for leaked secrets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": { "type": "string", "description": "Workspace name." },
                    "path": { "type": "string", "description": "Optional file path to scan." },
                    "content": { "type": "string", "description": "Optional inline content to scan directly." }
                }
            }
        }
    ])
}
