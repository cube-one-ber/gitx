//! Pure-Rust WebAssembly (`wasm32-wasip1`) bindings for GitX.
//!
//! Exposes a clean linear-memory ABI (`gitx_alloc`, `gitx_dealloc`, `gitx_create_repo`,
//! `gitx_drop_repo`, `gitx_invoke`) wrapping [`gitx_sdk::AgentRepo`] and
//! [`gitx_sdk::McpServer`] for zero-disk, zero-OS in-memory version control inside WASM.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::Utc;
use gitx_context::{CodeAnchor, ContextId, ContextKind, ContextRecord};
use gitx_core::{ChangeSet, DomainId, GitxError, Identity, ObjectHash};
use gitx_crypto::{AclPolicy, Principal, scan_content};
use gitx_sdk::{AgentIdentity, AgentRepo, CommitContext, McpServer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::alloc::{Layout, alloc, dealloc};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ptr::NonNull;
use std::slice;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{LazyLock, Mutex};
use ulid::Ulid;

const DEFAULT_WORKSPACE: &str = "default";
const DEFAULT_BOOKMARK: &str = "master";

struct RepoInstance {
    mcp: McpServer,
    default_workspace: String,
    default_agent: AgentIdentity,
}

static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1);
static REPOS: LazyLock<Mutex<BTreeMap<u32, RepoInstance>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Optional configuration JSON accepted by [`gitx_create_repo`] / [`create_repo_from_json`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoConfig {
    #[serde(default, alias = "author_name")]
    pub author_name: Option<String>,
    #[serde(default, alias = "author_email")]
    pub author_email: Option<String>,
    #[serde(default, alias = "principal_id")]
    pub principal_id: Option<String>,
    #[serde(default)]
    pub teams: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub anonymous: bool,
    #[serde(default)]
    pub acl: Option<String>,
    #[serde(default, alias = "default_workspace")]
    pub default_workspace: Option<String>,
    #[serde(default)]
    pub agent: Option<AgentInput>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentInput {
    pub harness: String,
    pub model: String,
    #[serde(alias = "session_id")]
    pub session_id: String,
}

impl From<AgentInput> for AgentIdentity {
    fn from(value: AgentInput) -> Self {
        AgentIdentity::new(value.harness, value.model, value.session_id)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InvokeEnvelope {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<InvokeError>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InvokeError {
    code: &'static str,
    message: String,
}

impl InvokeEnvelope {
    fn ok(data: Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    fn err(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(InvokeError {
                code,
                message: message.into(),
            }),
        }
    }

    fn from_gitx_error(err: GitxError) -> Self {
        let code = match &err {
            GitxError::NotFound(_) => "not_found",
            GitxError::AccessDenied { .. } => "access_denied",
            GitxError::ConflictPresent(_) => "conflict",
            GitxError::Merge(_) => "merge_error",
            GitxError::Workspace(_) => "workspace_error",
            GitxError::InvalidDomain(_) => "invalid_domain",
            GitxError::InvalidHash(_) => "invalid_hash",
            GitxError::Crypto(_) => "crypto_error",
            GitxError::Serialization(_) => "serialization_error",
            GitxError::Storage(_) => "storage_error",
            GitxError::GitBridge(_) => "git_bridge_error",
            GitxError::Io(_) => "io_error",
        };
        Self::err(code, err.to_string())
    }
}

// ---------------------------------------------------------------------------
// Linear-Memory ABI
// ---------------------------------------------------------------------------

/// Allocate `len` bytes in WASM linear memory with 1-byte alignment.
#[unsafe(no_mangle)]
pub extern "C" fn gitx_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return NonNull::<u8>::dangling().as_ptr();
    }
    let Ok(layout) = Layout::from_size_align(len, 1) else {
        return std::ptr::null_mut();
    };
    // SAFETY: `layout` has non-zero size and valid power-of-two alignment (1).
    unsafe { alloc(layout) }
}

/// Deallocate a buffer previously returned by [`gitx_alloc`] or [`gitx_invoke`].
///
/// # Safety
/// `ptr` must have been allocated by [`gitx_alloc`] (or returned by [`gitx_invoke`]) with the
/// exact same byte length `len`, and must not be freed more than once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gitx_dealloc(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    if let Ok(layout) = Layout::from_size_align(len, 1) {
        // SAFETY: Caller guarantees `ptr` was allocated with `Layout::from_size_align(len, 1)`.
        unsafe { dealloc(ptr, layout) };
    }
}

/// Create a new in-memory GitX repository instance from an optional UTF-8 JSON [`RepoConfig`].
///
/// Returns a non-zero repository handle (`u32`) on success, or `0` if configuration or
/// initialization fails.
///
/// # Safety
/// If `config_len > 0`, `config_ptr` must be valid for reads of `config_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gitx_create_repo(config_ptr: *const u8, config_len: usize) -> u32 {
    let config_str = if config_ptr.is_null() || config_len == 0 {
        ""
    } else {
        // SAFETY: Caller guarantees `config_ptr` is valid for `config_len` readable bytes.
        let bytes = unsafe { slice::from_raw_parts(config_ptr, config_len) };
        match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    create_repo_from_json(config_str).unwrap_or(0)
}

/// Drop an in-memory GitX repository handle and free all associated memory.
///
/// Returns `1` if the handle existed and was removed, or `0` if not found.
#[unsafe(no_mangle)]
pub extern "C" fn gitx_drop_repo(handle: u32) -> i32 {
    i32::from(drop_repo(handle))
}

/// Invoke an operation against repository `handle` using a UTF-8 JSON request buffer.
///
/// Returns a packed `u64`: upper 32 bits are the pointer to the UTF-8 JSON response buffer in
/// 32-bit WASM linear memory, and lower 32 bits are its byte length. The host must free the
/// returned buffer by calling [`gitx_dealloc`] with `(ptr, len)`.
///
/// For 64-bit native hosts, use [`gitx_invoke_into`] which writes the full pointer width without
/// 32-bit packing.
///
/// # Safety
/// If `req_len > 0`, `req_ptr` must be valid for reads of `req_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gitx_invoke(handle: u32, req_ptr: *const u8, req_len: usize) -> u64 {
    // SAFETY: Forwarded with the same preconditions guaranteed by the caller.
    let (ptr, len) = unsafe { invoke_to_raw_buffer(handle, req_ptr, req_len) };
    if ptr.is_null() {
        return 0;
    }
    pack_ptr_len(ptr as usize, len)
}

/// Pointer-width-independent variant of [`gitx_invoke`] writing the allocated response pointer
/// and byte length to `out_ptr` and `out_len`.
///
/// Returns `1` on success and `0` if `out_ptr`/`out_len` are null or allocation fails.
/// The caller must free the response buffer with [`gitx_dealloc`].
///
/// # Safety
/// - If `req_len > 0`, `req_ptr` must be valid for reads of `req_len` bytes.
/// - `out_ptr` and `out_len` must be valid, aligned, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gitx_invoke_into(
    handle: u32,
    req_ptr: *const u8,
    req_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return 0;
    }
    // SAFETY: Forwarded with the same preconditions guaranteed by the caller.
    let (ptr, len) = unsafe { invoke_to_raw_buffer(handle, req_ptr, req_len) };
    if ptr.is_null() {
        return 0;
    }
    // SAFETY: Caller guarantees `out_ptr` and `out_len` are valid writable pointers.
    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }
    1
}

/// # Safety
/// If `req_len > 0`, `req_ptr` must be valid for reads of `req_len` bytes.
unsafe fn invoke_to_raw_buffer(
    handle: u32,
    req_ptr: *const u8,
    req_len: usize,
) -> (*mut u8, usize) {
    let response_json = if req_ptr.is_null() && req_len > 0 {
        serialize_envelope(&InvokeEnvelope::err(
            "invalid_request",
            "null request pointer with non-zero length",
        ))
    } else {
        let bytes = if req_len == 0 {
            &[][..]
        } else {
            // SAFETY: Caller guarantees `req_ptr` is valid for `req_len` readable bytes.
            unsafe { slice::from_raw_parts(req_ptr, req_len) }
        };
        match std::str::from_utf8(bytes) {
            Ok(req_str) => invoke_json(handle, req_str),
            Err(err) => serialize_envelope(&InvokeEnvelope::err(
                "invalid_utf8",
                format!("request is not valid UTF-8: {err}"),
            )),
        }
    };

    write_response_bytes(response_json.as_bytes())
}

fn write_response_bytes(bytes: &[u8]) -> (*mut u8, usize) {
    let len = bytes.len();
    let ptr = gitx_alloc(len);
    if ptr.is_null() {
        return (std::ptr::null_mut(), 0);
    }
    if len > 0 {
        // SAFETY: `ptr` was freshly allocated for `len` bytes and does not overlap `bytes`.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len) };
    }
    (ptr, len)
}

/// Pack `(ptr, len)` into a single `u64` (`ptr` in high 32 bits, `len` in low 32 bits).
pub fn pack_ptr_len(ptr: usize, len: usize) -> u64 {
    ((ptr as u64) << 32) | ((len as u64) & 0xffff_ffff)
}

/// Unpack a `(ptr, len)` pair returned by [`gitx_invoke`].
pub fn unpack_ptr_len(packed: u64) -> (usize, usize) {
    let ptr = (packed >> 32) as usize;
    let len = (packed & 0xffff_ffff) as usize;
    (ptr, len)
}

// ---------------------------------------------------------------------------
// Safe Rust API (used by both the WASM ABI and host unit tests)
// ---------------------------------------------------------------------------

/// Create a new in-memory repository from an optional JSON [`RepoConfig`] string.
pub fn create_repo_from_json(config_json: &str) -> Result<u32, String> {
    let cfg: RepoConfig = if config_json.trim().is_empty() {
        RepoConfig::default()
    } else {
        serde_json::from_str(config_json).map_err(|e| format!("invalid repo config JSON: {e}"))?
    };

    let author_name = cfg
        .author_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "GitX Agent".to_string());
    let author_email = cfg
        .author_email
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}@gitx.local",
                author_name.to_lowercase().replace(' ', ".")
            )
        });
    let author = Identity {
        name: author_name.clone(),
        email: author_email,
        key_fingerprint: cfg.fingerprint.clone(),
    };

    let principal = if cfg.anonymous {
        Principal::anonymous()
    } else {
        let mut p = Principal::user(
            cfg.principal_id
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| author_name.to_lowercase().replace(' ', "-")),
        );
        if !cfg.teams.is_empty() {
            p = p.with_teams(cfg.teams);
        }
        if !cfg.roles.is_empty() {
            p = p.with_roles(cfg.roles);
        }
        if let Some(fp) = cfg.fingerprint {
            p = p.with_fingerprint(fp);
        }
        p
    };

    let mut repo = AgentRepo::in_memory(author, principal).map_err(|e| e.to_string())?;
    if let Some(acl_text) = cfg.acl {
        let policy = AclPolicy::parse(&acl_text).map_err(|e| e.to_string())?;
        repo.set_acl(policy);
    }

    let default_workspace = cfg
        .default_workspace
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_WORKSPACE.to_string());
    let default_agent = cfg
        .agent
        .map(AgentIdentity::from)
        .unwrap_or_else(|| AgentIdentity::new("gitx-wasm", "agent", "wasm-session"));

    let mcp = McpServer::new(repo)
        .with_default_workspace(default_workspace.clone())
        .with_default_agent(default_agent.clone());

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let mut map = REPOS
        .lock()
        .map_err(|_| "repository registry mutex poisoned".to_string())?;
    map.insert(
        handle,
        RepoInstance {
            mcp,
            default_workspace,
            default_agent,
        },
    );
    Ok(handle)
}

/// Remove a repository handle from the registry.
pub fn drop_repo(handle: u32) -> bool {
    let Ok(mut map) = REPOS.lock() else {
        return false;
    };
    map.remove(&handle).is_some()
}

/// Execute a JSON request against repository `handle` and return a JSON response envelope string.
pub fn invoke_json(handle: u32, req_str: &str) -> String {
    let envelope = match serde_json::from_str::<Value>(req_str) {
        Ok(req) => dispatch_request(handle, &req),
        Err(err) => InvokeEnvelope::err("invalid_json", format!("invalid request JSON: {err}")),
    };
    serialize_envelope(&envelope)
}

fn serialize_envelope(env: &InvokeEnvelope) -> String {
    serde_json::to_string(env).unwrap_or_else(|e| {
        format!(
            r#"{{"ok":false,"error":{{"code":"serialization_error","message":"{}"}}}}"#,
            e
        )
    })
}

fn dispatch_request(handle: u32, req: &Value) -> InvokeEnvelope {
    let Some(op) = req.get("op").and_then(Value::as_str) else {
        return InvokeEnvelope::err("invalid_request", "missing required string field 'op'");
    };

    let Ok(mut map) = REPOS.lock() else {
        return InvokeEnvelope::err("internal", "repository registry mutex poisoned");
    };
    let Some(inst) = map.get_mut(&handle) else {
        return InvokeEnvelope::err(
            "invalid_handle",
            format!("unknown repository handle {handle}"),
        );
    };

    let result = match op {
        "createWorkspace" => op_create_workspace(inst, req),
        "listWorkspaces" => op_list_workspaces(inst),
        "writeFile" => op_write_file(inst, req),
        "readFile" => op_read_file(inst, req),
        "deleteFile" => op_delete_file(inst, req),
        "listFiles" => op_list_files(inst, req),
        "commit" => op_commit(inst, req),
        "land" => op_land(inst, req),
        "diff" => op_diff(inst, req),
        "grep" => op_grep(inst, req),
        "log" => op_log(inst, req),
        "recordContext" => op_record_context(inst, req),
        "why" => op_why(inst, req),
        "checkpoint" => op_checkpoint(inst, req),
        "listCheckpoints" => op_list_checkpoints(inst, req),
        "undoCheckpoint" => op_undo_checkpoint(inst, req),
        "scanSecrets" => op_scan_secrets(inst, req),
        "setAcl" => op_set_acl(inst, req),
        "setPrincipal" => op_set_principal(inst, req),
        "mcpCall" => op_mcp_call(inst, req),
        other => {
            return InvokeEnvelope::err("unknown_op", format!("unsupported operation '{other}'"));
        }
    };

    match result {
        Ok(data) => InvokeEnvelope::ok(data),
        Err(err) => err,
    }
}

type OpResult = Result<Value, InvokeEnvelope>;

fn req_str<'a>(req: &'a Value, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(s) = req.get(*key).and_then(Value::as_str) {
            return Some(s);
        }
    }
    None
}

fn require_str<'a>(req: &'a Value, keys: &[&str]) -> Result<&'a str, InvokeEnvelope> {
    req_str(req, keys).ok_or_else(|| {
        InvokeEnvelope::err(
            "invalid_request",
            format!("missing required string field '{}'", keys[0]),
        )
    })
}

fn workspace_or_default<'a>(inst: &'a RepoInstance, req: &'a Value) -> &'a str {
    req_str(req, &["workspace"])
        .filter(|s| !s.is_empty())
        .unwrap_or(inst.default_workspace.as_str())
}

fn agent_or_default(inst: &RepoInstance, req: &Value) -> AgentIdentity {
    if let Some(agent_val) = req.get("agent")
        && let Ok(parsed) = serde_json::from_value::<AgentInput>(agent_val.clone())
    {
        return parsed.into();
    }
    AgentIdentity {
        harness: req_str(req, &["harness"])
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| inst.default_agent.harness.clone()),
        model: req_str(req, &["model"])
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| inst.default_agent.model.clone()),
        session_id: req_str(req, &["sessionId", "session_id"])
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| inst.default_agent.session_id.clone()),
    }
}

fn op_create_workspace(inst: &mut RepoInstance, req: &Value) -> OpResult {
    let name = require_str(req, &["name"])?;
    let base_ref = req_str(req, &["baseRef", "base_ref"])
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_BOOKMARK);
    let ws = inst
        .mcp
        .repo_mut()
        .create_workspace(name, base_ref)
        .map_err(InvokeEnvelope::from_gitx_error)?;
    Ok(json!({ "workspace": ws }))
}

fn op_list_workspaces(inst: &RepoInstance) -> OpResult {
    let workspaces = inst
        .mcp
        .repo()
        .list_workspaces()
        .map_err(InvokeEnvelope::from_gitx_error)?;
    Ok(json!({ "workspaces": workspaces }))
}

fn op_write_file(inst: &mut RepoInstance, req: &Value) -> OpResult {
    let ws = workspace_or_default(inst, req).to_string();
    let path = require_str(req, &["path"])?;
    let content = require_str(req, &["content"])?;
    let is_base64 =
        req_str(req, &["encoding"]).is_some_and(|enc| enc.eq_ignore_ascii_case("base64"));

    let bytes = if is_base64 {
        BASE64_STANDARD.decode(content).map_err(|e| {
            InvokeEnvelope::err("invalid_request", format!("invalid base64 content: {e}"))
        })?
    } else {
        content.as_bytes().to_vec()
    };

    let warnings = inst
        .mcp
        .repo_mut()
        .write_file(&ws, path, &bytes)
        .map_err(InvokeEnvelope::from_gitx_error)?;
    Ok(json!({
        "workspace": ws,
        "path": path,
        "bytesWritten": bytes.len(),
        "secretWarnings": warnings,
    }))
}

fn op_read_file(inst: &RepoInstance, req: &Value) -> OpResult {
    let target = req_str(req, &["rev"])
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| workspace_or_default(inst, req));
    let path = require_str(req, &["path"])?;
    let want_base64 =
        req_str(req, &["encoding"]).is_some_and(|enc| enc.eq_ignore_ascii_case("base64"));

    let bytes = inst
        .mcp
        .repo()
        .read_file_at(target, path)
        .map_err(InvokeEnvelope::from_gitx_error)?;

    if want_base64 {
        Ok(json!({
            "workspace": target,
            "path": path,
            "size": bytes.len(),
            "encoding": "base64",
            "content": BASE64_STANDARD.encode(&bytes),
        }))
    } else {
        match String::from_utf8(bytes) {
            Ok(text) => Ok(json!({
                "workspace": target,
                "path": path,
                "size": text.len(),
                "encoding": "utf8",
                "content": text,
            })),
            Err(err) => {
                let raw = err.into_bytes();
                Ok(json!({
                    "workspace": target,
                    "path": path,
                    "size": raw.len(),
                    "encoding": "base64",
                    "content": BASE64_STANDARD.encode(&raw),
                }))
            }
        }
    }
}

fn op_delete_file(inst: &mut RepoInstance, req: &Value) -> OpResult {
    let ws = workspace_or_default(inst, req).to_string();
    let path = require_str(req, &["path"])?;
    inst.mcp
        .repo_mut()
        .delete_file(&ws, path)
        .map_err(InvokeEnvelope::from_gitx_error)?;
    Ok(json!({
        "workspace": ws,
        "path": path,
        "deleted": true,
    }))
}

fn op_list_files(inst: &RepoInstance, req: &Value) -> OpResult {
    let target = req_str(req, &["rev"])
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| workspace_or_default(inst, req));
    let files = inst
        .mcp
        .repo()
        .list_files_at(target)
        .map_err(InvokeEnvelope::from_gitx_error)?;
    Ok(json!({
        "workspace": target,
        "files": files,
    }))
}

fn op_commit(inst: &mut RepoInstance, req: &Value) -> OpResult {
    let ws = workspace_or_default(inst, req).to_string();
    let message = require_str(req, &["message"])?;
    let agent = agent_or_default(inst, req);

    let context = match req_str(req, &["prompt"]) {
        Some(prompt) if !prompt.is_empty() => {
            let mut ctx = CommitContext::prompt(prompt);
            if let Some(vis) = req_str(req, &["visibility"]) {
                let domain = DomainId::new(vis).map_err(InvokeEnvelope::from_gitx_error)?;
                ctx = ctx.with_visibility(domain);
            }
            Some(ctx)
        }
        _ => None,
    };

    let outcome = inst
        .mcp
        .repo_mut()
        .commit(&ws, message, agent, context)
        .map_err(InvokeEnvelope::from_gitx_error)?;

    Ok(json!({
        "workspace": ws,
        "changesetId": outcome.changeset.id.to_hex(),
        "changeId": outcome.changeset.change_id.to_string(),
        "committer": outcome.changeset.committer,
        "description": outcome.changeset.description,
        "createdAt": outcome.changeset.created_at,
        "contextRecord": outcome.context_record,
        "secretWarnings": outcome.secret_warnings,
    }))
}

fn op_land(inst: &mut RepoInstance, req: &Value) -> OpResult {
    let ws = workspace_or_default(inst, req).to_string();
    let target = req_str(req, &["target"])
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_BOOKMARK);

    let outcome = inst
        .mcp
        .repo_mut()
        .land(&ws, target)
        .map_err(InvokeEnvelope::from_gitx_error)?;

    Ok(json!({
        "workspace": ws,
        "target": outcome.land_record.target,
        "landSeq": outcome.land_record.land_seq,
        "previousHead": outcome.land_record.previous_head.map(|h| h.to_hex()),
        "newHead": outcome.land_record.new_head.to_hex(),
        "changesetId": outcome.merged_changeset.id.to_hex(),
        "changeId": outcome.merged_changeset.change_id.to_string(),
        "autoMerged": outcome.auto_merged,
        "landedChanges": outcome
            .land_record
            .landed_changes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "conflictPaths": outcome.conflict_paths,
    }))
}

fn op_diff(inst: &RepoInstance, req: &Value) -> OpResult {
    let ws = workspace_or_default(inst, req);
    let base_ref = req_str(req, &["baseRef", "base_ref"]).filter(|s| !s.is_empty());
    let (diff, entries) = match base_ref {
        Some(base_ref) => (
            inst.mcp
                .repo()
                .diff_against(ws, base_ref)
                .map_err(InvokeEnvelope::from_gitx_error)?,
            inst.mcp
                .repo()
                .diff_entries_against(ws, base_ref)
                .map_err(InvokeEnvelope::from_gitx_error)?,
        ),
        None => (
            inst.mcp
                .repo()
                .diff(ws)
                .map_err(InvokeEnvelope::from_gitx_error)?,
            inst.mcp
                .repo()
                .diff_entries(ws)
                .map_err(InvokeEnvelope::from_gitx_error)?,
        ),
    };
    Ok(json!({
        "workspace": ws,
        "diff": diff,
        "entries": entries,
    }))
}

fn op_grep(inst: &RepoInstance, req: &Value) -> OpResult {
    let ws = workspace_or_default(inst, req);
    let query = require_str(req, &["query", "pattern"])?;
    let matches = inst
        .mcp
        .repo()
        .grep(ws, query)
        .map_err(InvokeEnvelope::from_gitx_error)?;
    Ok(json!({
        "workspace": ws,
        "query": query,
        "matches": matches,
    }))
}

fn op_log(inst: &RepoInstance, req: &Value) -> OpResult {
    let repo = inst.mcp.repo();
    let limit = req
        .get("limit")
        .and_then(Value::as_u64)
        .map(|n| (n as usize).clamp(1, 1000))
        .unwrap_or(50);

    let start_spec = req_str(req, &["rev"])
        .filter(|s| !s.is_empty())
        .or_else(|| req_str(req, &["workspace"]).filter(|s| !s.is_empty()))
        .unwrap_or(DEFAULT_BOOKMARK);

    let start_hash = resolve_start_hash(repo, start_spec)?;
    let Some(start_hash) = start_hash else {
        return Ok(json!({
            "rev": Value::Null,
            "commits": [],
        }));
    };

    let mut visited: HashSet<ObjectHash> = HashSet::new();
    let mut queue: VecDeque<ObjectHash> = VecDeque::new();
    let mut visible: Vec<ChangeSet> = Vec::new();
    queue.push_back(start_hash);

    while let Some(hash) = queue.pop_front() {
        if !visited.insert(hash) {
            continue;
        }
        let Ok(cs) = repo.get_changeset(hash) else {
            continue;
        };
        for &parent in &cs.parents {
            if !visited.contains(&parent) {
                queue.push_back(parent);
            }
        }
        if repo.acl().can_read_changeset(repo.principal(), &cs) {
            visible.push(cs);
        }
    }

    visible.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    visible.truncate(limit);

    let rev = visible.first().map(|c| c.id.to_hex());
    let commits: Vec<Value> = visible
        .into_iter()
        .map(|cs| {
            let filtered = repo.acl().filter_domain_trees(repo.principal(), &cs);
            let domains: Vec<String> = filtered.keys().map(ToString::to_string).collect();
            let visible_parents = visible_parent_hashes_wasm(repo, &cs);
            json!({
                "changesetId": cs.id.to_hex(),
                "changeId": cs.change_id.to_string(),
                "publicProjectionHash": cs.public_projection_hash.to_hex(),
                "parents": visible_parents.iter().map(ObjectHash::to_hex).collect::<Vec<_>>(),
                "author": cs.author,
                "committer": cs.committer,
                "description": cs.description,
                "createdAt": cs.created_at,
                "visibilityDomain": cs.visibility.primary_domain.to_string(),
                "domains": domains,
                "hasConflicts": cs.has_conflicts,
            })
        })
        .collect();

    Ok(json!({
        "rev": rev,
        "commits": commits,
    }))
}

fn visible_parent_hashes_wasm(repo: &AgentRepo, cs: &ChangeSet) -> Vec<ObjectHash> {
    let mut out = Vec::new();
    for &parent in &cs.parents {
        let mut visited = HashSet::new();
        let mut q = VecDeque::new();
        q.push_back(parent);
        while let Some(h) = q.pop_front() {
            if !visited.insert(h) {
                continue;
            }
            let Ok(p_cs) = repo.get_changeset(h) else {
                continue;
            };
            if repo.acl().can_read_changeset(repo.principal(), &p_cs) {
                if !out.contains(&p_cs.id) {
                    out.push(p_cs.id);
                }
                break;
            }
            for &gp in &p_cs.parents {
                if !visited.contains(&gp) {
                    q.push_back(gp);
                }
            }
        }
    }
    out
}

fn op_record_context(inst: &RepoInstance, req: &Value) -> OpResult {
    let repo = inst.mcp.repo();
    let rev_spec = req_str(req, &["rev"])
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| workspace_or_default(inst, req));

    let cs_hash = resolve_start_hash(repo, rev_spec)?.ok_or_else(|| {
        InvokeEnvelope::err("not_found", format!("revision '{rev_spec}' not found"))
    })?;
    let cs = repo
        .get_changeset(cs_hash)
        .map_err(InvokeEnvelope::from_gitx_error)?;

    let visibility = match req_str(req, &["visibility"]) {
        Some(v) if !v.is_empty() => DomainId::new(v).map_err(InvokeEnvelope::from_gitx_error)?,
        _ => DomainId::public(),
    };

    if !repo.acl().can_write_domain(repo.principal(), &visibility) {
        return Err(InvokeEnvelope::err(
            "access_denied",
            format!(
                "principal '{}' lacks write permission for domain '{}'",
                repo.principal().id,
                visibility
            ),
        ));
    }

    let agent = agent_or_default(inst, req);
    let kind_name = req_str(req, &["kind"]).unwrap_or("prompt");
    let kind = match kind_name {
        "prompt" => {
            let prompt = require_str(req, &["prompt"])?;
            ContextKind::Prompt {
                prompt: prompt.to_string(),
                model: agent.model.clone(),
                harness: agent.harness.clone(),
                session_id: agent.session_id.clone(),
            }
        }
        "design_decision" | "designDecision" => {
            let title = require_str(req, &["title"])?;
            let rationale = require_str(req, &["rationale", "prompt"])?;
            ContextKind::DesignDecision {
                title: title.to_string(),
                rationale: rationale.to_string(),
            }
        }
        "agent_trace" | "agentTrace" => {
            let summary = require_str(req, &["summary", "prompt"])?;
            let tool_calls = req
                .get("toolCalls")
                .or_else(|| req.get("tool_calls"))
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            ContextKind::AgentTrace {
                summary: summary.to_string(),
                tool_calls,
                session_id: agent.session_id.clone(),
            }
        }
        other => {
            return Err(InvokeEnvelope::err(
                "invalid_request",
                format!("unsupported context kind '{other}'"),
            ));
        }
    };

    let mut anchors = Vec::new();
    if let Some(path) = req_str(req, &["path"]).filter(|s| !s.is_empty()) {
        let bytes = repo
            .read_file_at(rev_spec, path)
            .map_err(InvokeEnvelope::from_gitx_error)?;
        let content = String::from_utf8_lossy(&bytes);
        let total_lines = content.lines().count().max(1) as u32;
        let line_start = req
            .get("lineStart")
            .or_else(|| req.get("line_start"))
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|&n| n >= 1)
            .unwrap_or(1);
        let line_end = req
            .get("lineEnd")
            .or_else(|| req.get("line_end"))
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|&n| n >= line_start)
            .unwrap_or(total_lines);

        anchors.push(CodeAnchor::from_file_lines(
            path, &content, line_start, line_end,
        ));
    }

    let rec = ContextRecord {
        id: ContextId::new(),
        change_id: cs.change_id,
        revision: cs.id,
        visibility,
        author: agent.into_actor(repo.author().clone()),
        kind,
        anchors,
        created_at: Utc::now(),
    };
    repo.context()
        .add_record(&rec)
        .map_err(InvokeEnvelope::from_gitx_error)?;

    Ok(json!({ "record": rec }))
}

fn op_why(inst: &RepoInstance, req: &Value) -> OpResult {
    let target = req_str(req, &["rev"])
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| workspace_or_default(inst, req));
    let path = require_str(req, &["path"])?;
    let line = req
        .get("line")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|&n| n >= 1)
        .ok_or_else(|| {
            InvokeEnvelope::err(
                "invalid_request",
                "missing or invalid 1-based integer field 'line'",
            )
        })?;

    let matches = inst
        .mcp
        .repo()
        .why(target, path, line)
        .map_err(InvokeEnvelope::from_gitx_error)?;

    Ok(json!({
        "workspace": target,
        "path": path,
        "line": line,
        "matches": matches,
    }))
}

fn op_checkpoint(inst: &mut RepoInstance, req: &Value) -> OpResult {
    let ws = workspace_or_default(inst, req).to_string();
    let summary = req_str(req, &["promptSummary", "prompt_summary", "summary"]).unwrap_or("");
    let agent = agent_or_default(inst, req);
    let cp = inst
        .mcp
        .repo_mut()
        .save_checkpoint(&ws, agent, summary)
        .map_err(InvokeEnvelope::from_gitx_error)?;
    Ok(json!({ "checkpoint": cp }))
}

fn op_list_checkpoints(inst: &RepoInstance, req: &Value) -> OpResult {
    let ws = workspace_or_default(inst, req);
    let limit = req
        .get("limit")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(50);
    let checkpoints = inst
        .mcp
        .repo()
        .list_checkpoints(ws, limit)
        .map_err(InvokeEnvelope::from_gitx_error)?;
    Ok(json!({
        "workspace": ws,
        "checkpoints": checkpoints,
    }))
}

fn op_undo_checkpoint(inst: &mut RepoInstance, req: &Value) -> OpResult {
    let ws = workspace_or_default(inst, req).to_string();
    let cp_id = match req_str(req, &["checkpointId", "checkpoint_id"]) {
        Some(raw) if !raw.is_empty() => {
            let parsed = Ulid::from_string(raw).map_err(|e| {
                InvokeEnvelope::err(
                    "invalid_request",
                    format!("invalid checkpointId '{raw}': {e}"),
                )
            })?;
            Some(parsed)
        }
        _ => None,
    };

    let outcome = inst
        .mcp
        .repo_mut()
        .undo_checkpoint(&ws, cp_id)
        .map_err(InvokeEnvelope::from_gitx_error)?;

    Ok(json!({
        "workspace": ws,
        "revertedCheckpoint": outcome.reverted_checkpoint,
        "restoredToCheckpoint": outcome.restored_to_checkpoint.map(|u| u.to_string()),
        "cleanPaths": outcome.clean_paths,
        "conflictPaths": outcome.conflict_paths,
    }))
}

fn op_scan_secrets(inst: &RepoInstance, req: &Value) -> OpResult {
    if let Some(content) = req_str(req, &["content"]) {
        let path = req_str(req, &["path"]).unwrap_or("inline.txt");
        let findings = scan_content(path, content.as_bytes());
        return Ok(json!({
            "path": path,
            "hasSecrets": !findings.is_empty(),
            "findings": findings,
        }));
    }

    let ws = workspace_or_default(inst, req);
    let path = req_str(req, &["path"]);
    let findings = inst
        .mcp
        .repo()
        .scan_secrets(ws, path)
        .map_err(InvokeEnvelope::from_gitx_error)?;
    Ok(json!({
        "workspace": ws,
        "path": path,
        "hasSecrets": !findings.is_empty(),
        "findings": findings,
    }))
}

fn op_set_acl(inst: &mut RepoInstance, req: &Value) -> OpResult {
    let policy_text = require_str(req, &["policy", "acl"])?;
    let policy = AclPolicy::parse(policy_text).map_err(InvokeEnvelope::from_gitx_error)?;
    inst.mcp.repo_mut().set_acl(policy);
    Ok(json!({ "applied": true }))
}

fn op_set_principal(inst: &mut RepoInstance, req: &Value) -> OpResult {
    let anonymous = req
        .get("anonymous")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let principal = if anonymous {
        Principal::anonymous()
    } else {
        let id = require_str(req, &["id", "user"])?;
        let mut p = Principal::user(id);
        if let Some(teams) = req.get("teams").and_then(Value::as_array) {
            let list: Vec<String> = teams
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect();
            if !list.is_empty() {
                p = p.with_teams(list);
            }
        }
        if let Some(roles) = req.get("roles").and_then(Value::as_array) {
            let list: Vec<String> = roles
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect();
            if !list.is_empty() {
                p = p.with_roles(list);
            }
        }
        if let Some(fp) = req_str(req, &["fingerprint"]) {
            p = p.with_fingerprint(fp);
        }
        p
    };

    inst.mcp.repo_mut().set_principal(principal.clone());
    Ok(json!({
        "principal": {
            "id": principal.id,
            "teams": principal.teams,
            "roles": principal.roles,
            "isAnonymous": principal.is_anonymous,
        }
    }))
}

fn op_mcp_call(inst: &mut RepoInstance, req: &Value) -> OpResult {
    let raw_line = match req.get("request") {
        Some(Value::String(s)) => s.clone(),
        Some(obj @ Value::Object(_)) => obj.to_string(),
        _ => {
            return Err(InvokeEnvelope::err(
                "invalid_request",
                "missing required 'request' object or JSON string for mcpCall",
            ));
        }
    };

    let response = match inst.mcp.handle_json_line(&raw_line) {
        Some(resp_str) => match serde_json::from_str::<Value>(&resp_str) {
            Ok(val) => val,
            Err(_) => Value::String(resp_str),
        },
        None => Value::Null,
    };

    Ok(json!({ "response": response }))
}

fn resolve_start_hash(repo: &AgentRepo, spec: &str) -> Result<Option<ObjectHash>, InvokeEnvelope> {
    let spec = spec.trim();
    if let Some(h) = repo
        .store()
        .get_bookmark(spec)
        .map_err(InvokeEnvelope::from_gitx_error)?
    {
        return Ok(Some(h));
    }
    if let Some(ws) = repo
        .store()
        .get_workspace(spec)
        .map_err(InvokeEnvelope::from_gitx_error)?
    {
        return Ok(Some(ws.head_changeset));
    }
    if let Ok(h) = ObjectHash::from_str(spec) {
        return Ok(repo.get_changeset(h).ok().map(|cs| cs.id));
    }
    let lower = spec.to_lowercase();
    let all = repo
        .store()
        .list_changesets()
        .map_err(InvokeEnvelope::from_gitx_error)?;
    for cs in all {
        if cs.id.to_hex().starts_with(&lower)
            || cs.change_id.to_string().starts_with(&lower)
            || cs.change_id.short() == lower
        {
            return Ok(Some(cs.id));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invoke(handle: u32, payload: Value) -> Value {
        let raw = invoke_json(handle, &payload.to_string());
        serde_json::from_str(&raw).expect("valid JSON envelope")
    }

    #[test]
    fn raw_linear_memory_abi_roundtrip() {
        let cfg = r#"{"authorName":"Wasm Tester","authorEmail":"wasm@gitx.local","principalId":"alice","teams":["core"]}"#;
        let cfg_ptr = gitx_alloc(cfg.len());
        assert!(!cfg_ptr.is_null());
        // SAFETY: `cfg_ptr` was just allocated for `cfg.len()` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(cfg.as_ptr(), cfg_ptr, cfg.len());
        }

        // SAFETY: `cfg_ptr` is valid for `cfg.len()` readable bytes.
        let handle = unsafe { gitx_create_repo(cfg_ptr, cfg.len()) };
        assert!(handle > 0);
        // SAFETY: `cfg_ptr` was allocated with `gitx_alloc(cfg.len())`.
        unsafe { gitx_dealloc(cfg_ptr, cfg.len()) };

        let req = r#"{"op":"listWorkspaces"}"#;
        let req_ptr = gitx_alloc(req.len());
        // SAFETY: `req_ptr` was allocated for `req.len()` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(req.as_ptr(), req_ptr, req.len());
        }

        let mut resp_ptr: *mut u8 = std::ptr::null_mut();
        let mut resp_len: usize = 0;
        // SAFETY: `req_ptr` is valid for `req.len()` readable bytes; out pointers are stack locals.
        let ok =
            unsafe { gitx_invoke_into(handle, req_ptr, req.len(), &mut resp_ptr, &mut resp_len) };
        // SAFETY: `req_ptr` was allocated with `gitx_alloc(req.len())`.
        unsafe { gitx_dealloc(req_ptr, req.len()) };

        assert_eq!(ok, 1);
        assert!(!resp_ptr.is_null() && resp_len > 0);
        // SAFETY: `gitx_invoke_into` returned a valid buffer of `resp_len` bytes.
        let resp_str = unsafe {
            let slice = slice::from_raw_parts(resp_ptr as *const u8, resp_len);
            std::str::from_utf8(slice).expect("valid utf8").to_string()
        };
        // SAFETY: Free the response buffer using the exact `(ptr, len)` returned by `gitx_invoke_into`.
        unsafe { gitx_dealloc(resp_ptr, resp_len) };

        assert_eq!(
            unpack_ptr_len(pack_ptr_len(0x0012_3456, 4096)),
            (0x0012_3456, 4096)
        );

        let parsed: Value = serde_json::from_str(&resp_str).expect("envelope JSON");
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["data"]["workspaces"].as_array().unwrap().len(), 1);
        assert_eq!(gitx_drop_repo(handle), 1);
        assert_eq!(gitx_drop_repo(handle), 0);
    }

    #[test]
    fn full_agent_workflow_merge_context_checkpoint_acl_and_mcp() {
        let acl = "secrets/** -> team:security allow=team:security\n";
        let handle = create_repo_from_json(
            &json!({
                "authorName": "Alice",
                "authorEmail": "alice@example.com",
                "principalId": "alice",
                "teams": ["security"],
                "acl": acl
            })
            .to_string(),
        )
        .expect("create repo");

        // Seed package.json and main.rs
        let seed_pkg = serde_json::to_string_pretty(&json!({
            "name": "wasm-demo",
            "dependencies": { "core": "^1.0.0" }
        }))
        .unwrap();
        assert_eq!(
            invoke(
                handle,
                json!({"op":"writeFile","path":"package.json","content": format!("{seed_pkg}\n")})
            )["ok"],
            true
        );
        assert_eq!(
            invoke(
                handle,
                json!({"op":"writeFile","path":"src/main.rs","content":"fn a() -> i32 { 1 }\n\nfn b() -> i32 { 2 }\n"})
            )["ok"],
            true
        );
        assert_eq!(
            invoke(
                handle,
                json!({"op":"writeFile","path":"secrets/vault.txt","content":"top-secret-key\n"})
            )["ok"],
            true
        );
        let c0 = invoke(handle, json!({"op":"commit","message":"Seed repo"}));
        assert_eq!(c0["ok"], true);
        let l0 = invoke(handle, json!({"op":"land","target":"master"}));
        assert_eq!(l0["ok"], true);
        assert_eq!(l0["data"]["landSeq"], 1);

        // Two concurrent workspaces edit disjoint keys in shared package.json
        assert_eq!(
            invoke(
                handle,
                json!({"op":"createWorkspace","name":"ws-a","baseRef":"master"})
            )["ok"],
            true
        );
        assert_eq!(
            invoke(
                handle,
                json!({"op":"createWorkspace","name":"ws-b","baseRef":"master"})
            )["ok"],
            true
        );

        let pkg_a = serde_json::to_string_pretty(&json!({
            "name": "wasm-demo",
            "dependencies": { "core": "^1.0.0", "alpha": "^2.0.0" }
        }))
        .unwrap();
        let pkg_b = serde_json::to_string_pretty(&json!({
            "name": "wasm-demo",
            "dependencies": { "core": "^1.0.0", "beta": "^3.0.0" }
        }))
        .unwrap();

        invoke(
            handle,
            json!({"op":"writeFile","workspace":"ws-a","path":"package.json","content":format!("{pkg_a}\n")}),
        );
        invoke(
            handle,
            json!({"op":"writeFile","workspace":"ws-b","path":"package.json","content":format!("{pkg_b}\n")}),
        );

        assert_eq!(
            invoke(
                handle,
                json!({"op":"commit","workspace":"ws-a","message":"Add alpha","prompt":"Install alpha dependency"})
            )["ok"],
            true
        );
        assert_eq!(
            invoke(
                handle,
                json!({"op":"commit","workspace":"ws-b","message":"Add beta","prompt":"Install beta dependency"})
            )["ok"],
            true
        );

        let la = invoke(
            handle,
            json!({"op":"land","workspace":"ws-a","target":"master"}),
        );
        assert_eq!(la["ok"], true);
        let lb = invoke(
            handle,
            json!({"op":"land","workspace":"ws-b","target":"master"}),
        );
        assert_eq!(lb["ok"], true);
        assert_eq!(lb["data"]["autoMerged"], true);

        let merged_pkg = invoke(
            handle,
            json!({"op":"readFile","rev":"master","path":"package.json"}),
        );
        assert_eq!(merged_pkg["ok"], true);
        let merged_json: Value =
            serde_json::from_str(merged_pkg["data"]["content"].as_str().unwrap()).unwrap();
        assert_eq!(merged_json["dependencies"]["alpha"], "^2.0.0");
        assert_eq!(merged_json["dependencies"]["beta"], "^3.0.0");

        // Record explicit context and query why
        let rec = invoke(
            handle,
            json!({
                "op": "recordContext",
                "rev": "master",
                "path": "src/main.rs",
                "lineStart": 1,
                "lineEnd": 1,
                "kind": "design_decision",
                "title": "Keep fn a pure",
                "rationale": "Deterministic execution in WASM"
            }),
        );
        assert_eq!(rec["ok"], true);

        let why_resp = invoke(
            handle,
            json!({"op":"why","rev":"master","path":"src/main.rs","line":1}),
        );
        assert_eq!(why_resp["ok"], true);
        assert_eq!(why_resp["data"]["matches"].as_array().unwrap().len(), 1);

        // Log
        let log_resp = invoke(handle, json!({"op":"log","rev":"master","limit":10}));
        assert_eq!(log_resp["ok"], true);
        assert!(log_resp["data"]["commits"].as_array().unwrap().len() >= 3);

        // Checkpoint & surgical undo preserving concurrent human edit
        invoke(
            handle,
            json!({"op":"createWorkspace","name":"ws-undo","baseRef":"master"}),
        );
        invoke(
            handle,
            json!({
                "op": "writeFile",
                "workspace": "ws-undo",
                "path": "src/main.rs",
                "content": "fn a() -> i32 { 999 }\n\nfn b() -> i32 { 2 }\n"
            }),
        );
        let cp = invoke(
            handle,
            json!({"op":"checkpoint","workspace":"ws-undo","promptSummary":"Agent changed a"}),
        );
        assert_eq!(cp["ok"], true);

        // Human concurrently edits fn b
        invoke(
            handle,
            json!({
                "op": "writeFile",
                "workspace": "ws-undo",
                "path": "src/main.rs",
                "content": "fn a() -> i32 { 999 }\n\nfn b() -> i32 { 42 }\n"
            }),
        );
        let undo = invoke(handle, json!({"op":"undoCheckpoint","workspace":"ws-undo"}));
        assert_eq!(undo["ok"], true);
        assert!(undo["data"]["conflictPaths"].as_array().unwrap().is_empty());

        let after_undo = invoke(
            handle,
            json!({"op":"readFile","workspace":"ws-undo","path":"src/main.rs"}),
        );
        let content = after_undo["data"]["content"].as_str().unwrap();
        assert!(content.contains("fn a() -> i32 { 1 }"));
        assert!(content.contains("fn b() -> i32 { 42 }"));

        // Direct MCP JSON-RPC dispatch on the same repo
        let mcp_init = invoke(
            handle,
            json!({
                "op": "mcpCall",
                "request": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                }
            }),
        );
        assert_eq!(mcp_init["ok"], true);
        assert!(
            mcp_init["data"]["response"]["result"]["tools"]
                .as_array()
                .unwrap()
                .len()
                >= 13
        );

        // Switch principal to unauthorized user and verify ACL blocks reading secrets/vault.txt
        let switched = invoke(
            handle,
            json!({"op":"setPrincipal","id":"bob","teams":["public"]}),
        );
        assert_eq!(switched["ok"], true);
        let denied = invoke(
            handle,
            json!({"op":"readFile","rev":"master","path":"secrets/vault.txt"}),
        );
        assert_eq!(denied["ok"], false);
        assert_eq!(denied["error"]["code"], "access_denied");

        assert!(drop_repo(handle));
    }
}
