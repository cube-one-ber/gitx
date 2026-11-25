use crate::repo::{DEFAULT_GITXACL, Repo};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use gitx_core::{
    Actor, ChangeSetBuilder, DomainId, DomainTree, EmbargoState, EntryKind, FileMode, Identity,
    ObjectHash, OpKind, VisibilityPolicy,
};
use gitx_server::{
    ActorAgentInput, BlameResponse, CommitResponse, DerivedStats, DiffResponse, GrepResponse,
    HEADER_FINGERPRINT, HEADER_ROLES, HEADER_TEAMS, HEADER_USER, LogEntry, LogResponse,
    RebaseResponse, SymbolsResponse, TreeFileEntry, TreeResponse,
};
use gitx_store::ObjectStore;
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub const REMOTES_FILE_NAME: &str = "remotes.toml";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemotesConfig {
    #[serde(default)]
    pub remotes: BTreeMap<String, RemoteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteConfig {
    pub url: String,
    pub owner: String,
    pub repo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pushed_head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pulled_head: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub remote_heads: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub synced_commits: BTreeMap<String, String>,
}

impl RemoteConfig {
    pub fn display_url(&self) -> String {
        format!(
            "{}/{}/{}",
            self.url.trim_end_matches('/'),
            self.owner,
            self.repo
        )
    }
}

/// Resolved remote target for HTTP API calls (either from `.gitx/remotes.toml` or direct `--url`).
#[derive(Debug, Clone)]
pub struct ResolvedRemote {
    pub name: Option<String>,
    pub base_url: String,
    pub owner: String,
    pub repo: String,
}

impl ResolvedRemote {
    pub fn api_url(&self, suffix: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        let suffix = suffix.trim_start_matches('/');
        format!("{base}/v1/repos/{}/{}/{suffix}", self.owner, self.repo)
    }

    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }
}

/// Parsed principal identity headers sent to `gitx-server`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthHeaders {
    pub user: Option<String>,
    pub teams: Vec<String>,
    pub roles: Vec<String>,
    pub fingerprint: Option<String>,
    pub raw_token: Option<String>,
}

impl AuthHeaders {
    pub fn is_anonymous(&self) -> bool {
        self.user.as_deref().is_none_or(|u| u.trim().is_empty())
    }

    pub fn from_repo_author(author: &Identity) -> Self {
        Self {
            user: Some(author.name.clone()),
            teams: Vec::new(),
            roles: Vec::new(),
            fingerprint: author.key_fingerprint.clone(),
            raw_token: None,
        }
    }

    pub fn apply(&self, mut req: RequestBuilder) -> RequestBuilder {
        if let Some(ref user) = self.user
            && !user.is_empty()
        {
            req = req.header(HEADER_USER, user);
        }
        if !self.teams.is_empty() {
            req = req.header(HEADER_TEAMS, self.teams.join(","));
        }
        if !self.roles.is_empty() {
            req = req.header(HEADER_ROLES, self.roles.join(","));
        }
        if let Some(ref fp) = self.fingerprint
            && !fp.is_empty()
        {
            req = req.header(HEADER_FINGERPRINT, fp);
        }
        if let Some(ref tok) = self.raw_token
            && !tok.is_empty()
        {
            req = req.header("Authorization", format!("Bearer {tok}"));
        }
        req
    }
}

/// Parse a CLI `--token` string into `gitx-server` authentication headers.
///
/// Supported formats:
/// - `""` / `"anonymous"` / `"anon"`: anonymous principal (public read-only)
/// - Key-value claims: `"user=alice;teams=core,security;roles=admin;fp=abc"`
/// - ACL subject list: `"user:alice,team:core,role:admin"`
/// - Bare username/token: `"alice"` -> `X-Gitx-User: alice` + `Authorization: Bearer alice`
pub fn parse_token_headers(raw: &str) -> AuthHeaders {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("anonymous")
        || trimmed.eq_ignore_ascii_case("anon")
    {
        return AuthHeaders::default();
    }

    if trimmed.starts_with("gitx1h.") || trimmed.starts_with("gitx1e.") {
        return AuthHeaders {
            user: None,
            teams: Vec::new(),
            roles: Vec::new(),
            fingerprint: None,
            raw_token: Some(trimmed.to_string()),
        };
    }

    if trimmed.contains('=') {
        let mut headers = AuthHeaders::default();
        for segment in trimmed.split([';', '&']) {
            let seg = segment.trim();
            if seg.is_empty() {
                continue;
            }
            if let Some((k, v)) = seg.split_once('=') {
                let key = k.trim().to_ascii_lowercase();
                let val = v.trim();
                if val.is_empty() {
                    continue;
                }
                match key.as_str() {
                    "user" | "u" | "id" => headers.user = Some(val.to_string()),
                    "team" | "teams" | "t" => {
                        for item in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                            if !headers.teams.iter().any(|existing| existing == item) {
                                headers.teams.push(item.to_string());
                            }
                        }
                    }
                    "role" | "roles" | "r" => {
                        for item in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                            if !headers.roles.iter().any(|existing| existing == item) {
                                headers.roles.push(item.to_string());
                            }
                        }
                    }
                    "fp" | "fingerprint" | "key" => {
                        headers.fingerprint = Some(val.to_string());
                    }
                    _ => {}
                }
            }
        }
        return headers;
    }

    if trimmed.starts_with("user:")
        || trimmed.starts_with("team:")
        || trimmed.starts_with("role:")
        || trimmed.starts_with("fp:")
        || trimmed.starts_with("key:")
    {
        let mut headers = AuthHeaders::default();
        for segment in trimmed.split([';', ',']) {
            let seg = segment.trim();
            if let Some(u) = seg.strip_prefix("user:") {
                if !u.is_empty() {
                    headers.user = Some(u.to_string());
                }
            } else if let Some(t) = seg.strip_prefix("team:") {
                if !t.is_empty() && !headers.teams.iter().any(|x| x == t) {
                    headers.teams.push(t.to_string());
                }
            } else if let Some(r) = seg.strip_prefix("role:") {
                if !r.is_empty() && !headers.roles.iter().any(|x| x == r) {
                    headers.roles.push(r.to_string());
                }
            } else if let Some(fp) = seg.strip_prefix("fp:").or_else(|| seg.strip_prefix("key:"))
                && !fp.is_empty()
            {
                headers.fingerprint = Some(fp.to_string());
            }
        }
        return headers;
    }

    AuthHeaders {
        user: Some(trimmed.to_string()),
        teams: Vec::new(),
        roles: Vec::new(),
        fingerprint: None,
        raw_token: Some(trimmed.to_string()),
    }
}

/// Resolve auth headers from an explicit `--token`, remote config `token`, `GITX_TOKEN`,
/// or (for write operations only) an optional fallback identity.
pub fn resolve_auth_headers(
    explicit_token: Option<&str>,
    remote_token: Option<&str>,
    fallback_author: Option<&Identity>,
) -> AuthHeaders {
    if let Some(tok) = explicit_token {
        return parse_token_headers(tok);
    }
    if let Some(tok) = remote_token {
        return parse_token_headers(tok);
    }
    if let Ok(env_tok) = env::var("GITX_TOKEN")
        && !env_tok.trim().is_empty()
    {
        return parse_token_headers(&env_tok);
    }
    if let Some(author) = fallback_author {
        return AuthHeaders::from_repo_author(author);
    }
    AuthHeaders::default()
}

/// Parse a remote URL such as `http://127.0.0.1:7878/owner/repo` (or `http://host:port`
/// combined with explicit `--owner` / `--repo`) into `(base_url, owner, repo)`.
pub fn parse_remote_url(
    raw_url: &str,
    owner_override: Option<&str>,
    repo_override: Option<&str>,
) -> Result<(String, String, String)> {
    let trimmed = raw_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("remote URL must not be empty");
    }

    let Some(scheme_idx) = trimmed.find("://") else {
        bail!("invalid remote URL '{raw_url}': expected scheme such as http:// or https://");
    };
    let after_scheme = scheme_idx + 3;
    let authority_end = trimmed[after_scheme..]
        .find('/')
        .map(|rel| after_scheme + rel)
        .unwrap_or(trimmed.len());

    let origin = &trimmed[..authority_end];
    if origin.len() <= after_scheme {
        bail!("invalid remote URL '{raw_url}': missing host");
    }

    let path_part = trimmed[authority_end..].trim_matches('/');
    let mut segments: Vec<&str> = if path_part.is_empty() {
        Vec::new()
    } else {
        path_part.split('/').filter(|s| !s.is_empty()).collect()
    };

    // Strip optional `/v1/repos` API prefix if caller pasted an API endpoint URL.
    let mut prefix_segments: Vec<&str> = Vec::new();
    let (parsed_owner, parsed_repo) = if segments.len() >= 2 {
        let repo_raw = segments.pop().unwrap();
        let owner_raw = segments.pop().unwrap();
        let repo_clean = repo_raw.strip_suffix(".git").unwrap_or(repo_raw);
        if segments.as_slice() == ["v1", "repos"] {
            segments.clear();
        }
        prefix_segments.extend(segments);
        (Some(owner_raw.to_string()), Some(repo_clean.to_string()))
    } else {
        prefix_segments.extend(segments);
        (None, None)
    };

    let owner = owner_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or(parsed_owner)
        .ok_or_else(|| {
            anyhow!(
                "could not infer owner from URL '{raw_url}'; pass --owner and --repo or use http://host:port/<owner>/<repo>"
            )
        })?;

    let repo = repo_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.strip_suffix(".git").unwrap_or(s).to_string())
        .or(parsed_repo)
        .ok_or_else(|| {
            anyhow!(
                "could not infer repository name from URL '{raw_url}'; pass --owner and --repo or use http://host:port/<owner>/<repo>"
            )
        })?;

    let base_url = if prefix_segments.is_empty() {
        origin.to_string()
    } else {
        format!("{origin}/{}", prefix_segments.join("/"))
    };

    Ok((base_url, owner, repo))
}

pub fn remotes_file_path(gitx_dir: &Path) -> PathBuf {
    gitx_dir.join(REMOTES_FILE_NAME)
}

pub fn load_remotes(gitx_dir: &Path) -> Result<RemotesConfig> {
    let path = remotes_file_path(gitx_dir);
    if !path.is_file() {
        return Ok(RemotesConfig::default());
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn save_remotes(gitx_dir: &Path, cfg: &RemotesConfig) -> Result<()> {
    let path = remotes_file_path(gitx_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(cfg)?;
    fs::write(&path, content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Select a named remote (or default to `"origin"`, or the sole configured remote).
pub fn select_remote_entry<'a>(
    cfg: &'a RemotesConfig,
    remote_name: Option<&str>,
) -> Result<(String, &'a RemoteConfig)> {
    if let Some(name) = remote_name {
        let entry = cfg
            .remotes
            .get(name)
            .ok_or_else(|| anyhow!("remote '{name}' is not configured"))?;
        return Ok((name.to_string(), entry));
    }

    if let Some(origin) = cfg.remotes.get("origin") {
        return Ok(("origin".to_string(), origin));
    }

    if cfg.remotes.len() == 1 {
        let (name, entry) = cfg.remotes.iter().next().expect("len == 1");
        return Ok((name.clone(), entry));
    }

    if cfg.remotes.is_empty() {
        bail!("no remotes configured (run `gitx remote add origin <url>` first)");
    }

    let names: Vec<&str> = cfg.remotes.keys().map(String::as_str).collect();
    bail!(
        "multiple remotes configured ({}) and no 'origin'; specify a remote name",
        names.join(", ")
    );
}

/// Resolve a remote endpoint for zero-clone RPC / queue commands.
/// Works without a local `.gitx` repository when `--url` is provided.
pub fn resolve_rpc_target(
    remote_name: Option<&str>,
    direct_url: Option<&str>,
    token: Option<&str>,
) -> Result<(ResolvedRemote, AuthHeaders)> {
    if let Some(url) = direct_url {
        let (base_url, owner, repo) = parse_remote_url(url, None, None)?;
        let resolved = ResolvedRemote {
            name: None,
            base_url,
            owner,
            repo,
        };
        let auth = resolve_auth_headers(token, None, None);
        return Ok((resolved, auth));
    }

    let cwd = env::current_dir()?;
    let repo = Repo::open(&cwd).context(
        "no --url specified and not inside a gitx repository; pass --url http://host:port/owner/repo or run inside a gitx repo",
    )?;
    let cfg = load_remotes(&repo.gitx_dir)?;
    let (name, entry) = select_remote_entry(&cfg, remote_name)?;
    let auth = resolve_auth_headers(token, entry.token.as_deref(), None);
    let resolved = ResolvedRemote {
        name: Some(name),
        base_url: entry.url.clone(),
        owner: entry.owner.clone(),
        repo: entry.repo.clone(),
    };
    Ok((resolved, auth))
}

pub fn run_async<F, T>(future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to initialize async runtime")?;
    rt.block_on(future)
}

pub fn build_http_client() -> Result<Client> {
    Client::builder()
        .build()
        .context("failed to build HTTP client")
}

pub async fn parse_json_response<T: for<'de> Deserialize<'de>>(
    resp: reqwest::Response,
    action: &str,
) -> Result<T> {
    let status = resp.status();
    let body_bytes = resp
        .bytes()
        .await
        .with_context(|| format!("failed to read HTTP response for {action}"))?;

    if !status.is_success() {
        let msg = extract_server_error(&body_bytes);
        bail!("{action} failed (HTTP {}): {msg}", status.as_u16());
    }

    serde_json::from_slice(&body_bytes)
        .with_context(|| format!("failed to decode JSON response for {action}"))
}

pub fn extract_server_error(body: &[u8]) -> String {
    if let Ok(val) = serde_json::from_slice::<Value>(body)
        && let Some(err) = val.get("error").and_then(Value::as_str)
    {
        if let Some(code) = val.get("code").and_then(Value::as_str) {
            return format!("[{code}] {err}");
        }
        return err.to_string();
    }
    let text = String::from_utf8_lossy(body).trim().to_string();
    if text.is_empty() {
        "empty error response".to_string()
    } else {
        text
    }
}

pub fn decode_tree_file_bytes(entry: &TreeFileEntry) -> Result<Vec<u8>> {
    if let Some(ref b64) = entry.content_base64 {
        return BASE64_STANDARD
            .decode(b64)
            .with_context(|| format!("invalid base64 payload for '{}'", entry.path));
    }
    if let Some(ref text) = entry.content {
        return Ok(text.as_bytes().to_vec());
    }
    Ok(Vec::new())
}

/// Collect all pushable `EntryKind::File` blobs across all non-secret domain trees of a ChangeSet.
pub fn collect_pushable_files(
    repo: &Repo,
    cs: &gitx_core::ChangeSet,
) -> Result<(BTreeMap<String, Vec<u8>>, bool)> {
    let mut files = BTreeMap::new();
    for (domain, &tree_hash) in &cs.domain_trees {
        if domain.is_secret() {
            continue;
        }
        let tree = repo.store.get_tree(tree_hash)?;
        for (path, kind) in &tree.entries {
            if let EntryKind::File { blob_hash, .. } = kind {
                let bytes = repo.store.read_blob_bytes(*blob_hash)?;
                files.insert(path.clone(), bytes);
            }
        }
    }

    let is_default_acl = files
        .get(".gitxacl")
        .is_some_and(|b| b.as_slice() == DEFAULT_GITXACL.as_bytes());
    Ok((files, is_default_acl))
}

/// Collect all already-envelope-encrypted `EntryKind::EncryptedSecret` JSON payloads across
/// `secret:*` domain trees so `gitx push` syncs `.env` and secrets end-to-end encrypted
/// (zero plaintext ever leaves the client).
pub fn collect_pushable_secrets(
    repo: &Repo,
    cs: &gitx_core::ChangeSet,
) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (domain, &tree_hash) in &cs.domain_trees {
        if !domain.is_secret() {
            continue;
        }
        let tree = repo.store.get_tree(tree_hash)?;
        for (path, kind) in &tree.entries {
            if let EntryKind::EncryptedSecret { envelope_hash, .. } = kind {
                let raw = repo.store.get_raw_object(*envelope_hash)?;
                let env_json = String::from_utf8(raw).with_context(|| {
                    format!("stored secret envelope for '{path}' in '{domain}' is not valid UTF-8")
                })?;
                out.entry(domain.to_string())
                    .or_default()
                    .insert(path.clone(), env_json);
            }
        }
    }
    Ok(out)
}

/// Fetch a remote tree if the repository/revision exists; returns `Ok(None)` on 404.
pub async fn fetch_remote_tree_optional(
    client: &Client,
    remote: &ResolvedRemote,
    auth: &AuthHeaders,
    rev: Option<&str>,
) -> Result<Option<TreeResponse>> {
    let mut req = auth.apply(client.get(remote.api_url("tree")));
    if let Some(r) = rev {
        req = req.query(&[("rev", r)]);
    }
    let resp = req
        .send()
        .await
        .with_context(|| format!("failed to contact remote {}", remote.base_url))?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let tree: TreeResponse = parse_json_response(resp, "fetch remote tree").await?;
    Ok(Some(tree))
}

/// Build the base64 `files` and `delete_files` delta comparing `local_files` against `remote_files`.
pub fn build_push_delta(
    local_files: &BTreeMap<String, Vec<u8>>,
    is_default_acl: bool,
    remote_files: &BTreeMap<String, Vec<u8>>,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut upload = BTreeMap::new();
    for (path, bytes) in local_files {
        if path == ".gitxacl" && is_default_acl && !remote_files.contains_key(".gitxacl") {
            continue;
        }
        if remote_files.get(path) != Some(bytes) {
            upload.insert(path.clone(), BASE64_STANDARD.encode(bytes));
        }
    }

    let mut deletions = Vec::new();
    for rpath in remote_files.keys() {
        if !local_files.contains_key(rpath) {
            deletions.push(rpath.clone());
        }
    }
    (upload, deletions)
}

/// Build JSON payload for `POST /v1/repos/{owner}/{repo}/commit`.
#[allow(clippy::too_many_arguments)]
pub fn build_commit_payload(
    cs: &gitx_core::ChangeSet,
    files: &BTreeMap<String, String>,
    delete_files: &[String],
    message: &str,
    target: &str,
    parent: Option<&str>,
    update_target: bool,
) -> Value {
    let actor_agent = match &cs.committer {
        Actor::Agent {
            harness,
            model,
            session_id,
            ..
        } => Some(ActorAgentInput {
            harness: harness.clone(),
            model: model.clone(),
            session_id: session_id.clone(),
        }),
        Actor::Human(_) => None,
    };

    let (visibility_domain, embargo_advisory, embargo_allowed_teams) = match &cs.visibility.embargo
    {
        Some(EmbargoState::Active {
            advisory_id,
            allowed_domains,
            ..
        }) => (
            None,
            Some(advisory_id.clone()),
            allowed_domains
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        ),
        _ if !cs.visibility.primary_domain.is_public() => (
            Some(cs.visibility.primary_domain.to_string()),
            None,
            Vec::new(),
        ),
        _ => (None, None, Vec::new()),
    };

    let mut payload = json!({
        "files": files,
        "delete_files": delete_files,
        "encoding": "base64",
        "message": message,
        "author_name": cs.author.name,
        "author_email": cs.author.email,
        "target": target,
        "update_target": update_target,
    });

    if let Some(map) = payload.as_object_mut() {
        if let Some(agent) = actor_agent {
            map.insert("actor_agent".to_string(), json!(agent));
        }
        if let Some(p) = parent {
            map.insert("parent".to_string(), json!(p));
        }
        if let Some(dom) = visibility_domain {
            map.insert("visibility_domain".to_string(), json!(dom));
        }
        if let Some(adv) = embargo_advisory {
            map.insert("embargo_advisory".to_string(), json!(adv));
        }
        if !embargo_allowed_teams.is_empty() {
            map.insert(
                "embargo_allowed_teams".to_string(),
                json!(embargo_allowed_teams),
            );
        }
    }

    payload
}

// ---------------------------------------------------------------------------
// Remote Configuration Commands (`remote add/list/show/rm`)
// ---------------------------------------------------------------------------

pub fn cmd_remote_add(
    name: String,
    url: String,
    owner: Option<String>,
    repo_name: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let trimmed_name = name.trim();
    if trimmed_name.is_empty()
        || !trimmed_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("invalid remote name '{name}'");
    }

    let (base_url, parsed_owner, parsed_repo) =
        parse_remote_url(&url, owner.as_deref(), repo_name.as_deref())?;

    let repo = Repo::open(&env::current_dir()?)?;
    let mut cfg = load_remotes(&repo.gitx_dir)?;
    if cfg.remotes.contains_key(trimmed_name) {
        bail!(
            "remote '{trimmed_name}' already exists (run `gitx remote rm {trimmed_name}` to replace it)"
        );
    }

    let entry = RemoteConfig {
        url: base_url,
        owner: parsed_owner,
        repo: parsed_repo,
        token: token.filter(|t| !t.trim().is_empty()),
        last_pushed_head: None,
        last_pulled_head: None,
        remote_heads: BTreeMap::new(),
        synced_commits: BTreeMap::new(),
    };
    let display = entry.display_url();
    let has_token = entry.token.is_some();
    cfg.remotes.insert(trimmed_name.to_string(), entry);
    save_remotes(&repo.gitx_dir, &cfg)?;

    println!("Added remote '{trimmed_name}' -> {display}");
    if has_token {
        println!("  auth: token configured");
    }
    Ok(())
}

pub fn cmd_remote_list() -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let cfg = load_remotes(&repo.gitx_dir)?;
    if cfg.remotes.is_empty() {
        println!("No remotes configured.");
        return Ok(());
    }

    for (name, entry) in &cfg.remotes {
        let auth_tag = if entry.token.is_some() {
            " [token]"
        } else {
            ""
        };
        println!(
            "{name}\t{} (owner={}, repo={}){auth_tag}",
            entry.display_url(),
            entry.owner,
            entry.repo
        );
    }
    Ok(())
}

pub fn cmd_remote_show(name: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let cfg = load_remotes(&repo.gitx_dir)?;
    let entry = cfg
        .remotes
        .get(&name)
        .ok_or_else(|| anyhow!("remote '{name}' not found"))?;

    println!("Remote: {name}");
    println!("  URL:    {}", entry.url);
    println!("  Owner:  {}", entry.owner);
    println!("  Repo:   {}", entry.repo);
    println!("  Target: {}", entry.display_url());
    match &entry.token {
        Some(tok) => {
            let parsed = parse_token_headers(tok);
            let summary = match parsed.user {
                Some(ref u) if !parsed.teams.is_empty() => {
                    format!("configured (user={u}, teams={})", parsed.teams.join(","))
                }
                Some(ref u) => format!("configured (user={u})"),
                None => "configured (anonymous)".to_string(),
            };
            println!("  Token:  {summary}");
        }
        None => println!("  Token:  (none)"),
    }
    if let Some(ref pushed) = entry.last_pushed_head {
        println!("  Last pushed: {}", short_hex(pushed));
    }
    if let Some(ref pulled) = entry.last_pulled_head {
        println!("  Last pulled: {}", short_hex(pulled));
    }
    if !entry.remote_heads.is_empty() {
        println!("  Tracked heads:");
        for (bm, hash) in &entry.remote_heads {
            println!("    {bm}: {}", short_hex(hash));
        }
    }
    Ok(())
}

pub fn cmd_remote_rm(name: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let mut cfg = load_remotes(&repo.gitx_dir)?;
    if cfg.remotes.remove(&name).is_none() {
        bail!("remote '{name}' not found");
    }
    save_remotes(&repo.gitx_dir, &cfg)?;
    println!("Removed remote '{name}'");
    Ok(())
}

// ---------------------------------------------------------------------------
// Push & Pull Commands
// ---------------------------------------------------------------------------

pub fn cmd_push(
    remote: Option<String>,
    target: Option<String>,
    message: Option<String>,
    token: Option<String>,
    allow_conflicts: bool,
) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let cs = snap.changeset;

    let target_bm = target.unwrap_or_else(|| repo.config.default_branch.clone());

    if cs.has_conflicts {
        if !allow_conflicts {
            bail!(
                "cannot push ChangeSet {} while it contains unresolved conflicts (pass --allow-conflicts on a non-trunk branch to share WIP conflicts)",
                cs.change_id.short()
            );
        }
        if target_bm == repo.config.default_branch {
            bail!(
                "refusing to push unresolved conflicts directly to trunk '{}' even with --allow-conflicts; specify a WIP --target branch",
                target_bm
            );
        }
    }

    let mut cfg = load_remotes(&repo.gitx_dir)?;
    // Support zero-ceremony push-to-create directly to an http(s):// URL without `remote add` first!
    let (remote_name_opt, resolved, auth) = match remote.as_deref() {
        Some(spec) if spec.starts_with("http://") || spec.starts_with("https://") => {
            let (base_url, owner, repo_name) = parse_remote_url(spec, None, None)?;
            let resolved = ResolvedRemote {
                name: None,
                base_url,
                owner,
                repo: repo_name,
            };
            let auth = resolve_auth_headers(token.as_deref(), None, Some(&repo.config.author));
            (None, resolved, auth)
        }
        other => {
            let (n, e) = select_remote_entry(&cfg, other)?;
            let e = e.clone();
            let auth = resolve_auth_headers(
                token.as_deref(),
                e.token.as_deref(),
                Some(&repo.config.author),
            );
            let resolved = ResolvedRemote {
                name: Some(n.clone()),
                base_url: e.url.clone(),
                owner: e.owner.clone(),
                repo: e.repo.clone(),
            };
            (Some(n), resolved, auth)
        }
    };

    let (local_files, is_default_acl) = collect_pushable_files(&repo, &cs)?;
    let local_secrets = collect_pushable_secrets(&repo, &cs)?;

    let commit_msg = message
        .filter(|m| !m.trim().is_empty())
        .or_else(|| {
            if !cs.description.trim().is_empty() {
                Some(cs.description.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| format!("Push {} to {target_bm}", cs.change_id.short()));

    let outcome = run_async(async {
        let client = build_http_client()?;

        let remote_tree =
            fetch_remote_tree_optional(&client, &resolved, &auth, Some(&target_bm)).await?;
        let remote_head = remote_tree.as_ref().and_then(|t| t.rev.clone());
        let mut remote_files = BTreeMap::new();
        let mut remote_secret_hashes: BTreeMap<(String, String), String> = BTreeMap::new();
        if let Some(ref tree) = remote_tree {
            for entry in &tree.files {
                remote_files.insert(entry.path.clone(), decode_tree_file_bytes(entry)?);
            }
            for sec in &tree.secrets {
                remote_secret_hashes.insert(
                    (sec.domain.clone(), sec.path.clone()),
                    sec.envelope_hash.clone(),
                );
            }
        }

        let (mut upload, deletions) = build_push_delta(&local_files, is_default_acl, &remote_files);

        // Delta-filter encrypted secret envelopes so unchanged secrets don't force churn.
        let mut upload_secrets: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut secret_count = 0usize;
        for (dom, paths) in &local_secrets {
            for (path, env_json) in paths {
                let local_hash = serde_json::from_str::<gitx_crypto::SecretEnvelope>(env_json)
                    .ok()
                    .map(|e| e.hash().to_hex());
                let unchanged = local_hash.is_some()
                    && remote_secret_hashes.get(&(dom.clone(), path.clone()))
                        == local_hash.as_ref();
                if !unchanged {
                    upload_secrets
                        .entry(dom.clone())
                        .or_default()
                        .insert(path.clone(), env_json.clone());
                    secret_count += 1;
                }
            }
        }

        if upload.is_empty() && deletions.is_empty() && secret_count == 0 {
            if let Some(head) = remote_head {
                return Ok((None, Some(head), 0usize, 0usize, 0usize));
            }
            if let Some(acl_bytes) = local_files.get(".gitxacl") {
                upload.insert(".gitxacl".to_string(), BASE64_STANDARD.encode(acl_bytes));
            } else {
                bail!("nothing to push (working tree has no pushable files or secrets)");
            }
        }

        let uploaded_count = upload.len();
        let deleted_count = deletions.len();
        let mut payload = build_commit_payload(
            &cs,
            &upload,
            &deletions,
            &commit_msg,
            &target_bm,
            None,
            true,
        );
        if !upload_secrets.is_empty()
            && let Some(map) = payload.as_object_mut()
        {
            map.insert("secret_envelopes".to_string(), json!(upload_secrets));
        }

        let resp = auth
            .apply(client.post(resolved.api_url("commit")))
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("failed to push to {}", resolved.base_url))?;
        let committed: CommitResponse = parse_json_response(resp, "push commit").await?;
        Ok((
            Some(committed),
            None,
            uploaded_count,
            deleted_count,
            secret_count,
        ))
    })?;

    let remote_label = remote_name_opt
        .as_deref()
        .unwrap_or(resolved.base_url.as_str());

    match outcome {
        (None, Some(head), _, _, _) => {
            if let Some(ref rname) = remote_name_opt
                && let Some(entry) = cfg.remotes.get_mut(rname)
            {
                entry.last_pushed_head = Some(head.clone());
                entry.remote_heads.insert(target_bm.clone(), head.clone());
                save_remotes(&repo.gitx_dir, &cfg)?;
            }
            println!(
                "Already up to date with remote '{remote_label}' ({target_bm}: {}).",
                short_hex(&head)
            );
        }
        (Some(committed), _, uploaded_count, deleted_count, secret_count) => {
            if let Some(ref rname) = remote_name_opt
                && let Some(entry) = cfg.remotes.get_mut(rname)
            {
                entry.last_pushed_head = Some(committed.changeset_id.clone());
                entry
                    .remote_heads
                    .insert(target_bm.clone(), committed.changeset_id.clone());
                entry
                    .synced_commits
                    .insert(committed.changeset_id.clone(), cs.id.to_hex());
                save_remotes(&repo.gitx_dir, &cfg)?;
                let _ = repo
                    .store
                    .set_bookmark(&format!("{rname}/{target_bm}"), cs.id);
            }

            println!(
                "Pushed to '{remote_label}' ({} -> {target_bm}):",
                resolved.full_name()
            );
            println!("  changeset: {}", committed.changeset_id);
            println!("  change_id: {}", committed.change_id);
            println!("  domains:   {}", committed.domains_written.join(", "));
            println!(
                "  files:     +{uploaded_count} uploaded, -{deleted_count} deleted, +{secret_count} encrypted secret(s)"
            );
        }
        _ => unreachable!(),
    }

    Ok(())
}

pub fn cmd_pull(
    remote: Option<String>,
    target: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let local_head = snap.changeset;

    let mut cfg = load_remotes(&repo.gitx_dir)?;
    let (remote_name, remote_entry) = {
        let (n, e) = select_remote_entry(&cfg, remote.as_deref())?;
        (n, e.clone())
    };
    let target_bm = target.unwrap_or_else(|| repo.config.default_branch.clone());

    // Pull uses explicit token, stored remote token, or GITX_TOKEN — never escalates anonymously.
    let auth = resolve_auth_headers(token.as_deref(), remote_entry.token.as_deref(), None);
    let resolved = ResolvedRemote {
        name: Some(remote_name.clone()),
        base_url: remote_entry.url.clone(),
        owner: remote_entry.owner.clone(),
        repo: remote_entry.repo.clone(),
    };

    let existing_synced = remote_entry.synced_commits.clone();

    let (tip_tree, chronological_commits) = run_async(async {
        let client = build_http_client()?;

        let tree_resp = auth
            .apply(client.get(resolved.api_url("tree")))
            .query(&[("rev", target_bm.as_str())])
            .send()
            .await
            .with_context(|| format!("failed to contact remote {}", resolved.base_url))?;
        let tip_tree: TreeResponse = parse_json_response(tree_resp, "pull remote tree").await?;

        let log_resp = auth
            .apply(client.get(resolved.api_url("log")))
            .query(&[("rev", target_bm.as_str()), ("limit", "100")])
            .send()
            .await
            .with_context(|| format!("failed to fetch remote log from {}", resolved.base_url))?;
        let log: LogResponse = parse_json_response(log_resp, "pull remote log").await?;

        let mut commits = log.commits;
        commits.reverse();

        let tip_rev = tip_tree.rev.clone().or(log.rev.clone());
        let mut with_trees: Vec<(LogEntry, Option<TreeResponse>)> =
            Vec::with_capacity(commits.len());

        for entry in commits {
            let already_synced = existing_synced.contains_key(&entry.changeset_id);
            if already_synced {
                with_trees.push((entry, None));
                continue;
            }
            if tip_rev.as_deref() == Some(entry.changeset_id.as_str()) {
                with_trees.push((entry, Some(tip_tree.clone())));
            } else {
                let c_resp = auth
                    .apply(client.get(resolved.api_url("tree")))
                    .query(&[("rev", entry.changeset_id.as_str())])
                    .send()
                    .await
                    .with_context(|| {
                        format!(
                            "failed to fetch tree for commit {}",
                            short_hex(&entry.changeset_id)
                        )
                    })?;
                let c_tree: TreeResponse = parse_json_response(c_resp, "fetch commit tree").await?;
                with_trees.push((entry, Some(c_tree)));
            }
        }

        Ok((tip_tree, with_trees))
    })?;

    let Some(remote_tip_id) = tip_tree.rev.clone().or_else(|| {
        chronological_commits
            .last()
            .map(|(e, _)| e.changeset_id.clone())
    }) else {
        println!(
            "No visible commits on remote '{remote_name}' ({} @ {target_bm}) — repository may be empty or filtered by ACL.",
            resolved.full_name()
        );
        return Ok(());
    };

    let old_target_hash = repo.store.get_bookmark(&target_bm)?;
    let old_target_cs = old_target_hash
        .map(|h| repo.store.get_changeset(h))
        .transpose()?;

    // Read existing local `.gitxacl` bytes so pulling a remote that didn't commit `.gitxacl`
    // doesn't clobber the local `.gitxacl` file.
    let preserved_local_acl = {
        let p = repo.root.join(".gitxacl");
        if p.is_file() { fs::read(&p).ok() } else { None }
    };

    let mut synced_map = remote_entry.synced_commits.clone();
    let mut prev_local_hash = old_target_hash;
    let mut newly_imported = 0usize;
    let mut tip_local_cs: Option<gitx_core::ChangeSet> = None;

    if chronological_commits.is_empty() {
        let local_cs = import_tree_as_changeset(
            &repo,
            &tip_tree,
            prev_local_hash,
            Identity {
                name: "remote".to_string(),
                email: "remote@gitx.local".to_string(),
                key_fingerprint: None,
            },
            format!(
                "Pulled {remote_name}/{target_bm} ({})",
                short_hex(&remote_tip_id)
            ),
            "public",
            preserved_local_acl.as_deref(),
        )?;
        synced_map.insert(remote_tip_id.clone(), local_cs.id.to_hex());
        newly_imported += 1;
        tip_local_cs = Some(local_cs);
    } else {
        for (entry, maybe_tree) in chronological_commits {
            if let Some(existing_hex) = synced_map.get(&entry.changeset_id)
                && let Ok(existing_hash) = ObjectHash::from_str(existing_hex)
                && let Ok(existing_cs) = repo.store.get_changeset(existing_hash)
            {
                prev_local_hash = Some(existing_cs.id);
                tip_local_cs = Some(existing_cs);
                continue;
            }

            let tree_data = maybe_tree.unwrap_or_else(|| tip_tree.clone());
            let author = Identity {
                name: entry.author_name.clone(),
                email: entry.author_email.clone(),
                key_fingerprint: None,
            };
            let local_cs = import_tree_as_changeset(
                &repo,
                &tree_data,
                prev_local_hash,
                author,
                entry.message.clone(),
                &entry.visibility_domain,
                preserved_local_acl.as_deref(),
            )?;
            synced_map.insert(entry.changeset_id.clone(), local_cs.id.to_hex());
            prev_local_hash = Some(local_cs.id);
            tip_local_cs = Some(local_cs);
            newly_imported += 1;
        }
    }

    let tip_cs = tip_local_cs.ok_or_else(|| anyhow!("pull produced no changeset"))?;

    // Check if local `@` is clean relative to previous target bookmark.
    let local_is_clean = old_target_cs
        .as_ref()
        .is_some_and(|old| old.domain_trees == local_head.domain_trees);

    repo.store.set_bookmark(&target_bm, tip_cs.id)?;
    repo.store
        .set_bookmark(&format!("{remote_name}/{target_bm}"), tip_cs.id)?;

    let mut conflict_paths = Vec::new();
    if local_is_clean || local_head.id == tip_cs.id {
        let working_cs = ChangeSetBuilder::new(repo.config.author.clone())
            .parents(vec![tip_cs.id])
            .public_parents(vec![tip_cs.public_projection_hash])
            .domain_trees(tip_cs.domain_trees.clone())
            .visibility(VisibilityPolicy::public())
            .description("")
            .build();
        repo.store.put_changeset(&working_cs)?;
        repo.update_active_workspace_head(&working_cs)?;
        repo.materialize_changeset(&tip_cs)?;
    } else {
        let (merged_trees, conflicts) =
            repo.merge_changeset_trees(old_target_cs.as_ref(), &local_head, &tip_cs)?;
        let has_conflicts = !conflicts.is_empty() || repo.trees_have_conflicts(&merged_trees)?;
        conflict_paths = conflicts;
        let merged_ws = ChangeSetBuilder::new(local_head.author.clone())
            .change_id(local_head.change_id)
            .previous_revision(Some(local_head.id))
            .parents(vec![tip_cs.id])
            .public_parents(vec![tip_cs.public_projection_hash])
            .domain_trees(merged_trees)
            .committer(local_head.committer.clone())
            .visibility(local_head.visibility.clone())
            .has_conflicts(has_conflicts)
            .description(local_head.description.clone())
            .build();
        repo.store.put_changeset(&merged_ws)?;
        repo.update_active_workspace_head(&merged_ws)?;
        repo.materialize_changeset(&merged_ws)?;
    }

    if let Some(entry) = cfg.remotes.get_mut(&remote_name) {
        entry.last_pulled_head = Some(remote_tip_id.clone());
        entry
            .remote_heads
            .insert(target_bm.clone(), remote_tip_id.clone());
        entry.synced_commits = synced_map;
    }
    save_remotes(&repo.gitx_dir, &cfg)?;

    let _ = repo.append_op(
        OpKind::Snapshot {
            workspace: repo.config.active_workspace.clone(),
        },
        format!(
            "Pulled {remote_name}/{target_bm} (remote={}, local={})",
            short_hex(&remote_tip_id),
            tip_cs.id.short()
        ),
    );

    // Automatically decrypt and materialize any authorized `secret:*` envelopes onto disk
    // when the local keypair is a recipient (recording decrypt audit entries).
    let mut decrypted_secrets = 0usize;
    if !tip_tree.secrets.is_empty()
        && let Ok(keypair) = repo.load_local_keypair()
    {
        let mut audit = repo.load_audit_log().ok();
        for sec in &tip_tree.secrets {
            if let Ok(env) = serde_json::from_str::<gitx_crypto::SecretEnvelope>(&sec.envelope_json)
                && let Ok(plaintext) = gitx_crypto::decrypt_secret(&env, &sec.path, &keypair)
                && let Ok(norm_path) = gitx_vfs::normalize_rel_path(&sec.path)
            {
                let dest = repo.root.join(&norm_path);
                if let Some(parent) = dest.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if fs::write(&dest, &plaintext).is_ok() {
                    decrypted_secrets += 1;
                    if let Some(ref mut a) = audit
                        && let Ok(dom) = DomainId::new(&sec.domain)
                    {
                        a.record_decrypt(keypair.fingerprint(), dom, &norm_path, sec.key_epoch);
                    }
                }
            }
        }
        if let Some(ref a) = audit {
            let _ = repo.save_audit_log(a);
        }
    }

    println!(
        "Pulled from '{remote_name}' ({} @ {target_bm}):",
        resolved.full_name()
    );
    println!("  remote_head: {}", remote_tip_id);
    println!("  local_head:  {}", tip_cs.id.short());
    println!("  commits:     {newly_imported} imported");
    println!(
        "  domains:     {}",
        if tip_tree.domains.is_empty() {
            "public".to_string()
        } else {
            tip_tree.domains.join(", ")
        }
    );
    println!("  files:       {}", tip_tree.files.len());
    if !tip_tree.secrets.is_empty() {
        println!(
            "  secrets:     {} synced ({} decrypted locally)",
            tip_tree.secrets.len(),
            decrypted_secrets
        );
    }
    if !conflict_paths.is_empty() {
        println!("  conflicts:   {}", conflict_paths.join(", "));
    }

    Ok(())
}

fn import_tree_as_changeset(
    repo: &Repo,
    tree_resp: &TreeResponse,
    parent_hash: Option<ObjectHash>,
    author: Identity,
    description: String,
    visibility_domain: &str,
    preserved_local_acl: Option<&[u8]>,
) -> Result<gitx_core::ChangeSet> {
    let mut per_domain: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
    let mut remote_had_acl = false;

    for file in &tree_resp.files {
        if file.path == ".gitxacl" {
            remote_had_acl = true;
        }
        let domain = DomainId::new(&file.domain).unwrap_or_else(|_| DomainId::public());
        let bytes = decode_tree_file_bytes(file)?;
        let blob = repo.store.put_blob_bytes(&bytes)?;
        let tree = per_domain
            .entry(domain.clone())
            .or_insert_with(|| DomainTree::new(domain));
        tree.insert(
            file.path.clone(),
            EntryKind::File {
                blob_hash: blob.manifest_hash(),
                mode: FileMode::Regular,
                size: blob.total_size,
            },
        );
    }

    // Preserve any authorized encrypted secret envelopes inside their `secret:*` domain trees.
    for sec in &tree_resp.secrets {
        if let Ok(dom) = DomainId::new(&sec.domain)
            && dom.is_secret()
            && let Ok(env) = serde_json::from_str::<gitx_crypto::SecretEnvelope>(&sec.envelope_json)
        {
            let env_hash = repo.put_envelope(&env)?;
            let tree = per_domain
                .entry(dom.clone())
                .or_insert_with(|| DomainTree::new(dom));
            tree.insert(
                sec.path.clone(),
                EntryKind::EncryptedSecret {
                    envelope_hash: env_hash,
                    key_epoch: sec.key_epoch,
                    mode: FileMode::Regular,
                },
            );
        }
    }

    let pub_tree = per_domain
        .entry(DomainId::public())
        .or_insert_with(|| DomainTree::new(DomainId::public()));

    if !remote_had_acl && let Some(acl_bytes) = preserved_local_acl {
        let blob = repo.store.put_blob_bytes(acl_bytes)?;
        pub_tree.insert(
            ".gitxacl".to_string(),
            EntryKind::File {
                blob_hash: blob.manifest_hash(),
                mode: FileMode::Regular,
                size: blob.total_size,
            },
        );
    }

    let mut domain_tree_hashes = BTreeMap::new();
    for (dom, tree) in &per_domain {
        let hash = repo.store.put_tree(tree)?;
        domain_tree_hashes.insert(dom.clone(), hash);
    }

    let parents: Vec<ObjectHash> = parent_hash.into_iter().collect();
    let public_parents: Vec<ObjectHash> = parent_hash
        .and_then(|h| repo.store.get_changeset(h).ok())
        .map(|p| vec![p.public_projection_hash])
        .unwrap_or_default();

    let visibility = if visibility_domain == "public" || visibility_domain.is_empty() {
        VisibilityPolicy::public()
    } else {
        let dom = DomainId::new(visibility_domain).unwrap_or_else(|_| DomainId::public());
        if dom.is_public() {
            VisibilityPolicy::public()
        } else {
            VisibilityPolicy::private(dom, false)
        }
    };

    let cs = ChangeSetBuilder::new(author)
        .parents(parents)
        .public_parents(public_parents)
        .domain_trees(domain_tree_hashes)
        .visibility(visibility)
        .description(description)
        .build();
    repo.store.put_changeset(&cs)?;
    Ok(cs)
}

// ---------------------------------------------------------------------------
// Zero-Clone Remote RPC Commands (`remote grep/diff/blame/log/stats`)
// ---------------------------------------------------------------------------

pub fn cmd_remote_grep(
    pattern: String,
    remote: Option<String>,
    url: Option<String>,
    rev: Option<String>,
    token: Option<String>,
    case_insensitive: bool,
) -> Result<()> {
    let (target, auth) = resolve_rpc_target(remote.as_deref(), url.as_deref(), token.as_deref())?;

    let grep_res: GrepResponse = run_async(async {
        let client = build_http_client()?;
        let mut params: Vec<(&str, String)> = vec![("q", pattern.clone())];
        if let Some(r) = rev {
            params.push(("rev", r));
        }
        if case_insensitive {
            params.push(("case_insensitive", "true".to_string()));
        }

        let resp = auth
            .apply(client.get(target.api_url("grep")))
            .query(&params)
            .send()
            .await
            .with_context(|| format!("failed to run remote grep on {}", target.base_url))?;
        parse_json_response(resp, "remote grep").await
    })?;

    if grep_res.matches.is_empty() {
        println!("(no matches for '{}')", grep_res.query);
        return Ok(());
    }

    for m in &grep_res.matches {
        println!("[{}] {}:{}: {}", m.domain, m.path, m.line_number, m.line);
    }
    Ok(())
}

pub fn cmd_remote_diff(
    from: String,
    to: String,
    remote: Option<String>,
    url: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let (target, auth) = resolve_rpc_target(remote.as_deref(), url.as_deref(), token.as_deref())?;

    let diff_res: DiffResponse = run_async(async {
        let client = build_http_client()?;
        let resp = auth
            .apply(client.get(target.api_url("diff")))
            .query(&[("from", from.as_str()), ("to", to.as_str())])
            .send()
            .await
            .with_context(|| format!("failed to run remote diff on {}", target.base_url))?;
        parse_json_response(resp, "remote diff").await
    })?;

    if diff_res.unified_diff.is_empty() {
        println!("(no differences)");
    } else {
        print!("{}", diff_res.unified_diff);
        if !diff_res.unified_diff.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

pub fn cmd_remote_blame(
    path: String,
    remote: Option<String>,
    url: Option<String>,
    rev: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let (target, auth) = resolve_rpc_target(remote.as_deref(), url.as_deref(), token.as_deref())?;

    let blame_res: BlameResponse = run_async(async {
        let client = build_http_client()?;
        let mut params: Vec<(&str, String)> = vec![("path", path.clone())];
        if let Some(r) = rev {
            params.push(("rev", r));
        }
        let resp = auth
            .apply(client.get(target.api_url("blame")))
            .query(&params)
            .send()
            .await
            .with_context(|| format!("failed to run remote blame on {}", target.base_url))?;
        parse_json_response(resp, "remote blame").await
    })?;

    if blame_res.lines.is_empty() {
        println!("(empty file '{}')", blame_res.path);
        return Ok(());
    }

    for line in &blame_res.lines {
        println!(
            "{} ({} {} L{}) {}",
            short_hex(&line.changeset_id),
            line.author_name,
            line.timestamp.format("%Y-%m-%d"),
            line.line_number,
            line.content
        );
    }
    Ok(())
}

pub fn cmd_remote_log(
    remote: Option<String>,
    url: Option<String>,
    rev: Option<String>,
    limit: Option<usize>,
    token: Option<String>,
) -> Result<()> {
    let (target, auth) = resolve_rpc_target(remote.as_deref(), url.as_deref(), token.as_deref())?;

    let log_res: LogResponse = run_async(async {
        let client = build_http_client()?;
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(r) = rev {
            params.push(("rev", r));
        }
        if let Some(l) = limit {
            params.push(("limit", l.to_string()));
        }
        let resp = auth
            .apply(client.get(target.api_url("log")))
            .query(&params)
            .send()
            .await
            .with_context(|| format!("failed to run remote log on {}", target.base_url))?;
        parse_json_response(resp, "remote log").await
    })?;

    if log_res.commits.is_empty() {
        println!("(no visible commits)");
        return Ok(());
    }

    for commit in &log_res.commits {
        let first_line = commit.message.lines().next().unwrap_or("(no description)");
        let conflict = if commit.has_conflicts {
            " [CONFLICT]"
        } else {
            ""
        };
        println!(
            "o {} {} [{}]{conflict} {} <{}>",
            short_id(&commit.change_id, 10),
            short_hex(&commit.changeset_id),
            commit.visibility_domain,
            commit.author_name,
            commit.author_email
        );
        println!("    {first_line}");
    }
    Ok(())
}

pub fn cmd_remote_stats(
    remote: Option<String>,
    url: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let (target, auth) = resolve_rpc_target(remote.as_deref(), url.as_deref(), token.as_deref())?;

    let stats: DerivedStats = run_async(async {
        let client = build_http_client()?;
        let resp = auth
            .apply(client.get(target.api_url("derived/stats")))
            .send()
            .await
            .with_context(|| format!("failed to fetch remote stats from {}", target.base_url))?;
        parse_json_response(resp, "remote derived stats").await
    })?;

    println!("Derived data stats for {}:", target.full_name());
    println!(
        "  trigram:      trees={} postings={} domains=[{}] hits={} misses={}",
        stats.trigram_indexed_trees,
        stats.trigram_total_postings,
        stats.trigram_domains.join(", "),
        stats.trigram_cache_hits,
        stats.trigram_cache_misses
    );
    println!(
        "  commit_graph: nodes={} hits={} misses={}",
        stats.commit_graph_nodes, stats.commit_graph_cache_hits, stats.commit_graph_cache_misses
    );
    println!(
        "  path_history: entries={} hits={} misses={}",
        stats.path_history_entries, stats.path_history_cache_hits, stats.path_history_cache_misses
    );
    println!(
        "  symbols:      trees={} symbols={} hits={} misses={}",
        stats.symbol_indexed_trees,
        stats.symbol_total_symbols,
        stats.symbol_cache_hits,
        stats.symbol_cache_misses
    );
    Ok(())
}

pub fn cmd_remote_symbols(
    path: Option<String>,
    remote: Option<String>,
    url: Option<String>,
    rev: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let (target, auth) = resolve_rpc_target(remote.as_deref(), url.as_deref(), token.as_deref())?;
    let resp: SymbolsResponse = run_async(async {
        let client = build_http_client()?;
        let mut req = auth.apply(client.get(target.api_url("symbols")));
        if let Some(ref r) = rev {
            req = req.query(&[("rev", r)]);
        }
        if let Some(ref p) = path {
            req = req.query(&[("path", p)]);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("failed to query remote symbols from {}", target.base_url))?;
        parse_json_response(resp, "remote symbols").await
    })?;

    if resp.symbols.is_empty() {
        println!("No symbols found.");
        return Ok(());
    }
    for sym in resp.symbols {
        println!(
            "[{}] {}:{}-{} {} {}",
            sym.domain, sym.path, sym.line_start, sym.line_end, sym.kind, sym.name
        );
    }
    Ok(())
}

pub fn cmd_remote_rebase(
    changeset_id: String,
    onto: String,
    update_bookmark: Option<String>,
    remote: Option<String>,
    url: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let (target, auth) = resolve_rpc_target(remote.as_deref(), url.as_deref(), token.as_deref())?;
    let payload = json!({
        "changeset_id": changeset_id,
        "onto": onto,
        "update_bookmark": update_bookmark,
    });
    let resp: RebaseResponse = run_async(async {
        let client = build_http_client()?;
        let resp = auth
            .apply(client.post(target.api_url("rebase")))
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("failed to rebase on remote {}", target.base_url))?;
        parse_json_response(resp, "remote rebase").await
    })?;

    println!(
        "Rebased {} onto {} -> {} (conflicts: {})",
        short_id(&resp.change_id, 8),
        short_hex(&resp.onto),
        short_hex(&resp.changeset_id),
        resp.conflicts.len()
    );
    if !resp.conflicts.is_empty() {
        println!("  conflicts: {}", resp.conflicts.join(", "));
    }
    Ok(())
}

pub fn short_hex(s: &str) -> &str {
    short_id(s, 12)
}

pub fn short_id(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len { s } else { &s[..max_len] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_remote_url_variants() {
        let (base, owner, repo) =
            parse_remote_url("http://127.0.0.1:7878/acme/demo", None, None).unwrap();
        assert_eq!(base, "http://127.0.0.1:7878");
        assert_eq!(owner, "acme");
        assert_eq!(repo, "demo");

        let (base, owner, repo) =
            parse_remote_url("http://127.0.0.1:7878/acme/demo.git/", None, None).unwrap();
        assert_eq!(base, "http://127.0.0.1:7878");
        assert_eq!(owner, "acme");
        assert_eq!(repo, "demo");

        let (base, owner, repo) =
            parse_remote_url("http://127.0.0.1:7878", Some("org"), Some("app")).unwrap();
        assert_eq!(base, "http://127.0.0.1:7878");
        assert_eq!(owner, "org");
        assert_eq!(repo, "app");

        let (base, owner, repo) =
            parse_remote_url("http://127.0.0.1:7878/v1/repos/acme/demo", None, None).unwrap();
        assert_eq!(base, "http://127.0.0.1:7878");
        assert_eq!(owner, "acme");
        assert_eq!(repo, "demo");

        assert!(parse_remote_url("http://127.0.0.1:7878", None, None).is_err());
    }

    #[test]
    fn parses_token_formats() {
        let kv = parse_token_headers("user=alice;teams=core,security;roles=admin;fp=deadbeef");
        assert_eq!(kv.user.as_deref(), Some("alice"));
        assert_eq!(kv.teams, vec!["core", "security"]);
        assert_eq!(kv.roles, vec!["admin"]);
        assert_eq!(kv.fingerprint.as_deref(), Some("deadbeef"));

        let subj = parse_token_headers("user:bob,team:infra,role:release");
        assert_eq!(subj.user.as_deref(), Some("bob"));
        assert_eq!(subj.teams, vec!["infra"]);
        assert_eq!(subj.roles, vec!["release"]);

        let plain = parse_token_headers("outsider");
        assert_eq!(plain.user.as_deref(), Some("outsider"));
        assert!(plain.teams.is_empty());

        let anon = parse_token_headers("anonymous");
        assert!(anon.is_anonymous());
    }
}
