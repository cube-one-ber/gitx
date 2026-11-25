//! ACL-filtered Git SSH transport adapter (`git-upload-pack` and `git-receive-pack`).
//!
//! Parses standard Git SSH remote commands (`git-upload-pack '<repo>'`,
//! `git-receive-pack '<repo>'`), dynamically projects strictly the caller's authorized
//! [`DomainId`]s into an ephemeral bare Git repository using [`export_to_git_repo`], and
//! streams standard Git pkt-line wire protocol frames over arbitrary [`Read`]/[`Write`]
//! streams so unauthorized domains, private branches, and secrets never cross the wire.

use crate::import::ImportReport;
use crate::objects::GitOid;
use crate::pktline::{PktLine, decode_pkt_lines, encode_flush_pkt, encode_pkt_line};
use crate::project::{ProjectionReport, export_to_git_repo, export_to_git_repo_filtered};
use chrono::{DateTime, Utc};
use gitx_core::{
    ChangeSetBuilder, DomainId, DomainTree, EmbargoState, EntryKind, FileMode, GitxError, Identity,
    ObjectHash, Result, VisibilityPolicy,
};
use gitx_crypto::{AclPolicy, Principal, scan_content};
use gitx_store::ObjectStore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Supported Git SSH remote services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GitSshService {
    UploadPack,
    ReceivePack,
}

impl GitSshService {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }
}

/// Parsed SSH remote Git command (e.g. `git-upload-pack '/acme/mono.git'`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedSshCommand {
    pub service: GitSshService,
    pub raw_repo: String,
    pub repo_path: String,
}

/// Summary produced after serving a Git SSH transport session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshSessionReport {
    pub service: GitSshService,
    pub repo_path: String,
    pub projection: ProjectionReport,
    pub imported: Option<ImportReport>,
    pub bytes_written: usize,
}

/// Parses and validates a Git SSH command string such as:
/// - `git-upload-pack '/acme/app.git'`
/// - `git-upload-pack "acme/app"`
/// - `git upload-pack '/acme/app.git'`
/// - `git-receive-pack '/acme/app.git'`
///
/// Rejects unknown services, shell metacharacters, and path traversal (`..`).
pub fn parse_ssh_command(command: &str) -> Result<ParsedSshCommand> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err(GitxError::GitBridge("empty SSH command".to_string()));
    }
    if trimmed.contains('\0') || trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(GitxError::GitBridge(
            "SSH command contains disallowed control characters".to_string(),
        ));
    }

    let (service, rest) = if let Some(r) = trimmed.strip_prefix("git-upload-pack") {
        (GitSshService::UploadPack, r)
    } else if let Some(r) = trimmed.strip_prefix("git upload-pack") {
        (GitSshService::UploadPack, r)
    } else if let Some(r) = trimmed.strip_prefix("git-receive-pack") {
        (GitSshService::ReceivePack, r)
    } else if let Some(r) = trimmed.strip_prefix("git receive-pack") {
        (GitSshService::ReceivePack, r)
    } else {
        return Err(GitxError::GitBridge(format!(
            "unsupported Git SSH command '{trimmed}': expected git-upload-pack or git-receive-pack"
        )));
    };

    if !rest.starts_with(char::is_whitespace) {
        return Err(GitxError::GitBridge(format!(
            "malformed Git SSH command '{trimmed}': missing repository argument"
        )));
    }

    let arg = rest.trim();
    if arg.is_empty() {
        return Err(GitxError::GitBridge(format!(
            "malformed Git SSH command '{trimmed}': empty repository argument"
        )));
    }

    let raw_repo = unquote_ssh_arg(arg)?;
    validate_ssh_repo_path(&raw_repo)?;

    let normalized = raw_repo
        .trim_start_matches('/')
        .strip_suffix(".git")
        .unwrap_or_else(|| raw_repo.trim_start_matches('/'))
        .to_string();

    if normalized.is_empty() {
        return Err(GitxError::GitBridge(format!(
            "invalid Git SSH repository path '{raw_repo}'"
        )));
    }

    Ok(ParsedSshCommand {
        service,
        raw_repo,
        repo_path: normalized,
    })
}

fn unquote_ssh_arg(arg: &str) -> Result<String> {
    if let Some(inner) = arg.strip_prefix('\'') {
        let Some(unquoted) = inner.strip_suffix('\'') else {
            return Err(GitxError::GitBridge(format!(
                "unterminated single quote in SSH argument '{arg}'"
            )));
        };
        if unquoted.contains('\'') {
            return Err(GitxError::GitBridge(format!(
                "unexpected embedded quote in SSH argument '{arg}'"
            )));
        }
        return Ok(unquoted.to_string());
    }

    if let Some(inner) = arg.strip_prefix('"') {
        let Some(unquoted) = inner.strip_suffix('"') else {
            return Err(GitxError::GitBridge(format!(
                "unterminated double quote in SSH argument '{arg}'"
            )));
        };
        if unquoted.contains('"') {
            return Err(GitxError::GitBridge(format!(
                "unexpected embedded quote in SSH argument '{arg}'"
            )));
        }
        return Ok(unquoted.to_string());
    }

    if arg.chars().any(char::is_whitespace) {
        return Err(GitxError::GitBridge(format!(
            "unexpected extra arguments in SSH command: '{arg}'"
        )));
    }

    Ok(arg.to_string())
}

fn validate_ssh_repo_path(raw: &str) -> Result<()> {
    if raw.is_empty()
        || raw.contains('\\')
        || raw.contains('\0')
        || raw.contains(';')
        || raw.contains('|')
        || raw.contains('&')
        || raw.contains('$')
        || raw.contains('`')
    {
        return Err(GitxError::GitBridge(format!(
            "disallowed characters in SSH repository path '{raw}'"
        )));
    }

    for seg in raw.trim_start_matches('/').split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(GitxError::GitBridge(format!(
                "invalid path segment in SSH repository path '{raw}'"
            )));
        }
    }

    Ok(())
}

/// Stateful ACL-enforcing Git SSH session operating over arbitrary [`Read`]/[`Write`] streams.
pub struct GitSshSession<'a> {
    store: &'a dyn ObjectStore,
    allowed_domains: Vec<DomainId>,
    write_domain: Option<DomainId>,
    git_protocol: Option<String>,
    acl_policy: Option<AclPolicy>,
    principal: Option<Principal>,
    can_admin_acl: bool,
}

impl<'a> GitSshSession<'a> {
    /// Creates a read-only ACL-filtered Git SSH session restricted strictly to `allowed_domains`.
    pub fn new(store: &'a dyn ObjectStore, allowed_domains: Vec<DomainId>) -> Self {
        Self {
            store,
            allowed_domains,
            write_domain: None,
            git_protocol: None,
            acl_policy: None,
            principal: None,
            can_admin_acl: false,
        }
    }

    /// Enables `git-receive-pack` pushes imported into `domain` (which must also be authorized
    /// in `allowed_domains`).
    pub fn with_write_domain(mut self, domain: DomainId) -> Self {
        self.write_domain = Some(domain);
        self
    }

    /// Overrides the [`AclPolicy`] enforced during `git-receive-pack` imports (defaults to the
    /// `.gitxacl` committed on `master` or [`AclPolicy::default_secure`]).
    pub fn with_acl_policy(mut self, policy: AclPolicy) -> Self {
        self.acl_policy = Some(policy);
        self
    }

    /// Associates an authenticated [`Principal`] with this SSH session for path-ACL, secret-domain,
    /// and `.gitxacl` authorization checks during `git-receive-pack`.
    pub fn with_principal(mut self, principal: Principal) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Grants or revokes `.gitxacl` administrative privileges for `git-receive-pack` on this session.
    pub fn with_acl_admin(mut self, can_admin_acl: bool) -> Self {
        self.can_admin_acl = can_admin_acl;
        self
    }

    /// Sets the `GIT_PROTOCOL` environment variable (e.g. `"version=2"`).
    pub fn with_git_protocol(mut self, protocol: impl Into<String>) -> Self {
        let proto = protocol.into();
        if !proto.is_empty() {
            self.git_protocol = Some(proto);
        }
        self
    }

    /// Dispatches `command` (`git-upload-pack` or `git-receive-pack`) over the provided
    /// full-duplex `input`/`output` streams, speaking standard Git pkt-line wire framing.
    pub fn run<R, W>(&self, command: &str, input: R, mut output: W) -> Result<SshSessionReport>
    where
        R: Read + Send,
        W: Write,
    {
        let parsed = parse_ssh_command(command)?;

        match parsed.service {
            GitSshService::UploadPack => {
                let tmp = TempDir::new()?;
                let bookmarks = self.store.list_bookmarks()?;
                let projection =
                    export_to_git_repo(self.store, tmp.path(), &self.allowed_domains, &bookmarks)?;

                let bytes_written = run_git_ssh_process(
                    "upload-pack",
                    tmp.path(),
                    self.git_protocol.as_deref(),
                    input,
                    &mut output,
                )?;

                Ok(SshSessionReport {
                    service: GitSshService::UploadPack,
                    repo_path: parsed.repo_path,
                    projection,
                    imported: None,
                    bytes_written,
                })
            }
            GitSshService::ReceivePack => {
                let Some(ref target_domain) = self.write_domain else {
                    let err_pkt =
                        encode_pkt_line(b"ERR write access denied for this SSH session\n");
                    let _ = output.write_all(&err_pkt);
                    let _ = output.write_all(&encode_flush_pkt());
                    let _ = output.flush();
                    return Err(GitxError::AccessDenied {
                        domain: "write".to_string(),
                        reason: "git-receive-pack is disabled for read-only SSH sessions"
                            .to_string(),
                    });
                };

                if !self.allowed_domains.contains(target_domain) {
                    let err_pkt = encode_pkt_line(
                        format!("ERR unauthorized write domain '{target_domain}'\n").as_bytes(),
                    );
                    let _ = output.write_all(&err_pkt);
                    let _ = output.write_all(&encode_flush_pkt());
                    let _ = output.flush();
                    return Err(GitxError::AccessDenied {
                        domain: target_domain.to_string(),
                        reason: "target write domain is not in caller's allowed domains"
                            .to_string(),
                    });
                }

                if target_domain.is_embargo() {
                    let err_pkt = encode_pkt_line(
                        b"ERR git-receive-pack is not supported for embargo domains\n",
                    );
                    let _ = output.write_all(&err_pkt);
                    let _ = output.write_all(&encode_flush_pkt());
                    let _ = output.flush();
                    return Err(GitxError::AccessDenied {
                        domain: target_domain.to_string(),
                        reason: "git-receive-pack cannot target an embargo domain".to_string(),
                    });
                }

                let tmp = TempDir::new()?;
                let bookmarks = self.store.list_bookmarks()?;
                // Project STRICTLY `target_domain` into the receive-pack staging repo (including
                // readable non-embargo commits where `target_domain` is a non-primary domain tree,
                // so existing files in `target_domain` are never dropped on push and unreadable
                // private commits are never leaked into the staging view).
                let projection = export_receive_pack_staging_filtered(
                    self.store,
                    tmp.path(),
                    target_domain,
                    &bookmarks,
                    |cs| self.allowed_domains.contains(&cs.visibility.primary_domain),
                )?;
                let refs_before = list_bare_branch_refs(tmp.path())?;

                // Reject branch deletions at the Git protocol level so a single-domain SSH client
                // can never silently drop or desynchronize multi-domain GitX bookmarks.
                let cfg_status = Command::new("git")
                    .arg("-C")
                    .arg(tmp.path())
                    .args(["config", "receive.denyDeletes", "true"])
                    .status()?;
                if !cfg_status.success() {
                    return Err(GitxError::GitBridge(
                        "failed to configure receive.denyDeletes on staging bare repository"
                            .to_string(),
                    ));
                }

                let policy = match &self.acl_policy {
                    Some(p) => p.clone(),
                    None => load_committed_acl_policy(self.store)?,
                };
                // If the SSH caller explicitly authorized `target_domain` via `with_write_domain`
                // without passing an explicit `Principal`, allow updates/deletions inside
                // `target_domain` itself (while still enforcing path-ACL, `.gitxacl` admin guard,
                // and blocking cross-secret shadowing of other `secret:*` domains).
                let implicit_secret_domains: Vec<DomainId> =
                    if self.principal.is_none() && target_domain.is_secret() {
                        vec![target_domain.clone()]
                    } else {
                        Vec::new()
                    };

                // Stream ONLY the Phase-1 ref advertisement (through the first flush `0000`) to
                // the client while buffering `git receive-pack`'s Phase-2 status response (`unpack ok`
                // / `ok refs/heads/...`), then run full two-pass ACL & atomic import and flush the
                // Phase-2 status (or ERR/sideband-3 rejection) BEFORE joining the stdin pump so
                // full-duplex `git send-pack` clients (which keep stdin open until reading status)
                // never deadlock.
                let (bytes_written, imported) = run_git_receive_pack_buffered(
                    tmp.path(),
                    self.git_protocol.as_deref(),
                    input,
                    &mut output,
                    || {
                        import_received_refs_internal(
                            tmp.path(),
                            self.store,
                            target_domain,
                            &bookmarks,
                            &refs_before,
                            &policy,
                            self.principal.as_ref(),
                            self.can_admin_acl,
                            &implicit_secret_domains,
                        )
                    },
                )?;

                Ok(SshSessionReport {
                    service: GitSshService::ReceivePack,
                    repo_path: parsed.repo_path,
                    projection,
                    imported: Some(imported),
                    bytes_written,
                })
            }
        }
    }
}

/// Dispatches a read-only ACL-filtered Git SSH command (`git-upload-pack` / `git-receive-pack`)
/// against `store`, projecting strictly `allowed_domains`.
pub fn handle_ssh_command<R, W>(
    command: &str,
    store: &dyn ObjectStore,
    allowed_domains: &[DomainId],
    input: R,
    output: W,
) -> Result<SshSessionReport>
where
    R: Read + Send,
    W: Write,
{
    GitSshSession::new(store, allowed_domains.to_vec()).run(command, input, output)
}

/// Captures the standard SSH pkt-line ref advertisement for `git-upload-pack` restricted to
/// `allowed_domains` (equivalent to a client sending a flush packet `0000` after reading refs).
pub fn advertise_ssh_upload_pack_refs(
    store: &dyn ObjectStore,
    allowed_domains: &[DomainId],
    git_protocol: Option<&str>,
) -> Result<(Vec<u8>, ProjectionReport)> {
    let mut session = GitSshSession::new(store, allowed_domains.to_vec());
    if let Some(proto) = git_protocol {
        session = session.with_git_protocol(proto);
    }
    let flush = encode_flush_pkt();
    let mut out = Vec::new();
    let report = session.run("git-upload-pack '/repo.git'", flush.as_slice(), &mut out)?;
    Ok((out, report.projection))
}

/// Parses Git pkt-line ref advertisement frames (v0/v1 SSH wire format) into a sorted map
/// of `ref_name -> GitOid` (e.g. `"HEAD"`, `"refs/heads/master"`).
pub fn parse_advertised_refs(pkt_stream: &[u8]) -> Result<BTreeMap<String, GitOid>> {
    let frames = decode_pkt_lines(pkt_stream)?;
    let mut refs = BTreeMap::new();

    for frame in frames {
        match frame {
            PktLine::Flush => break,
            PktLine::Delim | PktLine::ResponseEnd => continue,
            PktLine::Data(bytes) => {
                // First ref line contains `<oid> <refname>\0<capabilities>\n`.
                let line_bytes = bytes.split(|&b| b == 0).next().unwrap_or(&bytes);
                let line = std::str::from_utf8(line_bytes).map_err(|e| {
                    GitxError::GitBridge(format!("non-UTF8 ref advertisement line: {e}"))
                })?;
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let Some((oid_str, ref_name)) = trimmed.split_once(' ') else {
                    continue;
                };
                if oid_str.len() == 40
                    && oid_str.bytes().all(|b| b.is_ascii_hexdigit())
                    && !ref_name.is_empty()
                {
                    let oid = GitOid::from_hex(oid_str)?;
                    refs.insert(ref_name.to_string(), oid);
                }
            }
        }
    }

    Ok(refs)
}

fn run_git_ssh_process<R, W>(
    subcommand: &str,
    bare_git_dir: &Path,
    git_protocol: Option<&str>,
    mut input: R,
    output: &mut W,
) -> Result<usize>
where
    R: Read + Send,
    W: Write,
{
    let mut cmd = Command::new("git");
    cmd.arg(subcommand)
        .arg(bare_git_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(proto) = git_protocol
        && !proto.is_empty()
    {
        cmd.env("GIT_PROTOCOL", proto);
    }

    let mut child = cmd.spawn()?;
    let mut child_stdin = child.stdin.take().ok_or_else(|| {
        GitxError::GitBridge(format!("failed to open stdin for git {subcommand}"))
    })?;
    let mut child_stdout = child.stdout.take().ok_or_else(|| {
        GitxError::GitBridge(format!("failed to open stdout for git {subcommand}"))
    })?;
    let mut child_stderr = child.stderr.take().ok_or_else(|| {
        GitxError::GitBridge(format!("failed to open stderr for git {subcommand}"))
    })?;

    let (bytes_written, stdin_res, stderr_bytes) = std::thread::scope(|scope| {
        let stdin_handle = scope.spawn(move || -> std::io::Result<()> {
            let mut buf = [0u8; 8192];
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                if let Err(err) = child_stdin.write_all(&buf[..n]) {
                    if err.kind() == ErrorKind::BrokenPipe {
                        break;
                    }
                    return Err(err);
                }
                if let Err(err) = child_stdin.flush() {
                    if err.kind() == ErrorKind::BrokenPipe {
                        break;
                    }
                    return Err(err);
                }
            }
            drop(child_stdin);
            Ok(())
        });

        let stderr_handle = scope.spawn(move || -> Vec<u8> {
            let mut err_buf = Vec::new();
            let _ = child_stderr.read_to_end(&mut err_buf);
            err_buf
        });

        let mut total_written = 0usize;
        let mut out_buf = [0u8; 16384];
        let mut stdout_err: Option<std::io::Error> = None;
        loop {
            match child_stdout.read(&mut out_buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = output.write_all(&out_buf[..n]) {
                        stdout_err = Some(e);
                        break;
                    }
                    if let Err(e) = output.flush() {
                        stdout_err = Some(e);
                        break;
                    }
                    total_written += n;
                }
                Err(e) => {
                    stdout_err = Some(e);
                    break;
                }
            }
        }

        drop(child_stdout);
        if stdout_err.is_some() {
            let _ = child.kill();
        }

        let stdin_res = stdin_handle.join();
        let stderr_bytes = stderr_handle.join().unwrap_or_default();

        if let Some(err) = stdout_err {
            return (Err(err), stdin_res, stderr_bytes);
        }
        (Ok(total_written), stdin_res, stderr_bytes)
    });

    let status = child.wait()?;
    let written = bytes_written?;

    match stdin_res {
        Ok(Ok(())) => {}
        Ok(Err(e)) if e.kind() == ErrorKind::BrokenPipe => {}
        Ok(Err(e)) => return Err(GitxError::Io(e)),
        Err(_) => {
            return Err(GitxError::GitBridge(format!(
                "git {subcommand} stdin pump thread panicked"
            )));
        }
    }

    if !status.success() {
        let stderr_str = String::from_utf8_lossy(&stderr_bytes);
        return Err(GitxError::GitBridge(format!(
            "git {subcommand} failed (status {status}): {}",
            stderr_str.trim()
        )));
    }

    Ok(written)
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn status_uses_sideband(status_buf: &[u8]) -> bool {
    status_buf.len() >= 5 && matches!(status_buf[4], 1..=3)
}

fn truncate_utf8_prefix(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn write_receive_pack_rejection<W: Write>(
    output: &mut W,
    status_buf: &[u8],
    message: &str,
) -> usize {
    // Keep pkt-line payload well within `MAX_PKT_PAYLOAD` (65516 bytes) so huge stderr never panics.
    let safe_msg = truncate_utf8_prefix(message, 60_000);
    let mut written = 0usize;
    if status_uses_sideband(status_buf) {
        let mut band3 = Vec::with_capacity(1 + safe_msg.len() + 1);
        band3.push(3u8);
        band3.extend_from_slice(safe_msg.as_bytes());
        band3.push(b'\n');
        let pkt = encode_pkt_line(&band3);
        let flush = encode_flush_pkt();
        if output.write_all(&pkt).is_ok() {
            written += pkt.len();
        }
        if output.write_all(&flush).is_ok() {
            written += flush.len();
        }
    } else {
        let err_pkt = encode_pkt_line(format!("ERR {safe_msg}\n").as_bytes());
        let flush = encode_flush_pkt();
        if output.write_all(&err_pkt).is_ok() {
            written += err_pkt.len();
        }
        if output.write_all(&flush).is_ok() {
            written += flush.len();
        }
    }
    let _ = output.flush();
    written
}

/// Runs `git receive-pack`, streaming ONLY Phase 1 (ref advertisement through the first flush
/// packet `0000`) immediately to `output`, buffering Phase 2 (`unpack ok` / ref status),
/// executing `on_received` after `git receive-pack` exits, and flushing either the buffered
/// Phase-2 status OR a protocol rejection frame BEFORE joining the stdin pump thread so live
/// full-duplex `git send-pack` clients (which keep stdin open until reading status) never deadlock.
fn run_git_receive_pack_buffered<R, W, F, T>(
    bare_git_dir: &Path,
    git_protocol: Option<&str>,
    mut input: R,
    output: &mut W,
    on_received: F,
) -> Result<(usize, T)>
where
    R: Read + Send,
    W: Write,
    F: FnOnce() -> Result<T>,
{
    let mut cmd = Command::new("git");
    cmd.arg("receive-pack")
        .arg(bare_git_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(proto) = git_protocol
        && !proto.is_empty()
    {
        cmd.env("GIT_PROTOCOL", proto);
    }

    let mut child = cmd.spawn()?;
    let mut child_stdin = child.stdin.take().ok_or_else(|| {
        GitxError::GitBridge("failed to open stdin for git receive-pack".to_string())
    })?;
    let mut child_stdout = child.stdout.take().ok_or_else(|| {
        GitxError::GitBridge("failed to open stdout for git receive-pack".to_string())
    })?;
    let mut child_stderr = child.stderr.take().ok_or_else(|| {
        GitxError::GitBridge("failed to open stderr for git receive-pack".to_string())
    })?;

    let (result, stdin_res) = std::thread::scope(|scope| {
        let stdin_handle = scope.spawn(move || -> std::io::Result<()> {
            let mut buf = [0u8; 8192];
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                if let Err(err) = child_stdin.write_all(&buf[..n]) {
                    if err.kind() == ErrorKind::BrokenPipe {
                        break;
                    }
                    return Err(err);
                }
                if let Err(err) = child_stdin.flush() {
                    if err.kind() == ErrorKind::BrokenPipe {
                        break;
                    }
                    return Err(err);
                }
            }
            drop(child_stdin);
            Ok(())
        });

        let stderr_handle = scope.spawn(move || -> Vec<u8> {
            let mut err_buf = Vec::new();
            let _ = child_stderr.read_to_end(&mut err_buf);
            err_buf
        });

        // Phase 1: stream exact Git pkt-line ref advertisement frames through the first `0000`.
        let mut total_written = 0usize;
        let mut status_buf = Vec::new();
        let mut io_err: Option<std::io::Error> = None;

        loop {
            let mut len_hdr = [0u8; 4];
            match read_exact_or_eof(&mut child_stdout, &mut len_hdr) {
                Ok(0) => break,
                Ok(n) if n < 4 => {
                    if let Err(e) = output.write_all(&len_hdr[..n]) {
                        io_err = Some(e);
                    } else {
                        let _ = output.flush();
                        total_written += n;
                    }
                    break;
                }
                Ok(_) => {
                    if let Err(e) = output.write_all(&len_hdr) {
                        io_err = Some(e);
                        break;
                    }
                    total_written += 4;
                    if &len_hdr == b"0000" {
                        if let Err(e) = output.flush() {
                            io_err = Some(e);
                        }
                        break;
                    }
                    let frame_len = std::str::from_utf8(&len_hdr)
                        .ok()
                        .and_then(|s| usize::from_str_radix(s, 16).ok())
                        .unwrap_or(0);
                    if frame_len > 4 {
                        let mut payload = vec![0u8; frame_len - 4];
                        match read_exact_or_eof(&mut child_stdout, &mut payload) {
                            Ok(n) => {
                                if let Err(e) = output.write_all(&payload[..n]) {
                                    io_err = Some(e);
                                    break;
                                }
                                total_written += n;
                                if n < payload.len() {
                                    let _ = output.flush();
                                    break;
                                }
                            }
                            Err(e) => {
                                io_err = Some(e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    io_err = Some(e);
                    break;
                }
            }
        }

        // Phase 2: buffer remaining post-pack status bytes until `git receive-pack` closes stdout.
        if io_err.is_none()
            && let Err(e) = child_stdout.read_to_end(&mut status_buf)
        {
            io_err = Some(e);
        }
        drop(child_stdout);
        if io_err.is_some() {
            let _ = child.kill();
        }

        let stderr_bytes = stderr_handle.join().unwrap_or_default();
        let wait_res = child.wait();

        // Run validation/import and write final Phase-2 status OR rejection to `output` BEFORE
        // joining `stdin_handle`, so full-duplex `git send-pack` receives status and closes stdin!
        let outcome: Result<(usize, T)> = (|| {
            if let Some(err) = io_err {
                return Err(GitxError::Io(err));
            }
            let status = wait_res?;
            if !status.success() {
                let stderr_str = String::from_utf8_lossy(&stderr_bytes);
                let msg = format!(
                    "git receive-pack failed (status {status}): {}",
                    stderr_str.trim()
                );
                let _ = write_receive_pack_rejection(output, &status_buf, &msg);
                return Err(GitxError::GitBridge(msg));
            }
            match on_received() {
                Ok(val) => {
                    if !status_buf.is_empty() {
                        output.write_all(&status_buf)?;
                        output.flush()?;
                        total_written += status_buf.len();
                    }
                    Ok((total_written, val))
                }
                Err(err) => {
                    let _ = write_receive_pack_rejection(output, &status_buf, &err.to_string());
                    Err(err)
                }
            }
        })();

        let stdin_res = stdin_handle.join();
        (outcome, stdin_res)
    });

    match stdin_res {
        Ok(Ok(())) => {}
        Ok(Err(e)) if e.kind() == ErrorKind::BrokenPipe => {}
        Ok(Err(e)) => {
            if result.is_ok() {
                return Err(GitxError::Io(e));
            }
        }
        Err(_) => {
            if result.is_ok() {
                return Err(GitxError::GitBridge(
                    "git receive-pack stdin pump thread panicked".to_string(),
                ));
            }
        }
    }

    result
}

pub fn list_bare_branch_refs(bare_dir: &Path) -> Result<BTreeMap<String, String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(bare_dir)
        .args([
            "for-each-ref",
            "--format=%(refname:short) %(objectname)",
            "refs/heads",
        ])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitxError::GitBridge(format!(
            "git for-each-ref failed: {}",
            stderr.trim()
        )));
    }
    let mut refs = BTreeMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let trimmed = line.trim();
        if let Some((branch, oid)) = trimmed.split_once(' ')
            && !branch.is_empty()
            && !oid.is_empty()
        {
            refs.insert(branch.to_string(), oid.to_string());
        }
    }
    Ok(refs)
}

/// Exports a single-domain staging bare Git repository for `git-receive-pack`, filtering
/// changesets through `can_read` so unreadable commits never leak into the staging view while
/// still including readable non-embargo commits where `target_domain` is a non-primary domain tree.
pub fn export_receive_pack_staging_filtered<F>(
    store: &dyn ObjectStore,
    bare_dir: &Path,
    target_domain: &DomainId,
    bookmarks: &BTreeMap<String, ObjectHash>,
    can_read: F,
) -> Result<ProjectionReport>
where
    F: Fn(&gitx_core::ChangeSet) -> bool,
{
    if target_domain.is_embargo() {
        return Err(GitxError::AccessDenied {
            domain: target_domain.to_string(),
            reason: "git-receive-pack cannot target an embargo domain".to_string(),
        });
    }
    let receive_domains = vec![target_domain.clone()];
    export_to_git_repo_filtered(store, bare_dir, &receive_domains, bookmarks, |cs| {
        !matches!(cs.visibility.embargo, Some(EmbargoState::Active { .. }))
            && can_read(cs)
            && (cs.visibility.primary_domain == *target_domain
                || cs.domain_trees.contains_key(target_domain))
    })
}

/// Exports a single-domain staging bare Git repository for `git-receive-pack`.
pub fn export_receive_pack_staging(
    store: &dyn ObjectStore,
    bare_dir: &Path,
    target_domain: &DomainId,
    bookmarks: &BTreeMap<String, ObjectHash>,
) -> Result<ProjectionReport> {
    export_receive_pack_staging_filtered(store, bare_dir, target_domain, bookmarks, |_| true)
}

fn load_committed_acl_policy(store: &dyn ObjectStore) -> Result<AclPolicy> {
    let Some(master_id) = store.get_bookmark("master")? else {
        return Ok(AclPolicy::default_secure());
    };
    let cs = store.get_changeset(master_id)?;
    let Some(&pub_tree_hash) = cs.domain_trees.get(&DomainId::public()) else {
        return Ok(AclPolicy::default_secure());
    };
    let pub_tree = store.get_tree(pub_tree_hash)?;
    let Some(EntryKind::File { blob_hash, .. }) = pub_tree.entries.get(".gitxacl") else {
        return Ok(AclPolicy::default_secure());
    };
    let bytes = store.read_blob_bytes(*blob_hash)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| GitxError::Crypto(format!("invalid UTF-8 in committed .gitxacl: {e}")))?;
    AclPolicy::parse(text)
}

pub fn import_received_refs(
    bare_dir: &Path,
    store: &dyn ObjectStore,
    target_domain: &DomainId,
    old_bookmarks: &BTreeMap<String, ObjectHash>,
    refs_before: &BTreeMap<String, String>,
) -> Result<ImportReport> {
    let policy = load_committed_acl_policy(store)?;
    import_received_refs_with_policy(
        bare_dir,
        store,
        target_domain,
        old_bookmarks,
        refs_before,
        &policy,
        None,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn import_received_refs_with_policy(
    bare_dir: &Path,
    store: &dyn ObjectStore,
    target_domain: &DomainId,
    old_bookmarks: &BTreeMap<String, ObjectHash>,
    refs_before: &BTreeMap<String, String>,
    policy: &AclPolicy,
    principal: Option<&Principal>,
    can_admin_acl: bool,
) -> Result<ImportReport> {
    import_received_refs_internal(
        bare_dir,
        store,
        target_domain,
        old_bookmarks,
        refs_before,
        policy,
        principal,
        can_admin_acl,
        &[],
    )
}

struct ValidatedRefImport {
    branch: String,
    old_head: Option<ObjectHash>,
    prev_cs: Option<gitx_core::ChangeSet>,
    prev_target_tree: Option<DomainTree>,
    pushed_files: BTreeMap<String, (FileMode, Vec<u8>)>,
    author_name: String,
    author_email: String,
    created_at: DateTime<Utc>,
    description: String,
}

#[allow(clippy::too_many_arguments)]
fn import_received_refs_internal(
    bare_dir: &Path,
    store: &dyn ObjectStore,
    target_domain: &DomainId,
    old_bookmarks: &BTreeMap<String, ObjectHash>,
    refs_before: &BTreeMap<String, String>,
    policy: &AclPolicy,
    principal: Option<&Principal>,
    can_admin_acl: bool,
    authorized_secret_write_domains: &[DomainId],
) -> Result<ImportReport> {
    if target_domain.is_embargo() {
        return Err(GitxError::AccessDenied {
            domain: target_domain.to_string(),
            reason: "git-receive-pack cannot target an embargo domain".to_string(),
        });
    }

    let refs_after = list_bare_branch_refs(bare_dir)?;
    for branch in refs_before.keys() {
        if !refs_after.contains_key(branch) {
            return Err(GitxError::AccessDenied {
                domain: target_domain.to_string(),
                reason: format!(
                    "branch deletion for '{branch}' is not permitted via single-domain Git SSH push"
                ),
            });
        }
    }

    let principal_can_write_secret = |dom: &DomainId| -> bool {
        if authorized_secret_write_domains.contains(dom) {
            return true;
        }
        match principal {
            Some(p) => p.roles.iter().any(|r| r == "admin") || policy.can_write_domain(p, dom),
            None => false,
        }
    };

    // Pass 1: Validate EVERY changed ref completely BEFORE mutating `store`, so a multi-ref push
    // where a later ref fails path-ACL, `.gitxacl`, secret, or embargo validation leaves `store`
    // completely untouched.
    let mut validated_refs: Vec<ValidatedRefImport> = Vec::new();
    for (branch, new_oid) in &refs_after {
        if refs_before.get(branch) == Some(new_oid) {
            continue;
        }

        // Load previous ChangeSet, target tree, public tree (for `.gitxacl` diff), and any secret trees.
        let old_head = old_bookmarks.get(branch).copied();
        if old_head.is_some() && !refs_before.contains_key(branch) {
            return Err(GitxError::AccessDenied {
                domain: target_domain.to_string(),
                reason: format!(
                    "bookmark '{branch}' already exists outside the '{target_domain}' staging view and cannot be overwritten via git push"
                ),
            });
        }
        let prev_cs = old_head.map(|h| store.get_changeset(h)).transpose()?;
        if let Some(ref c) = prev_cs
            && matches!(c.visibility.embargo, Some(EmbargoState::Active { .. }))
        {
            return Err(GitxError::AccessDenied {
                domain: target_domain.to_string(),
                reason: format!(
                    "bookmark '{branch}' points to an active embargo and cannot be overwritten via git push"
                ),
            });
        }
        let prev_target_tree = match prev_cs
            .as_ref()
            .and_then(|c| c.domain_trees.get(target_domain).copied())
        {
            Some(h) => Some(store.get_tree(h)?),
            None => None,
        };
        let prev_public_acl_bytes = match prev_cs
            .as_ref()
            .and_then(|c| c.domain_trees.get(&DomainId::public()).copied())
        {
            Some(h) => {
                let pub_tree = store.get_tree(h)?;
                match pub_tree.entries.get(".gitxacl") {
                    Some(EntryKind::File { blob_hash, .. }) => {
                        Some(store.read_blob_bytes(*blob_hash)?)
                    }
                    _ => None,
                }
            }
            None => None,
        };
        let mut prev_secret_trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
        if let Some(ref c) = prev_cs {
            for (dom, &tree_hash) in &c.domain_trees {
                if dom.is_secret() {
                    prev_secret_trees.insert(dom.clone(), store.get_tree(tree_hash)?);
                }
            }
        }

        // Read ALL pushed tree entries and blobs first and validate BEFORE mutating `store`.
        let ls_out = Command::new("git")
            .arg("-C")
            .arg(bare_dir)
            .args(["ls-tree", "-r", "-z", new_oid])
            .output()?;
        if !ls_out.status.success() {
            let stderr = String::from_utf8_lossy(&ls_out.stderr);
            return Err(GitxError::GitBridge(format!(
                "git ls-tree failed for pushed ref '{branch}': {}",
                stderr.trim()
            )));
        }

        let mut pushed_files: BTreeMap<String, (FileMode, Vec<u8>)> = BTreeMap::new();
        for record in ls_out.stdout.split(|&b| b == 0) {
            if record.is_empty() {
                continue;
            }
            let Some(tab_pos) = record.iter().position(|&b| b == b'\t') else {
                continue;
            };
            let meta = std::str::from_utf8(&record[..tab_pos]).map_err(|e| {
                GitxError::GitBridge(format!("invalid ls-tree metadata UTF-8: {e}"))
            })?;
            let path = std::str::from_utf8(&record[tab_pos + 1..])
                .map_err(|e| GitxError::GitBridge(format!("invalid ls-tree path UTF-8: {e}")))?;
            let mut parts = meta.split_whitespace();
            let mode_str = parts.next().unwrap_or("100644");
            let obj_type = parts.next().unwrap_or("");
            let blob_oid = parts.next().unwrap_or("");
            if obj_type != "blob" || blob_oid.is_empty() {
                continue;
            }
            let mode = match mode_str {
                "100755" => FileMode::Executable,
                "120000" => FileMode::Symlink,
                _ => FileMode::Regular,
            };

            let blob_out = Command::new("git")
                .arg("-C")
                .arg(bare_dir)
                .args(["cat-file", "blob", blob_oid])
                .output()?;
            if !blob_out.status.success() {
                let stderr = String::from_utf8_lossy(&blob_out.stderr);
                return Err(GitxError::GitBridge(format!(
                    "git cat-file blob {blob_oid} failed: {}",
                    stderr.trim()
                )));
            }

            // 1. Enforce path ACL routing: every pushed file must route to `target_domain`.
            let routed_domain = policy.domain_for_path(path);
            if routed_domain != *target_domain {
                return Err(GitxError::AccessDenied {
                    domain: routed_domain.to_string(),
                    reason: format!(
                        "path '{path}' is routed to domain '{routed_domain}' by ACL policy and cannot be pushed into '{target_domain}'"
                    ),
                });
            }

            // 2. Block cross-secret-tree shadowing unless caller is admin or has explicit write on that secret domain.
            for (sdom, stree) in &prev_secret_trees {
                if sdom != target_domain
                    && stree.entries.contains_key(path)
                    && !principal_can_write_secret(sdom)
                {
                    return Err(GitxError::AccessDenied {
                        domain: sdom.to_string(),
                        reason: format!(
                            "path '{path}' exists in protected secret domain '{sdom}' and cannot be shadowed via '{target_domain}'"
                        ),
                    });
                }
            }

            // 3. Zero-trust secret content scan on `public` pushes.
            if target_domain.is_public() {
                let findings = scan_content(path, &blob_out.stdout);
                if !findings.is_empty() {
                    return Err(GitxError::AccessDenied {
                        domain: target_domain.to_string(),
                        reason: format!(
                            "secret detected in pushed file '{path}'; refusing to import into 'public'"
                        ),
                    });
                }
            }

            pushed_files.insert(path.to_string(), (mode, blob_out.stdout));
        }

        // 4. Enforce `.gitxacl` admin authorization & syntax validation (adding, modifying, or deleting).
        if target_domain.is_public() {
            let new_acl_bytes = pushed_files.get(".gitxacl").map(|(_, b)| b.as_slice());
            let acl_changed = match (prev_public_acl_bytes.as_deref(), new_acl_bytes) {
                (None, None) => false,
                (Some(old), Some(new)) => old != new,
                _ => true,
            };
            if acl_changed {
                if !can_admin_acl {
                    return Err(GitxError::AccessDenied {
                        domain: "acl".to_string(),
                        reason: "caller is not authorized to add, modify, or delete .gitxacl via git push".to_string(),
                    });
                }
                if let Some(acl_bytes) = new_acl_bytes {
                    let acl_text = std::str::from_utf8(acl_bytes).map_err(|e| {
                        GitxError::Crypto(format!(".gitxacl must be valid UTF-8: {e}"))
                    })?;
                    let _ = AclPolicy::parse(acl_text)?;
                }
            }
        } else if pushed_files.contains_key(".gitxacl") {
            return Err(GitxError::AccessDenied {
                domain: "acl".to_string(),
                reason: ".gitxacl may only live in the 'public' domain".to_string(),
            });
        }

        // 5. Unconfigured `secret:*` dropbox guard: non-admin callers without explicit write
        //    permission cannot modify or delete existing entries in `target_domain`.
        if target_domain.is_secret()
            && !principal_can_write_secret(target_domain)
            && let Some(ref prev_tree) = prev_target_tree
        {
            for (existing_path, existing_entry) in &prev_tree.entries {
                match existing_entry {
                    EntryKind::EncryptedSecret { .. } => {
                        if pushed_files.contains_key(existing_path) {
                            return Err(GitxError::AccessDenied {
                                domain: target_domain.to_string(),
                                reason: format!(
                                    "not authorized to overwrite existing secret '{existing_path}' in '{target_domain}'"
                                ),
                            });
                        }
                    }
                    EntryKind::File { blob_hash, .. } => {
                        let Some((_, new_bytes)) = pushed_files.get(existing_path) else {
                            return Err(GitxError::AccessDenied {
                                domain: target_domain.to_string(),
                                reason: format!(
                                    "not authorized to delete existing secret '{existing_path}' in '{target_domain}'"
                                ),
                            });
                        };
                        let old_bytes = store.read_blob_bytes(*blob_hash)?;
                        if new_bytes != &old_bytes {
                            return Err(GitxError::AccessDenied {
                                domain: target_domain.to_string(),
                                reason: format!(
                                    "not authorized to overwrite existing secret '{existing_path}' in '{target_domain}'"
                                ),
                            });
                        }
                    }
                    EntryKind::Conflict { .. } => {}
                }
            }
        }

        // Extract commit author/timestamp/message metadata from the pushed Git tip.
        let show_out = Command::new("git")
            .arg("-C")
            .arg(bare_dir)
            .args(["show", "-s", "--format=%an%x00%ae%x00%at%x00%B", new_oid])
            .output()?;
        let show_str = String::from_utf8_lossy(&show_out.stdout);
        let mut fields = show_str.splitn(4, '\0');
        let author_name = fields.next().unwrap_or("git").trim().to_string();
        let author_email = fields.next().unwrap_or("git@local").trim().to_string();
        let ts_secs: i64 = fields
            .next()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or_else(|| Utc::now().timestamp());
        let description = fields.next().unwrap_or("").trim_end().to_string();
        let created_at = DateTime::from_timestamp(ts_secs, 0).unwrap_or_else(Utc::now);

        validated_refs.push(ValidatedRefImport {
            branch: branch.clone(),
            old_head,
            prev_cs,
            prev_target_tree,
            pushed_files,
            author_name,
            author_email,
            created_at,
            description,
        });
    }

    // Pass 2: Every changed ref passed validation — persist immutable blobs/trees/changesets first,
    // then update ALL affected bookmarks atomically in a single transactional `cas_bookmarks` call.
    let mut imported_commits = 0usize;
    let mut head_changeset: Option<ObjectHash> = None;
    let mut last_branch = "master".to_string();
    let mut bookmark_updates: Vec<(String, Option<ObjectHash>, ObjectHash)> =
        Vec::with_capacity(validated_refs.len());

    for item in validated_refs {
        last_branch = item.branch.clone();
        let mut domain_tree = DomainTree::new(target_domain.clone());
        // Preserve existing `EncryptedSecret` envelopes in `target_domain` that are intentionally
        // omitted from plaintext Git staging exports unless explicitly replaced by an authorized caller.
        if let Some(ref prev_tree) = item.prev_target_tree {
            for (existing_path, existing_entry) in &prev_tree.entries {
                if matches!(existing_entry, EntryKind::EncryptedSecret { .. })
                    && !item.pushed_files.contains_key(existing_path)
                {
                    domain_tree.insert(existing_path.clone(), existing_entry.clone());
                }
            }
        }
        for (path, (mode, bytes)) in item.pushed_files {
            let blob = store.put_blob_bytes(&bytes)?;
            domain_tree.insert(
                path,
                EntryKind::File {
                    blob_hash: blob.manifest_hash(),
                    mode,
                    size: blob.total_size,
                },
            );
        }

        // Preserve all untouched domains from the branch's previous ChangeSet!
        let mut domain_trees: BTreeMap<DomainId, ObjectHash> = BTreeMap::new();
        let mut parents = Vec::new();
        let mut public_parents = Vec::new();
        if let Some(prev_hash) = item.old_head
            && let Some(ref prev_c) = item.prev_cs
        {
            for (dom, &tree_hash) in &prev_c.domain_trees {
                if dom != target_domain {
                    domain_trees.insert(dom.clone(), tree_hash);
                }
            }
            parents.push(prev_hash);
            if prev_c.visibility.is_publicly_visible() {
                public_parents.push(prev_c.public_projection_hash);
            } else {
                public_parents.extend(prev_c.public_parents.iter().copied());
            }
        }

        let target_tree_hash = store.put_tree(&domain_tree)?;
        domain_trees.insert(target_domain.clone(), target_tree_hash);

        let visibility = if target_domain.is_public() {
            VisibilityPolicy::public()
        } else {
            VisibilityPolicy::private(target_domain.clone(), false)
        };

        let cs = ChangeSetBuilder::new(Identity {
            name: item.author_name,
            email: item.author_email,
            key_fingerprint: None,
        })
        .parents(parents)
        .public_parents(public_parents)
        .domain_trees(domain_trees)
        .visibility(visibility)
        .created_at(item.created_at)
        .description(item.description)
        .build();

        store.put_changeset(&cs)?;
        bookmark_updates.push((item.branch, item.old_head, cs.id));
        head_changeset = Some(cs.id);
        imported_commits += 1;
    }

    store.cas_bookmarks(&bookmark_updates)?;

    Ok(ImportReport {
        imported_commits,
        head_changeset,
        branch: last_branch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_and_invalid_ssh_commands() {
        let p1 = parse_ssh_command("git-upload-pack '/acme/mono.git'").unwrap();
        assert_eq!(p1.service, GitSshService::UploadPack);
        assert_eq!(p1.raw_repo, "/acme/mono.git");
        assert_eq!(p1.repo_path, "acme/mono");

        let p2 = parse_ssh_command("git upload-pack \"org/service\"").unwrap();
        assert_eq!(p2.service, GitSshService::UploadPack);
        assert_eq!(p2.repo_path, "org/service");

        let p3 = parse_ssh_command("git-receive-pack '/team/app.git'").unwrap();
        assert_eq!(p3.service, GitSshService::ReceivePack);
        assert_eq!(p3.repo_path, "team/app");

        assert!(parse_ssh_command("").is_err());
        assert!(parse_ssh_command("rm -rf /").is_err());
        assert!(parse_ssh_command("git-upload-pack '../etc/passwd'").is_err());
        assert!(parse_ssh_command("git-upload-pack '/acme/repo;id'").is_err());
        assert!(parse_ssh_command("git-upload-pack '/unterminated").is_err());
    }
}
