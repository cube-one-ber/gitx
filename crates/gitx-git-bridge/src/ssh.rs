//! ACL-filtered Git SSH transport adapter (`git-upload-pack` and `git-receive-pack`).
//!
//! Parses standard Git SSH remote commands (`git-upload-pack '<repo>'`,
//! `git-receive-pack '<repo>'`), dynamically projects strictly the caller's authorized
//! [`DomainId`]s into an ephemeral bare Git repository using [`export_to_git_repo`], and
//! streams standard Git pkt-line wire protocol frames over arbitrary [`Read`]/[`Write`]
//! streams so unauthorized domains, private branches, and secrets never cross the wire.

use crate::import::{ImportReport, import_from_git_repo};
use crate::objects::GitOid;
use crate::pktline::{PktLine, decode_pkt_lines, encode_flush_pkt, encode_pkt_line};
use crate::project::{ProjectionReport, export_to_git_repo};
use gitx_core::{DomainId, GitxError, Result};
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
}

impl<'a> GitSshSession<'a> {
    /// Creates a read-only ACL-filtered Git SSH session restricted strictly to `allowed_domains`.
    pub fn new(store: &'a dyn ObjectStore, allowed_domains: Vec<DomainId>) -> Self {
        Self {
            store,
            allowed_domains,
            write_domain: None,
            git_protocol: None,
        }
    }

    /// Enables `git-receive-pack` pushes imported into `domain` (which must also be authorized
    /// in `allowed_domains`).
    pub fn with_write_domain(mut self, domain: DomainId) -> Self {
        self.write_domain = Some(domain);
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
                    let err_pkt = encode_pkt_line(b"ERR write access denied for this SSH session\n");
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

                let tmp = TempDir::new()?;
                let bookmarks = self.store.list_bookmarks()?;
                let projection =
                    export_to_git_repo(self.store, tmp.path(), &self.allowed_domains, &bookmarks)?;

                let bytes_written = run_git_ssh_process(
                    "receive-pack",
                    tmp.path(),
                    self.git_protocol.as_deref(),
                    input,
                    &mut output,
                )?;

                let imported = import_from_git_repo(tmp.path(), self.store, target_domain.clone())?;

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
    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| GitxError::GitBridge(format!("failed to open stdin for git {subcommand}")))?;
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
