//! Real async SSH server transport (`russh`) exposing ACL-filtered `git-upload-pack` and
//! `git-receive-pack` over SSH (`git clone ssh://...` / `git push ssh://...`).
//!
//! Authenticates clients via OpenSSH public keys registered in [`crate::ServerConfig::ssh_authorized_keys`]
//! (with optional anonymous public-only read access) and dispatches every session through
//! [`gitx_git_bridge::GitSshSession`] so private files, private branches, secrets, and
//! active embargoes never cross the SSH wire to unauthorized callers.

use crate::auth::{can_administer_acl, can_write_domain_effective, readable_non_embargo_domains};
use crate::state::AppState;
use bytes::Bytes;
use gitx_core::{DomainId, GitxError, Result};
use gitx_crypto::{Principal, UserKeyPair, encode_openssh_ed25519_private};
use gitx_git_bridge::{GitSshService, GitSshSession, parse_ssh_command};
use russh::keys::{PrivateKey, ssh_key};
use russh::server::{
    Auth, ChannelOpenHandle, Config, Handler, Msg, Server, Session, VerifiedPublicKey,
};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use tokio::net::TcpListener;

/// Serve the GitX ACL-enforcing SSH server on a pre-bound `TcpListener`.
pub async fn serve_ssh(listener: TcpListener, state: Arc<AppState>) -> Result<()> {
    let host_key = load_or_generate_host_key(&state.config.data_dir)?;
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::PublicKey);

    let mut cfg = Config {
        methods,
        auth_rejection_time: std::time::Duration::from_millis(50),
        auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
        nodelay: true,
        ..Default::default()
    };
    cfg.keys.push(host_key);

    if let Ok(local_addr) = listener.local_addr() {
        tracing::info!("gitx-server SSH listening on ssh://{local_addr}");
    }

    let mut server = GitxSshServer { state };
    server
        .run_on_socket(Arc::new(cfg), &listener)
        .await
        .map_err(GitxError::Io)
}

/// Bind `addr` and serve the GitX ACL-enforcing SSH server.
pub async fn serve_ssh_addr(addr: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(addr).await.map_err(GitxError::Io)?;
    serve_ssh(listener, state).await
}

fn load_or_generate_host_key(data_dir: &std::path::Path) -> Result<PrivateKey> {
    let key_path = data_dir.join("ssh_host_ed25519_key");
    if key_path.is_file()
        && let Ok(pem) = std::fs::read_to_string(&key_path)
        && let Ok(key) = PrivateKey::from_openssh(&pem)
    {
        return Ok(key);
    }

    let kp = UserKeyPair::generate();
    let bundle = kp.to_secret_bundle();
    let pem = encode_openssh_ed25519_private(&bundle.ed25519_secret, "gitx-host");
    let key = PrivateKey::from_openssh(&pem)
        .map_err(|e| GitxError::Crypto(format!("failed to generate SSH host key: {e}")))?;

    if std::fs::create_dir_all(data_dir).is_ok()
        && let Ok(pem_out) = key.to_openssh(ssh_key::LineEnding::LF)
    {
        let _ = std::fs::write(&key_path, pem_out.as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }
    }
    Ok(key)
}

struct GitxSshServer {
    state: Arc<AppState>,
}

impl Server for GitxSshServer {
    type Handler = GitxSshHandler;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        GitxSshHandler {
            state: Arc::clone(&self.state),
            principal: Principal::anonymous(),
            git_protocol: None,
            stdin_senders: HashMap::new(),
        }
    }
}

struct GitxSshHandler {
    state: Arc<AppState>,
    principal: Principal,
    git_protocol: Option<String>,
    stdin_senders: HashMap<ChannelId, mpsc::Sender<Vec<u8>>>,
}

impl Handler for GitxSshHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> std::result::Result<Auth, Self::Error> {
        // OpenSSH always sends an initial `none` auth probe to discover supported methods.
        // Reject `none` for normal SSH users (e.g. `git`) so the client proceeds to offer its
        // public key in `auth_publickey`; only allow explicit `anonymous` user on `none`.
        if self.state.config.allow_anonymous_ssh_read && user.eq_ignore_ascii_case("anonymous") {
            self.principal = Principal::anonymous();
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> std::result::Result<Auth, Self::Error> {
        if let Ok(openssh_pub) = key.public_key.to_openssh()
            && let Some(principal) = self.state.resolve_ssh_key(&openssh_pub)
        {
            self.principal = principal;
            return Ok(Auth::Accept);
        }
        if self.state.config.allow_anonymous_ssh_read {
            self.principal = Principal::anonymous();
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if variable_name == "GIT_PROTOCOL" {
            self.git_protocol = Some(variable_value.to_string());
            let _ = session.channel_success(channel);
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let Ok(cmd_str) = std::str::from_utf8(data) else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        let parsed = match parse_ssh_command(cmd_str) {
            Ok(p) => p,
            Err(err) => {
                let _ = session.channel_success(channel);
                let _ = session.extended_data(channel, 1, Bytes::from(format!("ERR {err}\n")));
                let _ = session.exit_status_request(channel, 1);
                let _ = session.eof(channel);
                let _ = session.close(channel);
                return Ok(());
            }
        };

        let Some((owner, name)) = split_owner_repo(&parsed.repo_path) else {
            let _ = session.channel_success(channel);
            let _ = session.extended_data(
                channel,
                1,
                Bytes::from(format!(
                    "ERR invalid repository path '{}': expected '<owner>/<repo>'\n",
                    parsed.repo_path
                )),
            );
            let _ = session.exit_status_request(channel, 1);
            let _ = session.eof(channel);
            let _ = session.close(channel);
            return Ok(());
        };

        let _ = session.channel_success(channel);
        let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>();
        self.stdin_senders.insert(channel, stdin_tx);

        let state = Arc::clone(&self.state);
        let principal = self.principal.clone();
        let git_protocol = self.git_protocol.clone();
        let command_owned = cmd_str.to_string();
        let handle = session.handle();
        let rt_handle = tokio::runtime::Handle::current();

        tokio::task::spawn_blocking(move || {
            let reader = ChannelReader {
                rx: stdin_rx,
                buf: Vec::new(),
                pos: 0,
            };
            let writer = ChannelWriter {
                handle: handle.clone(),
                channel,
                rt: rt_handle.clone(),
            };

            let exit_code = match run_ssh_git_session(
                &state,
                &principal,
                &owner,
                &name,
                parsed.service,
                &command_owned,
                git_protocol.as_deref(),
                reader,
                writer,
            ) {
                Ok(()) => 0u32,
                Err(err) => {
                    let msg = format!("gitx-ssh error: {err}\n");
                    let _ = rt_handle.block_on(handle.extended_data(channel, 1, Bytes::from(msg)));
                    1u32
                }
            };

            rt_handle.block_on(async {
                let _ = handle.exit_status_request(channel, exit_code).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
        });

        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(tx) = self.stdin_senders.get(&channel) {
            let _ = tx.send(data.to_vec());
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.stdin_senders.remove(&channel);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.stdin_senders.remove(&channel);
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn run_ssh_git_session<R, W>(
    state: &AppState,
    principal: &Principal,
    owner: &str,
    name: &str,
    service: GitSshService,
    command: &str,
    git_protocol: Option<&str>,
    reader: R,
    writer: W,
) -> Result<()>
where
    R: Read + Send,
    W: Write,
{
    match service {
        GitSshService::UploadPack => {
            let repo = state.get_repo(owner, name)?.ok_or_else(|| {
                GitxError::NotFound(format!("repository '{owner}/{name}' not found"))
            })?;
            let policy = repo.acl_snapshot()?;
            let allowed_domains =
                readable_non_embargo_domains(repo.store.as_ref(), &policy, principal);
            let mut ssh_sess = GitSshSession::new(repo.store.as_ref(), allowed_domains)
                .with_acl_policy(policy)
                .with_principal(principal.clone());
            if let Some(proto) = git_protocol {
                ssh_sess = ssh_sess.with_git_protocol(proto);
            }
            ssh_sess.run(command, reader, writer)?;
            Ok(())
        }
        GitSshService::ReceivePack => {
            if principal.is_anonymous {
                return Err(GitxError::AccessDenied {
                    domain: "public".to_string(),
                    reason: "anonymous callers are not permitted to git-push over SSH".to_string(),
                });
            }
            let repo = state.get_or_create_repo(owner, name)?;
            let policy = repo.acl_snapshot()?;
            let target_domain = DomainId::public();
            if !can_write_domain_effective(&policy, principal, &target_domain, &[]) {
                return Err(GitxError::AccessDenied {
                    domain: target_domain.to_string(),
                    reason: format!(
                        "principal '{}' is not authorized to push to '{owner}/{name}'",
                        principal.id
                    ),
                });
            }
            let allowed_domains =
                readable_non_embargo_domains(repo.store.as_ref(), &policy, principal);
            let can_admin = can_administer_acl(&policy, principal);
            let prev_master = repo.store.get_bookmark("master")?;
            let mut ssh_sess = GitSshSession::new(repo.store.as_ref(), allowed_domains)
                .with_write_domain(target_domain)
                .with_acl_policy(policy)
                .with_principal(principal.clone())
                .with_acl_admin(can_admin);
            if let Some(proto) = git_protocol {
                ssh_sess = ssh_sess.with_git_protocol(proto);
            }
            ssh_sess.run(command, reader, writer)?;
            let new_master = repo.store.get_bookmark("master")?;
            repo.reload_acl_if_master_acl_changed(prev_master, new_master)?;
            Ok(())
        }
    }
}

fn split_owner_repo(repo_path: &str) -> Option<(String, String)> {
    let trimmed = repo_path.trim_matches('/');
    let (owner, name) = trimmed.split_once('/')?;
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return None;
    }
    Some((owner.to_string(), name.to_string()))
}

struct ChannelReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let avail = &self.buf[self.pos..];
        let n = avail.len().min(out.len());
        out[..n].copy_from_slice(&avail[..n]);
        self.pos += n;
        Ok(n)
    }
}

struct ChannelWriter {
    handle: russh::server::Handle,
    channel: ChannelId,
    rt: tokio::runtime::Handle,
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        for chunk in buf.chunks(16_384) {
            self.rt
                .block_on(
                    self.handle
                        .data(self.channel, Bytes::copy_from_slice(chunk)),
                )
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "SSH channel closed"))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
