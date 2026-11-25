use crate::repo::Repo;
use anyhow::{Context, Result, bail};
use chrono::Utc;
use gitx_crypto::{Principal, TokenClaims, sign_token_hmac};
use gitx_server::{AppState, ServerConfig, command_conflict_resolver};
use gitx_store::BlobBackendConfig;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[allow(clippy::too_many_arguments)]
pub fn cmd_serve(
    addr: String,
    grpc_addr: Option<String>,
    data_dir: Option<PathBuf>,
    tokens: Vec<String>,
    signing_secret: Option<String>,
    strict_auth: bool,
    object_store: Option<String>,
    webhook_urls: Vec<String>,
    conflict_resolver_cmd: Option<String>,
    post_land_cmd: Option<String>,
) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let socket_addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid bind address '{addr}'"))?;

    let grpc_socket: Option<SocketAddr> = match grpc_addr {
        Some(raw) => Some(
            raw.parse()
                .with_context(|| format!("invalid gRPC bind address '{raw}'"))?,
        ),
        None => None,
    };

    let resolved_data_dir = match data_dir {
        Some(dir) => dir,
        None => {
            let cwd = env::current_dir()?;
            if let Ok(repo) = Repo::open(&cwd) {
                repo.gitx_dir.join("server-data")
            } else {
                cwd.join("gitx-server-data")
            }
        }
    };

    let mut config = ServerConfig::new(&resolved_data_dir);

    for raw_tok in tokens {
        let (tok, principal) = parse_token_binding(&raw_tok)?;
        config = config.with_token(tok, principal);
    }

    if let Some(secret) = signing_secret.filter(|s| !s.is_empty()) {
        config = config.with_token_signing_secret(secret.into_bytes());
    }

    if strict_auth {
        config = config.with_trust_proxy_headers(false);
    }

    if let Some(uri) = object_store.filter(|s| !s.trim().is_empty()) {
        let backend = parse_blob_backend_uri(&uri)?;
        config = config.with_blob_backend(backend);
    }

    for url in webhook_urls {
        if !url.trim().is_empty() {
            config = config.with_webhook_url(url);
        }
    }

    if let Some(cmd) = conflict_resolver_cmd.filter(|c| !c.trim().is_empty()) {
        config = config.with_conflict_resolver(command_conflict_resolver(cmd));
    }

    if let Some(cmd) = post_land_cmd.filter(|c| !c.trim().is_empty()) {
        config = config.with_post_land_cmd(cmd);
    }

    if !socket_addr.ip().is_loopback()
        && config.tokens.is_empty()
        && config.token_signing_secret.is_none()
    {
        tracing::warn!(
            "Binding gitx-server to non-loopback address {} with no bearer tokens or signing secret configured; \
             only expose this behind a trusted reverse proxy that strips client X-Gitx-* headers.",
            socket_addr
        );
    }

    println!(
        "Serving gitx-server HTTP on http://{} (data dir: {})",
        socket_addr,
        resolved_data_dir.display()
    );
    if let Some(gaddr) = grpc_socket {
        println!("Serving gitx-server gRPC on grpc://{gaddr}");
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let state = Arc::new(AppState::new(config));
        let http_listener = tokio::net::TcpListener::bind(socket_addr).await?;

        if let Some(gaddr) = grpc_socket {
            let grpc_state = Arc::clone(&state);
            let grpc_fut = async move {
                gitx_server::serve_grpc_addr(gaddr, grpc_state)
                    .await
                    .map_err(anyhow::Error::from)
            };
            let http_fut = async move {
                gitx_server::serve_with_state(http_listener, state)
                    .await
                    .map_err(anyhow::Error::from)
            };
            tokio::try_join!(http_fut, grpc_fut)?;
            Ok::<(), anyhow::Error>(())
        } else {
            gitx_server::serve_with_state(http_listener, state)
                .await
                .map_err(anyhow::Error::from)
        }
    })
}

pub fn cmd_token_mint(
    secret: String,
    user: String,
    teams: Option<String>,
    roles: Option<String>,
    ttl_secs: Option<i64>,
) -> Result<()> {
    let now = Utc::now().timestamp();
    let mut claims = TokenClaims::new(user, now);
    if let Some(t) = teams {
        let list: Vec<String> = t
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        claims = claims.with_teams(list);
    }
    if let Some(r) = roles {
        let list: Vec<String> = r
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        claims = claims.with_roles(list);
    }
    if let Some(ttl) = ttl_secs {
        claims = claims.with_expires_at(now + ttl);
    }
    let token = sign_token_hmac(&claims, secret.as_bytes())?;
    println!("{token}");
    Ok(())
}

/// Parse `<token>=<user>[:teams=a,b][:roles=admin]` into `(token, Principal)`.
fn parse_token_binding(raw: &str) -> Result<(String, Principal)> {
    let Some((tok, spec)) = raw.split_once('=') else {
        bail!("invalid --token '{raw}': expected '<token>=<user>[:teams=a,b][:roles=admin]'");
    };
    let tok = tok.trim();
    if tok.is_empty() {
        bail!("--token value must not be empty");
    }
    let mut parts = spec.split(':');
    let user = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing user in --token '{raw}'"))?;
    let mut principal = Principal::user(user);
    for seg in parts {
        if let Some(v) = seg.strip_prefix("teams=") {
            let list: Vec<String> = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
            if !list.is_empty() {
                principal = principal.with_teams(list);
            }
        } else if let Some(v) = seg.strip_prefix("roles=") {
            let list: Vec<String> = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
            if !list.is_empty() {
                principal = principal.with_roles(list);
            }
        }
    }
    Ok((tok.to_string(), principal))
}

fn parse_blob_backend_uri(uri: &str) -> Result<BlobBackendConfig> {
    let trimmed = uri.trim();
    if trimmed == "memory://" || trimmed == "memory" {
        return Ok(BlobBackendConfig::InMemory);
    }
    if let Some(path) = trimmed.strip_prefix("fs://") {
        if path.is_empty() {
            bail!("fs:// object store URI requires a directory path");
        }
        return Ok(BlobBackendConfig::LocalFileSystem {
            root: PathBuf::from(path),
        });
    }
    bail!(
        "unsupported --object-store URI '{trimmed}': expected 'memory://' or 'fs:///path/to/cas'"
    )
}
