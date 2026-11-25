use crate::repo::Repo;
use anyhow::{Context, Result, bail};
use chrono::Utc;
use gitx_crypto::{Principal, TokenClaims, sign_token_hmac};
use gitx_server::{AppState, ServerConfig, command_conflict_resolver};
use gitx_store::{BlobBackendConfig, GcsConfig, PostgresConfig, S3Config};
use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[allow(clippy::too_many_arguments)]
pub fn cmd_serve(
    addr: String,
    grpc_addr: Option<String>,
    ssh_addr: Option<String>,
    ssh_keys: Vec<String>,
    data_dir: Option<PathBuf>,
    tokens: Vec<String>,
    signing_secret: Option<String>,
    strict_auth: bool,
    object_store: Option<String>,
    postgres_url: Option<String>,
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

    let ssh_socket: Option<SocketAddr> = match ssh_addr {
        Some(raw) => Some(
            raw.parse()
                .with_context(|| format!("invalid SSH bind address '{raw}'"))?,
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

    for raw_ssh in ssh_keys {
        let (pub_line, principal) = parse_ssh_key_binding(&raw_ssh)?;
        config = config.with_ssh_authorized_key(pub_line, principal);
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

    if let Some(pg_url) = postgres_url.filter(|s| !s.trim().is_empty()) {
        let pg = PostgresConfig::new(pg_url);
        pg.validate()?;
        config = config.with_postgres_config(pg);
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
    if let Some(saddr) = ssh_socket {
        println!("Serving gitx-server SSH on ssh://{saddr}");
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let state = Arc::new(AppState::new(config));
        let http_listener = tokio::net::TcpListener::bind(socket_addr).await?;

        let http_state = Arc::clone(&state);
        let http_fut = async move {
            gitx_server::serve_with_state(http_listener, http_state)
                .await
                .map_err(anyhow::Error::from)
        };

        let grpc_fut = async {
            if let Some(gaddr) = grpc_socket {
                gitx_server::serve_grpc_addr(gaddr, Arc::clone(&state))
                    .await
                    .map_err(anyhow::Error::from)
            } else {
                std::future::pending::<Result<()>>().await
            }
        };

        let ssh_fut = async {
            if let Some(saddr) = ssh_socket {
                gitx_server::serve_ssh_addr(saddr, Arc::clone(&state))
                    .await
                    .map_err(anyhow::Error::from)
            } else {
                std::future::pending::<Result<()>>().await
            }
        };

        tokio::try_join!(http_fut, grpc_fut, ssh_fut)?;
        Ok::<(), anyhow::Error>(())
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

/// Parse `<user>[:teams=a,b][:roles=admin]=<openssh-pub-path-or-inline-key>`.
fn parse_ssh_key_binding(raw: &str) -> Result<(String, Principal)> {
    let Some((spec, key_or_path)) = raw.split_once('=') else {
        bail!(
            "invalid --ssh-key '{raw}': expected '<user>[:teams=a,b][:roles=admin]=<pubkey-or-path>'"
        );
    };
    let (_, principal) = parse_token_binding(&format!("ssh={spec}"))?;
    let key_or_path = key_or_path.trim();
    let pub_line = if std::path::Path::new(key_or_path).is_file() {
        std::fs::read_to_string(key_or_path)
            .with_context(|| format!("failed to read SSH public key file '{key_or_path}'"))?
    } else {
        key_or_path.to_string()
    };
    Ok((pub_line, principal))
}

pub fn parse_blob_backend_uri(uri: &str) -> Result<BlobBackendConfig> {
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
    if let Some(rest) = trimmed.strip_prefix("s3://") {
        let (path_part, query_map) = split_uri_query(rest);
        let (bucket, prefix) = split_bucket_and_prefix(path_part)?;
        let region = query_map
            .get("region")
            .cloned()
            .or_else(|| env::var("AWS_REGION").ok().filter(|s| !s.trim().is_empty()))
            .or_else(|| {
                env::var("AWS_DEFAULT_REGION")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
            })
            .unwrap_or_else(|| "us-east-1".to_string());
        let mut cfg = S3Config::new(bucket, region);
        if let Some(pref) = prefix {
            cfg = cfg.with_prefix(pref);
        }
        if let Some(ep) = query_map.get("endpoint").cloned().or_else(|| {
            env::var("AWS_ENDPOINT_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
        }) {
            cfg = cfg.with_endpoint(ep);
        }
        if let (Ok(ak), Ok(sk)) = (
            env::var("AWS_ACCESS_KEY_ID"),
            env::var("AWS_SECRET_ACCESS_KEY"),
        ) {
            cfg = cfg.with_credentials(ak, sk);
        }
        if let Ok(st) = env::var("AWS_SESSION_TOKEN")
            && !st.trim().is_empty()
        {
            cfg.session_token = Some(st);
        }
        if query_map
            .get("allow_http")
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        {
            cfg = cfg.with_allow_http(true);
        }
        cfg.validate()?;
        return Ok(BlobBackendConfig::S3(cfg));
    }
    if let Some(rest) = trimmed.strip_prefix("r2://") {
        let (path_part, query_map) = split_uri_query(rest);
        let mut segs = path_part.splitn(3, '/');
        let account_id = segs
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("r2:// URI must be 'r2://<account_id>/<bucket>[/prefix]'")
            })?;
        let bucket = segs
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("r2:// URI must be 'r2://<account_id>/<bucket>[/prefix]'")
            })?;
        let prefix = segs
            .next()
            .map(|p| p.trim_matches('/').to_string())
            .filter(|p| !p.is_empty());
        let ak = env::var("R2_ACCESS_KEY_ID")
            .or_else(|_| env::var("AWS_ACCESS_KEY_ID"))
            .unwrap_or_default();
        let sk = env::var("R2_SECRET_ACCESS_KEY")
            .or_else(|_| env::var("AWS_SECRET_ACCESS_KEY"))
            .unwrap_or_default();
        let mut cfg = S3Config::cloudflare_r2(account_id, bucket, ak, sk);
        if let Some(pref) = prefix {
            cfg = cfg.with_prefix(pref);
        }
        if let Some(ep) = query_map.get("endpoint") {
            cfg = cfg.with_endpoint(ep.clone());
        }
        cfg.validate()?;
        return Ok(BlobBackendConfig::S3(cfg));
    }
    if let Some(rest) = trimmed
        .strip_prefix("gcs://")
        .or_else(|| trimmed.strip_prefix("gs://"))
    {
        let (path_part, query_map) = split_uri_query(rest);
        let (bucket, prefix) = split_bucket_and_prefix(path_part)?;
        let mut cfg = GcsConfig::new(bucket);
        if let Some(pref) = prefix {
            cfg = cfg.with_prefix(pref);
        }
        if let Some(sa) = query_map.get("service_account").cloned().or_else(|| {
            env::var("GOOGLE_SERVICE_ACCOUNT")
                .or_else(|_| env::var("GOOGLE_APPLICATION_CREDENTIALS"))
                .ok()
                .filter(|s| !s.trim().is_empty())
        }) {
            cfg = cfg.with_service_account_path(sa);
        }
        if let Ok(key_json) = env::var("GOOGLE_SERVICE_ACCOUNT_KEY")
            && !key_json.trim().is_empty()
        {
            cfg = cfg.with_service_account_key(key_json);
        }
        cfg.validate()?;
        return Ok(BlobBackendConfig::Gcs(cfg));
    }
    bail!(
        "unsupported --object-store URI '{trimmed}': expected 'memory://', 'fs:///path', 's3://bucket[/prefix]', 'r2://account/bucket[/prefix]', or 'gcs://bucket[/prefix]'"
    )
}

fn split_uri_query(raw: &str) -> (&str, BTreeMap<String, String>) {
    let mut map = BTreeMap::new();
    let Some((path, query)) = raw.split_once('?') else {
        return (raw, map);
    };
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && !k.trim().is_empty()
        {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    (path, map)
}

fn split_bucket_and_prefix(raw: &str) -> Result<(String, Option<String>)> {
    let trimmed = raw.trim_matches('/');
    if trimmed.is_empty() {
        bail!("object store URI missing bucket name");
    }
    match trimmed.split_once('/') {
        Some((bucket, pref)) => {
            let clean_pref = pref.trim_matches('/');
            Ok((
                bucket.to_string(),
                if clean_pref.is_empty() {
                    None
                } else {
                    Some(clean_pref.to_string())
                },
            ))
        }
        None => Ok((trimmed.to_string(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_blob_backend_uri;
    use gitx_store::BlobBackendConfig;

    #[test]
    fn parses_all_object_store_uri_schemes() {
        assert!(matches!(
            parse_blob_backend_uri("memory://").unwrap(),
            BlobBackendConfig::InMemory
        ));
        assert!(matches!(
            parse_blob_backend_uri("fs:///tmp/gitx-cas").unwrap(),
            BlobBackendConfig::LocalFileSystem { .. }
        ));
        match parse_blob_backend_uri(
            "s3://my-bucket/org/prefix?region=eu-west-1&endpoint=http://127.0.0.1:9000&allow_http=true",
        )
        .unwrap()
        {
            BlobBackendConfig::S3(cfg) => {
                assert_eq!(cfg.bucket, "my-bucket");
                assert_eq!(cfg.region, "eu-west-1");
                assert_eq!(cfg.prefix.as_deref(), Some("org/prefix"));
                assert_eq!(cfg.endpoint.as_deref(), Some("http://127.0.0.1:9000"));
                assert!(cfg.allow_http);
            }
            other => panic!("expected S3 config, got {other:?}"),
        }
        match parse_blob_backend_uri("r2://acct123/gitx-blobs/prod").unwrap() {
            BlobBackendConfig::S3(cfg) => {
                assert_eq!(cfg.bucket, "gitx-blobs");
                assert_eq!(cfg.region, "auto");
                assert_eq!(
                    cfg.endpoint.as_deref(),
                    Some("https://acct123.r2.cloudflarestorage.com")
                );
                assert_eq!(cfg.prefix.as_deref(), Some("prod"));
            }
            other => panic!("expected R2 S3 config, got {other:?}"),
        }
        match parse_blob_backend_uri("gcs://my-gcs-bucket/cas").unwrap() {
            BlobBackendConfig::Gcs(cfg) => {
                assert_eq!(cfg.bucket, "my-gcs-bucket");
                assert_eq!(cfg.prefix.as_deref(), Some("cas"));
            }
            other => panic!("expected GCS config, got {other:?}"),
        }
    }
}
