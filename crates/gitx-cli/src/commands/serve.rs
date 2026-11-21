use crate::repo::Repo;
use anyhow::{Context, Result};
use gitx_server::ServerConfig;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

pub fn cmd_serve(addr: String, data_dir: Option<PathBuf>) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let socket_addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid bind address '{addr}'"))?;

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

    let config = ServerConfig::new(&resolved_data_dir);
    tracing::info!(
        "Starting gitx-server on http://{} (data dir: {})",
        socket_addr,
        resolved_data_dir.display()
    );
    println!(
        "Serving gitx-server on http://{} (data dir: {})",
        socket_addr,
        resolved_data_dir.display()
    );

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        gitx_server::serve_addr(socket_addr, config)
            .await
            .map_err(anyhow::Error::from)
    })
}
