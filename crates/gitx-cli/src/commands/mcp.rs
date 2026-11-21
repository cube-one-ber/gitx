use crate::repo::Repo;
use anyhow::Result;
use gitx_core::Identity;
use gitx_crypto::Principal;
use gitx_sdk::{AgentRepo, McpServer};
use std::env;
use std::io;

pub fn cmd_mcp(in_memory: bool) -> Result<()> {
    let (agent_repo, active_workspace) = if in_memory {
        let author = default_mcp_identity();
        let principal = Principal::user(author.name.clone());
        let repo = AgentRepo::in_memory(author, principal)?;
        (repo, "default".to_string())
    } else {
        let cwd = env::current_dir()?;
        if let Some((root, config)) = Repo::discover_config(&cwd) {
            let mut principal = Principal::user(config.author.name.clone());
            if let Some(ref fp) = config.author.key_fingerprint {
                principal = principal.with_fingerprint(fp.clone());
            }
            let repo = AgentRepo::open_local(&root, config.author, principal)?;
            (repo, config.active_workspace)
        } else {
            let author = default_mcp_identity();
            let principal = Principal::user(author.name.clone());
            let repo = AgentRepo::open_local(&cwd, author, principal)?;
            (repo, "default".to_string())
        }
    };

    let mut server = McpServer::new(agent_repo).with_default_workspace(active_workspace);
    let stdin = io::stdin();
    let stdout = io::stdout();
    server.run_stdio(stdin.lock(), stdout.lock())?;
    Ok(())
}

fn default_mcp_identity() -> Identity {
    let name = env::var("GITX_AUTHOR_NAME")
        .ok()
        .or_else(|| env::var("USER").ok())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "GitX Agent".to_string());
    let email = env::var("GITX_AUTHOR_EMAIL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("{}@gitx.local", name.to_lowercase().replace(' ', ".")));
    Identity {
        name,
        email,
        key_fingerprint: None,
    }
}
