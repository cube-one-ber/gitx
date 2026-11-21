use crate::repo::Repo;
use anyhow::{Result, bail};
use gitx_core::{DomainId, OpKind};
use gitx_git_bridge::export_to_git_repo;
use gitx_store::ObjectStore;
use gitx_vfs::{
    FleetOverlayBundle, FleetWorkspaceMetadata, WorkspaceManager, apply_overlay,
    export_overlay_with_metadata,
};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

pub fn cmd_ws_add(name: String, path: Option<PathBuf>, mem: bool) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;

    let base_hash = repo
        .store
        .get_bookmark(&repo.config.default_branch)?
        .unwrap_or(snap.changeset.id);

    let store_dyn: Arc<dyn ObjectStore> = repo.store.clone();
    let mgr = WorkspaceManager::with_pool_dir(store_dyn, repo.pool_dir());
    let ws_ref = if mem {
        let (ws_ref, _vfs) = mgr.create_mem_workspace(&name, base_hash)?;
        ws_ref
    } else {
        let ws_dir = path.unwrap_or_else(|| repo.gitx_dir.join("workspaces").join(&name));
        let (ws_ref, _cow) = mgr.create_cow_workspace(&name, &ws_dir, base_hash)?;
        ws_ref
    };

    repo.append_op(
        OpKind::WorkspaceCreate { name: name.clone() },
        format!(
            "Created {:?} workspace '{}' at {}",
            ws_ref.backend,
            ws_ref.name,
            ws_ref.head_changeset.short()
        ),
    )?;

    println!(
        "Created workspace '{}' (backend: {:?}, head: {}, path: {})",
        ws_ref.name,
        ws_ref.backend,
        ws_ref.head_changeset.short(),
        ws_ref.root_path.as_deref().unwrap_or("<memory>")
    );
    Ok(())
}

pub fn cmd_ws_list() -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let workspaces = repo.store.list_workspaces()?;
    if workspaces.is_empty() {
        println!("No workspaces registered.");
        return Ok(());
    }
    for ws in workspaces.values() {
        let active = if ws.name == repo.config.active_workspace {
            "*"
        } else {
            " "
        };
        println!(
            "{active} {} [{:?}] @ {} ({}) path={}",
            ws.name,
            ws.backend,
            ws.head_change_id.short(),
            ws.head_changeset.short(),
            ws.root_path.as_deref().unwrap_or("<memory>")
        );
    }
    Ok(())
}

pub fn cmd_ws_rm(name: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    if name == repo.config.active_workspace {
        bail!("cannot remove the active workspace '{name}'");
    }
    let store_dyn: Arc<dyn ObjectStore> = repo.store.clone();
    let mgr = WorkspaceManager::with_pool_dir(store_dyn, repo.pool_dir());
    mgr.remove_workspace(&name)?;

    repo.append_op(
        OpKind::WorkspaceRemove { name: name.clone() },
        format!("Removed workspace '{name}'"),
    )?;
    println!("Removed workspace '{name}'");
    Ok(())
}

pub fn cmd_git_export(target_dir: PathBuf, domains: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;

    let allowed_domains: Vec<DomainId> = domains
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(DomainId::new)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut bookmarks = repo.store.list_bookmarks()?;
    let head_already_bookmarked = bookmarks.values().any(|&h| h == snap.changeset.id);
    if !head_already_bookmarked {
        bookmarks.insert("head".to_string(), snap.changeset.id);
    }

    let report = export_to_git_repo(
        repo.store.as_ref(),
        &target_dir,
        &allowed_domains,
        &bookmarks,
    )?;

    println!("Exported Git repository to {}", target_dir.display());
    println!("  exported_commits:        {}", report.exported_commits);
    println!("  skipped_private_commits: {}", report.skipped_private_commits);
    println!("  omitted_private_files:   {}", report.omitted_private_files);
    for (branch, oid) in &report.ref_map {
        println!("  ref refs/heads/{branch}: {oid}");
    }
    Ok(())
}

pub fn cmd_fleet_export(bundle_path: PathBuf, include: String) -> Result<()> {
    let cwd = env::current_dir()?;
    let patterns: Vec<&str> = include
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let metadata = if cwd.join(".gitx").is_dir() {
        if let Ok(repo) = Repo::open(&cwd) {
            if let Ok(ws) = repo.active_workspace_ref() {
                FleetWorkspaceMetadata::from_workspace_ref(&ws)
            } else {
                FleetWorkspaceMetadata::default()
            }
        } else {
            FleetWorkspaceMetadata::default()
        }
    } else {
        FleetWorkspaceMetadata::default()
    };

    let bundle = export_overlay_with_metadata(&cwd, &patterns, metadata)?;
    let json = bundle.to_json()?;

    if let Some(parent) = bundle_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(&bundle_path, json)?;

    println!(
        "Exported fleet overlay bundle to {} ({} file(s))",
        bundle_path.display(),
        bundle.files.len()
    );
    for path in bundle.files.keys() {
        println!("  + {path}");
    }
    Ok(())
}

pub fn cmd_fleet_apply(bundle_path: PathBuf) -> Result<()> {
    let cwd = env::current_dir()?;
    let json = fs::read_to_string(&bundle_path)?;
    let bundle = FleetOverlayBundle::from_json(&json)?;
    let restored = apply_overlay(&cwd, &bundle)?;

    println!(
        "Applied fleet overlay bundle from {} ({} file(s) restored)",
        bundle_path.display(),
        restored.len()
    );
    for path in &restored {
        println!("  -> {path}");
    }
    Ok(())
}
