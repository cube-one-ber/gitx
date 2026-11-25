use crate::commands::remote::{
    build_http_client, parse_json_response, resolve_rpc_target, run_async,
};
use crate::repo::{Repo, WorkspacePointer, load_json_file, save_json_file};
use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use gitx_core::{ChangeSetBuilder, DomainId, DomainTree, EntryKind, OpKind, VisibilityPolicy};
use gitx_crypto::{PublicKeyBundle, UserKeyPair};
use gitx_git_bridge::{export_to_git_repo, import_from_git_repo};
use gitx_server::FleetSyncRecord;
use gitx_store::ObjectStore;
#[cfg(target_os = "linux")]
use gitx_vfs::FuseMountHandle;
use gitx_vfs::{
    EncryptedFleetBundle, FleetOverlayBundle, FleetWorkspaceMetadata, LazyWorkspace,
    LoopbackVfsServer, WorkspaceBackendKind, WorkspaceManager, apply_encrypted_overlay,
    apply_overlay, export_encrypted_overlay, export_overlay_with_metadata,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountBackend {
    Fuse,
    Loopback,
}

impl MountBackend {
    fn as_str(self) -> &'static str {
        match self {
            MountBackend::Fuse => "fuse",
            MountBackend::Loopback => "loopback",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MountRecord {
    workspace: String,
    mountpoint: String,
    backend: String,
    overlay_root: String,
    pid: u32,
    addr: Option<String>,
    stop_file: String,
}

pub fn cmd_ws_add(
    name: String,
    path: Option<PathBuf>,
    mem: bool,
    lazy: bool,
    from_remote: Option<String>,
    share: Vec<String>,
) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;

    // Avoid stale-local-master footgun: prefer explicit `--from-remote` tracking bookmark, or
    // `origin/<default_branch>` when it is strictly newer than local `master`.
    let local_trunk = repo.store.get_bookmark(&repo.config.default_branch)?;
    let remote_bm_name = format!(
        "{}/{}",
        from_remote.as_deref().unwrap_or("origin"),
        repo.config.default_branch
    );
    let remote_trunk = repo.store.get_bookmark(&remote_bm_name)?;

    let base_hash = if from_remote.is_some() {
        remote_trunk.ok_or_else(|| {
            anyhow!(
                "remote tracking bookmark '{remote_bm_name}' not found; run `gitx pull` first"
            )
        })?
    } else if let (Some(rem), Some(loc)) = (remote_trunk, local_trunk) {
        if repo.is_ancestor(loc, rem)? && rem != loc {
            rem
        } else {
            loc
        }
    } else {
        remote_trunk.or(local_trunk).unwrap_or(snap.changeset.id)
    };

    let store_dyn: Arc<dyn ObjectStore> = repo.store.clone();
    let mgr = WorkspaceManager::with_pool_dir(store_dyn, repo.pool_dir());
    let mut lazy_virtual_count = None;

    let ws_ref = if mem {
        let (ws_ref, _vfs) = mgr.create_mem_workspace(&name, base_hash)?;
        ws_ref
    } else if lazy {
        let ws_dir = path.unwrap_or_else(|| repo.gitx_dir.join("workspaces").join(&name));
        let (ws_ref, lazy_ws) = mgr.create_lazy_workspace(&name, &ws_dir, base_hash)?;
        lazy_virtual_count = Some(lazy_ws.stats().total_virtual_files);
        hydrate_shared_overlays(&repo.root, &ws_dir, &share)?;
        ws_ref
    } else {
        let ws_dir = path.unwrap_or_else(|| repo.gitx_dir.join("workspaces").join(&name));
        let (mut ws_ref, _cow) = mgr.create_cow_workspace(&name, &ws_dir, base_hash)?;

        // Give each CoW workspace its own child working-copy ChangeSet (`@`) on top of `base_hash`
        // so parallel edits diverge cleanly from the shared base and auto-merge on `gitx land`.
        let base_cs = repo.store.get_changeset(base_hash)?;
        let working_cs = ChangeSetBuilder::new(repo.config.author.clone())
            .parents(vec![base_cs.id])
            .public_parents(vec![base_cs.public_projection_hash])
            .domain_trees(base_cs.domain_trees.clone())
            .visibility(VisibilityPolicy::public())
            .description("")
            .build();
        repo.store.put_changeset(&working_cs)?;
        ws_ref.head_changeset = working_cs.id;
        ws_ref.head_change_id = working_cs.change_id;
        repo.store.put_workspace(&ws_ref)?;

        let pointer = WorkspacePointer {
            gitx_dir: repo.gitx_dir.clone(),
            workspace: ws_ref.name.clone(),
        };
        save_json_file(&ws_dir.join(".gitx").join("workspace.json"), &pointer)?;
        hydrate_shared_overlays(&repo.root, &ws_dir, &share)?;
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

    if let Some(virtual_files) = lazy_virtual_count {
        println!(
            "Created workspace '{}' (backend: {:?}, head: {}, path: {}, virtual_files: {}, overlay_dirty: 0)",
            ws_ref.name,
            ws_ref.backend,
            ws_ref.head_changeset.short(),
            ws_ref.root_path.as_deref().unwrap_or("<memory>"),
            virtual_files
        );
    } else {
        println!(
            "Created workspace '{}' (backend: {:?}, head: {}, path: {})",
            ws_ref.name,
            ws_ref.backend,
            ws_ref.head_changeset.short(),
            ws_ref.root_path.as_deref().unwrap_or("<memory>")
        );
    }
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

pub fn cmd_ws_mount(name: String, mountpoint: PathBuf, backend: MountBackend) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let ws_ref = repo
        .store
        .get_workspace(&name)?
        .ok_or_else(|| anyhow!("workspace '{name}' not found"))?;

    let cs = repo.store.get_changeset(ws_ref.head_changeset)?;
    let mut tree = DomainTree::new(DomainId::public());
    for tree_hash in cs.domain_trees.values() {
        let domain_tree = repo.store.get_tree(*tree_hash)?;
        for (path, kind) in domain_tree.entries {
            if !matches!(kind, EntryKind::EncryptedSecret { .. }) {
                tree.insert(path, kind);
            }
        }
    }

    let overlay_root = if ws_ref.backend == WorkspaceBackendKind::LazyMount {
        ws_ref
            .root_path
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| repo.gitx_dir.join("overlays").join(&name))
    } else {
        repo.gitx_dir.join("overlays").join(&name)
    };

    fs::create_dir_all(&mountpoint)?;
    let mountpoint = fs::canonicalize(&mountpoint).unwrap_or(mountpoint);
    let mount_key = mountpoint.to_string_lossy().into_owned();

    let stop_file = mount_stop_file(&repo.gitx_dir, &mount_key);
    if stop_file.exists() {
        let _ = fs::remove_file(&stop_file);
    }

    let store_dyn: Arc<dyn ObjectStore> = repo.store.clone();
    let lazy_ws = LazyWorkspace::mount(&overlay_root, Arc::clone(&store_dyn), tree)?;

    match backend {
        MountBackend::Fuse => {
            #[cfg(target_os = "linux")]
            {
                let handle = FuseMountHandle::mount_background(&mountpoint, lazy_ws, store_dyn)?;
                let stats = handle.stats();

                let record = MountRecord {
                    workspace: name.clone(),
                    mountpoint: mount_key.clone(),
                    backend: backend.as_str().to_string(),
                    overlay_root: overlay_root.to_string_lossy().into_owned(),
                    pid: std::process::id(),
                    addr: None,
                    stop_file: stop_file.to_string_lossy().into_owned(),
                };
                register_mount_record(&repo.gitx_dir, record)?;

                println!(
                    "Mounted workspace '{}' at {} (backend: fuse, virtual_files: {}, overlay_dirty: {}, pid: {})",
                    name,
                    mountpoint.display(),
                    stats.total_virtual_files,
                    stats.overlay_dirty_files,
                    std::process::id()
                );
                io::stdout().flush()?;

                while !stop_file.exists() && handle.is_alive() {
                    thread::sleep(Duration::from_millis(50));
                }

                let _ = handle.unmount();
                let _ = fs::remove_file(&stop_file);
                let _ = unregister_mount_record(&repo.gitx_dir, &mount_key);
                println!("Unmounted {}", mountpoint.display());
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (lazy_ws, store_dyn, stop_file, mount_key);
                bail!(
                    "FUSE3 mount backend is only supported on Linux; use `--backend loopback` on this platform"
                );
            }
        }
        MountBackend::Loopback => {
            let server = LoopbackVfsServer::start("127.0.0.1:0", lazy_ws, store_dyn)?;
            let addr = server.addr();
            let stats = server.stats();

            let record = MountRecord {
                workspace: name.clone(),
                mountpoint: mount_key.clone(),
                backend: backend.as_str().to_string(),
                overlay_root: overlay_root.to_string_lossy().into_owned(),
                pid: std::process::id(),
                addr: Some(addr.to_string()),
                stop_file: stop_file.to_string_lossy().into_owned(),
            };
            register_mount_record(&repo.gitx_dir, record)?;

            println!(
                "Mounted workspace '{}' at {} (backend: loopback, addr: {}, virtual_files: {}, overlay_dirty: {}, pid: {})",
                name,
                mountpoint.display(),
                addr,
                stats.total_virtual_files,
                stats.overlay_dirty_files,
                std::process::id()
            );
            io::stdout().flush()?;

            while !stop_file.exists() {
                thread::sleep(Duration::from_millis(50));
            }

            server.shutdown();
            let _ = fs::remove_file(&stop_file);
            let _ = unregister_mount_record(&repo.gitx_dir, &mount_key);
            println!("Unmounted {}", mountpoint.display());
            Ok(())
        }
    }
}

pub fn cmd_ws_unmount(mountpoint: PathBuf) -> Result<()> {
    let resolved = fs::canonicalize(&mountpoint).unwrap_or_else(|_| {
        if mountpoint.is_absolute() {
            mountpoint.clone()
        } else {
            env::current_dir()
                .map(|cwd| cwd.join(&mountpoint))
                .unwrap_or_else(|_| mountpoint.clone())
        }
    });
    let mount_key = resolved.to_string_lossy().into_owned();

    if let Ok(repo) = Repo::open(&env::current_dir()?)
        && let Some(record) = unregister_mount_record(&repo.gitx_dir, &mount_key)?
    {
        if record.backend == "fuse" {
            let _ = unmount_os_fuse(&resolved);
        }
        let stop_path = PathBuf::from(&record.stop_file);
        if let Some(parent) = stop_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&stop_path, b"stop\n")?;
        println!(
            "Unmounted workspace '{}' at {} (backend: {})",
            record.workspace,
            resolved.display(),
            record.backend
        );
        return Ok(());
    }

    if unmount_os_fuse(&resolved).is_ok() {
        println!("Unmounted {}", resolved.display());
        return Ok(());
    }

    bail!("mountpoint '{}' is not an active gitx mount", resolved.display());
}

fn mounts_registry_path(gitx_dir: &Path) -> PathBuf {
    gitx_dir.join("mounts.json")
}

fn mount_stop_file(gitx_dir: &Path, mount_key: &str) -> PathBuf {
    let id = gitx_core::ObjectHash::of_bytes(mount_key.as_bytes()).short();
    gitx_dir.join("mounts").join(format!("{id}.stop"))
}

fn load_mount_registry(gitx_dir: &Path) -> BTreeMap<String, MountRecord> {
    let path = mounts_registry_path(gitx_dir);
    if path.is_file() {
        load_json_file(&path).unwrap_or_default()
    } else {
        BTreeMap::new()
    }
}

fn register_mount_record(gitx_dir: &Path, record: MountRecord) -> Result<()> {
    let mut map = load_mount_registry(gitx_dir);
    map.insert(record.mountpoint.clone(), record);
    save_json_file(&mounts_registry_path(gitx_dir), &map)
}

fn unregister_mount_record(gitx_dir: &Path, mount_key: &str) -> Result<Option<MountRecord>> {
    let mut map = load_mount_registry(gitx_dir);
    let removed = map.remove(mount_key);
    if removed.is_some() {
        save_json_file(&mounts_registry_path(gitx_dir), &map)?;
    }
    Ok(removed)
}

fn unmount_os_fuse(mountpoint: &Path) -> Result<()> {
    for (bin, args) in [
        ("fusermount3", vec!["-u"]),
        ("fusermount", vec!["-u"]),
        ("umount", vec![]),
    ] {
        if let Ok(status) = Command::new(bin).args(&args).arg(mountpoint).status()
            && status.success()
        {
            return Ok(());
        }
    }
    bail!(
        "failed to unmount FUSE mountpoint {}",
        mountpoint.display()
    )
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

pub fn cmd_fleet_export(
    bundle_path: PathBuf,
    include: String,
    encrypted: bool,
    machine: Option<String>,
) -> Result<()> {
    let cwd = env::current_dir()?;
    let patterns: Vec<&str> = include
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if encrypted {
        let repo = Repo::open(&cwd)?;
        let keyring = repo.load_keyring()?;
        let mut recipients: Vec<PublicKeyBundle> = keyring.recipients.values().cloned().collect();
        if recipients.is_empty() {
            let local_kp = UserKeyPair::from_secret_bundle(&keyring.local)?;
            recipients.push(local_kp.public_bundle());
        }

        let machine_id = resolve_machine_id(machine);
        let domain = DomainId::secret("fleet")?;
        let bundle = export_encrypted_overlay(&cwd, &patterns, &machine_id, &domain, 1, &recipients)?;
        let json = bundle.to_json()?;

        if let Some(parent) = bundle_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(&bundle_path, json)?;

        println!(
            "Exported encrypted fleet overlay bundle to {} ({} file(s), machine: {}, recipients: {})",
            bundle_path.display(),
            bundle.file_count,
            bundle.machine_id,
            recipients.len()
        );
        return Ok(());
    }

    let mut metadata = if cwd.join(".gitx").is_dir() {
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

    if let Some(m) = machine {
        metadata.source_machine = Some(m);
    }

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

pub fn cmd_fleet_apply(bundle_path: PathBuf, encrypted: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let json = fs::read_to_string(&bundle_path)?;

    if encrypted {
        let repo = Repo::open(&cwd)?;
        let keypair = repo.load_local_keypair()?;
        let bundle = EncryptedFleetBundle::from_json(&json)?;
        let restored = apply_encrypted_overlay(&cwd, &bundle, &keypair)?;

        println!(
            "Applied encrypted fleet overlay bundle from {} ({} file(s) restored, machine: {})",
            bundle_path.display(),
            restored.len(),
            bundle.machine_id
        );
        for path in &restored {
            println!("  -> {path}");
        }
        return Ok(());
    }

    let bundle = match FleetOverlayBundle::from_json(&json) {
        Ok(b) => b,
        Err(err) => {
            if EncryptedFleetBundle::from_json(&json).is_ok() {
                bail!(
                    "fleet overlay bundle '{}' is end-to-end encrypted; re-run with --encrypted",
                    bundle_path.display()
                );
            }
            return Err(err.into());
        }
    };
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

fn resolve_machine_id(machine: Option<String>) -> String {
    machine
        .filter(|s| !s.trim().is_empty())
        .or_else(|| env::var("HOSTNAME").ok().filter(|s| !s.trim().is_empty()))
        .or_else(|| env::var("USER").ok().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "local".to_string())
}

/// Reflink-hydrate shared heavy ignored directories (such as `node_modules` or build caches)
/// from the primary workspace into a newly created workspace with minimal disk/APFS overhead.
fn hydrate_shared_overlays(src_root: &Path, dst_root: &Path, share: &[String]) -> Result<()> {
    for raw in share {
        let rel = raw.trim().trim_start_matches("./").trim_end_matches('/');
        if rel.is_empty() || rel.contains("..") || Path::new(rel).is_absolute() {
            bail!("invalid --share overlay path '{raw}'");
        }
        let src = src_root.join(rel);
        if !src.exists() {
            continue;
        }
        let dst = dst_root.join(rel);
        reflink_copy_tree(&src, &dst)?;
    }
    Ok(())
}

fn reflink_copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src)?;
    if meta.is_symlink() {
        let target = fs::read_link(src)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, dst)?;
        return Ok(());
    }
    if meta.is_file() {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        reflink_copy::reflink_or_copy(src, dst)?;
        return Ok(());
    }
    if meta.is_dir() {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            reflink_copy_tree(&entry.path(), &dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

/// Live cross-machine encrypted Fleet Sync ("Dropbox for Devs") via `gitx-server`.
#[allow(clippy::too_many_arguments)]
pub fn cmd_fleet_sync(
    remote: Option<String>,
    url: Option<String>,
    include: String,
    machine: Option<String>,
    push: bool,
    pull: bool,
    token: Option<String>,
) -> Result<()> {
    let cwd = env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let (target, auth) = resolve_rpc_target(remote.as_deref(), url.as_deref(), token.as_deref())?;

    let do_push = push || !pull;
    let do_pull = pull || !push;
    let machine_id = resolve_machine_id(machine);

    if do_pull {
        let pulled: Option<FleetSyncRecord> = run_async(async {
            let client = build_http_client()?;
            let resp = auth
                .apply(client.get(target.api_url("fleet")))
                .send()
                .await
                .with_context(|| format!("failed to contact remote {}", target.base_url))?;
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let rec: FleetSyncRecord = parse_json_response(resp, "fleet sync pull").await?;
            Ok(Some(rec))
        })?;

        if let Some(rec) = pulled {
            let keypair = repo.load_local_keypair()?;
            let bundle = EncryptedFleetBundle::from_json(&rec.bundle_json)?;
            let restored = apply_encrypted_overlay(&cwd, &bundle, &keypair)?;
            println!(
                "Fleet pull from {} ({} file(s) restored, source machine: {})",
                target.full_name(),
                restored.len(),
                bundle.machine_id
            );
            for path in &restored {
                println!("  <- {path}");
            }
        } else if pull && !push {
            println!(
                "No fleet overlay bundle stored yet for this identity on {}.",
                target.full_name()
            );
        }
    }

    if do_push {
        let patterns: Vec<&str> = include
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let keyring = repo.load_keyring()?;
        let mut recipients: Vec<PublicKeyBundle> = keyring.recipients.values().cloned().collect();
        if recipients.is_empty() {
            let local_kp = UserKeyPair::from_secret_bundle(&keyring.local)?;
            recipients.push(local_kp.public_bundle());
        }
        let domain = DomainId::secret("fleet")?;
        let bundle =
            export_encrypted_overlay(&cwd, &patterns, &machine_id, &domain, 1, &recipients)?;
        let bundle_json = bundle.to_json()?;
        let payload = json!({
            "bundle_json": bundle_json,
            "machine": machine_id,
        });

        let rec: FleetSyncRecord = run_async(async {
            let client = build_http_client()?;
            let resp = auth
                .apply(client.post(target.api_url("fleet")))
                .json(&payload)
                .send()
                .await
                .with_context(|| format!("failed to contact remote {}", target.base_url))?;
            parse_json_response(resp, "fleet sync push").await
        })?;

        println!(
            "Fleet push to {} ({} file(s) encrypted for {} recipient(s), machine: {}, updated: {})",
            target.full_name(),
            bundle.file_count,
            recipients.len(),
            rec.machine.as_deref().unwrap_or(&machine_id),
            rec.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        );
    }

    Ok(())
}

/// Bidirectional ACL-filtered Git mirror sync (e.g. GitHub / Forgejo / local bare Git remote).
pub fn cmd_mirror_sync(git_remote: String, domains: String, branch: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let _snap = repo.snapshot_working_copy()?;

    let allowed_domains: Vec<DomainId> = domains
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(DomainId::new)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if allowed_domains.is_empty() {
        bail!("--domains must include at least one visibility domain (e.g. 'public')");
    }

    let tmp_dir = env::temp_dir().join(format!(
        "gitx-mirror-{}",
        ulid::Ulid::new().to_string().to_lowercase()
    ));
    fs::create_dir_all(&tmp_dir)?;

    let result = (|| -> Result<()> {
        let bookmarks = repo.store.list_bookmarks()?;
        let proj = export_to_git_repo(repo.store.as_ref(), &tmp_dir, &allowed_domains, &bookmarks)?;

        // 1. Push ACL-filtered projection to the Git mirror remote (if the branch exists in projection).
        if proj.ref_map.contains_key(&branch) {
            let push_out = Command::new("git")
                .arg("-C")
                .arg(&tmp_dir)
                .args([
                    "push",
                    "--force-with-lease",
                    &git_remote,
                    &format!("refs/heads/{branch}:refs/heads/{branch}"),
                ])
                .output()?;
            if !push_out.status.success() {
                let stderr = String::from_utf8_lossy(&push_out.stderr);
                // If remote has newer upstream commits, fetch & import them first.
                let fetch_out = Command::new("git")
                    .arg("-C")
                    .arg(&tmp_dir)
                    .args([
                        "fetch",
                        &git_remote,
                        &format!("refs/heads/{branch}:refs/heads/{branch}"),
                    ])
                    .output()?;
                if fetch_out.status.success() {
                    let imp = import_from_git_repo(
                        &tmp_dir,
                        repo.store.as_ref(),
                        allowed_domains[0].clone(),
                    )?;
                    println!(
                        "Mirror pulled {} upstream commit(s) from '{}' (branch: {})",
                        imp.imported_commits, git_remote, imp.branch
                    );
                } else {
                    bail!("git mirror push failed: {}", stderr.trim());
                }
            } else {
                println!(
                    "Mirror pushed {} commit(s) to '{}' (branch: {}, omitted private files: {})",
                    proj.exported_commits, git_remote, branch, proj.omitted_private_files
                );
            }
        } else {
            // Local repo has no projected commits for `branch`; attempt to pull from mirror.
            let fetch_out = Command::new("git")
                .arg("-C")
                .arg(&tmp_dir)
                .args([
                    "fetch",
                    &git_remote,
                    &format!("refs/heads/{branch}:refs/heads/{branch}"),
                ])
                .output()?;
            if fetch_out.status.success() {
                let imp = import_from_git_repo(
                    &tmp_dir,
                    repo.store.as_ref(),
                    allowed_domains[0].clone(),
                )?;
                println!(
                    "Mirror imported {} commit(s) from '{}' (branch: {})",
                    imp.imported_commits, git_remote, imp.branch
                );
            } else {
                let stderr = String::from_utf8_lossy(&fetch_out.stderr);
                bail!("git mirror fetch failed: {}", stderr.trim());
            }
        }
        Ok(())
    })();

    let _ = fs::remove_dir_all(&tmp_dir);
    result
}
