use gitx_core::oplog::WorkspaceBackendKind;
use gitx_core::{
    ChangeSetBuilder, ConflictTerm, DomainId, DomainTree, EntryKind, FileMode, GitxError, Identity,
    ObjectHash,
};
use gitx_store::{MemoryStore, ObjectStore};
use gitx_vfs::{
    CowWorkspace, FleetOverlayBundle, FleetWorkspaceMetadata, MemVfs, WorkspaceBackend,
    WorkspaceChanges, WorkspaceManager, apply_overlay, export_overlay,
    export_overlay_with_metadata, normalize_rel_path,
};
use std::fs;
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

fn test_identity() -> Identity {
    Identity {
        name: "Dev Agent".to_string(),
        email: "agent@gitx.dev".to_string(),
        key_fingerprint: None,
    }
}

fn seed_base_repo(store: &dyn ObjectStore) -> (ObjectHash, DomainTree) {
    let mut tree = DomainTree::new(DomainId::public());
    for (path, content, mode) in [
        ("README.md", b"# gitx repo\n".as_slice(), FileMode::Regular),
        (
            "src/main.rs",
            b"fn main() { println!(\"hello\"); }\n".as_slice(),
            FileMode::Regular,
        ),
        (
            "scripts/run.sh",
            b"#!/usr/bin/env sh\necho running\n".as_slice(),
            FileMode::Executable,
        ),
    ] {
        let blob = store.put_blob_bytes(content).expect("put blob");
        tree.insert(
            path,
            EntryKind::File {
                blob_hash: blob.manifest_hash(),
                mode,
                size: blob.total_size,
            },
        );
    }

    let tree_hash = store.put_tree(&tree).expect("put tree");
    let cs = ChangeSetBuilder::new(test_identity())
        .domain_tree(DomainId::public(), tree_hash)
        .description("initial commit")
        .build();
    let cs_id = store.put_changeset(&cs).expect("put changeset");
    store.set_bookmark("master", cs_id).expect("set master");
    (cs_id, tree)
}

#[test]
fn mem_vfs_fan_out_50_parallel_workspaces_off_same_base_without_locking() {
    let store: Arc<dyn ObjectStore> = Arc::new(MemoryStore::new());
    let (base_cs, base_tree) = seed_base_repo(store.as_ref());
    let manager = Arc::new(WorkspaceManager::new(Arc::clone(&store)));

    // Pre-seed a template MemVfs to also exercise O(1) clone_instant alongside manager creation.
    let base_mem = MemVfs::from_tree(&base_tree, store.as_ref()).expect("from_tree");
    assert_eq!(base_mem.backend_kind(), WorkspaceBackendKind::Memory);
    assert_eq!(base_mem.len(), 3);

    let handles: Vec<_> = (0..50)
        .map(|i| {
            let manager = Arc::clone(&manager);
            let store = Arc::clone(&store);
            let base_tree = base_tree.clone();
            let instant_fork = base_mem.clone_instant();
            thread::spawn(move || {
                let ws_name = format!("agent-{i:02}");
                let (ws_ref, mut vfs) = manager
                    .create_mem_workspace(&ws_name, base_cs)
                    .expect("create mem workspace without lock contention");
                assert_eq!(ws_ref.head_changeset, base_cs);
                assert_eq!(ws_ref.backend, WorkspaceBackendKind::Memory);

                // Independent edits per agent: add a unique file, modify src/main.rs, and on
                // even indices remove README.md.
                let agent_file = format!("agents/out_{i:02}.txt");
                vfs.write_file(
                    &agent_file,
                    format!("agent {i} payload").as_bytes(),
                    FileMode::Regular,
                )
                .expect("write agent file");
                vfs.write_file(
                    "src/main.rs",
                    format!("fn main() {{ println!(\"agent {i}\"); }}\n").as_bytes(),
                    FileMode::Regular,
                )
                .expect("modify main.rs");
                if i % 2 == 0 {
                    vfs.remove_file("README.md").expect("remove README.md");
                }

                // Verify instant fork remained untouched by sibling edits.
                assert_eq!(
                    instant_fork.read_file("src/main.rs").unwrap(),
                    b"fn main() { println!(\"hello\"); }\n"
                );
                let mut local_fork = instant_fork.clone_instant();
                local_fork
                    .write_file("scratch.txt", format!("fork {i}").as_bytes(), FileMode::Regular)
                    .unwrap();
                assert!(!instant_fork.contains("scratch.txt"));

                let snap = vfs
                    .snapshot_tree(DomainId::public(), store.as_ref())
                    .expect("snapshot");
                let changes = WorkspaceManager::detect_changes(&snap, &base_tree);
                assert_eq!(changes.added, vec![agent_file]);
                assert_eq!(changes.modified, vec!["src/main.rs".to_string()]);
                if i % 2 == 0 {
                    assert_eq!(changes.removed, vec!["README.md".to_string()]);
                } else {
                    assert!(changes.removed.is_empty());
                }
                (ws_name, snap)
            })
        })
        .collect();

    let mut snapshots = Vec::with_capacity(50);
    for h in handles {
        snapshots.push(h.join().expect("agent thread succeeded"));
    }

    // All 50 workspaces are registered simultaneously on the same base ChangeSet.
    let all_ws = manager.list_workspaces().expect("list workspaces");
    assert_eq!(all_ws.len(), 50);
    assert!(all_ws.values().all(|w| w.head_changeset == base_cs));

    // All 50 snapshots have distinct tree hashes because each made unique edits.
    let unique_hashes: std::collections::BTreeSet<_> =
        snapshots.iter().map(|(_, t)| t.hash()).collect();
    assert_eq!(unique_hashes.len(), 50);

    // Base MemVfs is still completely pristine.
    assert_eq!(
        base_mem.read_file("README.md").unwrap(),
        b"# gitx repo\n"
    );
    assert_eq!(base_mem.list_files().unwrap().len(), 3);
}

#[test]
fn cow_workspace_materialization_pool_exec_mode_and_roundtrip() {
    let tmp = TempDir::new().expect("tempdir");
    let pool_dir = tmp.path().join("cas-pool");
    let ws1_root = tmp.path().join("ws1");
    let ws2_root = tmp.path().join("ws2");

    let store: Arc<dyn ObjectStore> = Arc::new(MemoryStore::new());
    let (base_cs, base_tree) = seed_base_repo(store.as_ref());

    let mut ws1 = CowWorkspace::open(&ws1_root, &pool_dir).expect("open ws1");
    assert_eq!(ws1.backend_kind(), WorkspaceBackendKind::CopyOnWrite);
    ws1.materialize_tree(&base_tree, store.as_ref())
        .expect("materialize ws1");

    // Verify shared CAS pool contains all 3 blobs as read-only files.
    for kind in base_tree.entries.values() {
        if let EntryKind::File { blob_hash, .. } = kind {
            let pool_file = ws1.pool_path_for(*blob_hash);
            assert!(pool_file.is_file(), "pool blob should exist");
            let perms = fs::metadata(&pool_file).unwrap().permissions();
            assert!(perms.readonly(), "pool blob should be read-only");
        }
    }

    // Verify executable bit is preserved on Unix and files are writable in the workspace.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script_mode = fs::metadata(ws1_root.join("scripts/run.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(script_mode & 0o111, 0, "scripts/run.sh must be executable");
        assert_ne!(script_mode & 0o200, 0, "workspace file must be writable");

        let readme_mode = fs::metadata(ws1_root.join("README.md"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(readme_mode & 0o111, 0, "README.md must not be executable");
    }

    // Re-materializing the identical tree skips unchanged files cleanly.
    ws1.materialize_tree(&base_tree, store.as_ref())
        .expect("re-materialize unchanged");

    // Snapshot roundtrip reproduces the exact base DomainTree hash!
    let roundtrip = ws1
        .snapshot_tree(DomainId::public(), store.as_ref())
        .expect("snapshot roundtrip");
    assert_eq!(roundtrip, base_tree);
    assert_eq!(roundtrip.hash(), base_tree.hash());

    // Materialize a smaller tree -> stale tracked file (scripts/run.sh) and empty scripts/ dir are removed.
    let mut trimmed_tree = base_tree.clone();
    trimmed_tree.remove("scripts/run.sh");
    ws1.materialize_tree(&trimmed_tree, store.as_ref())
        .expect("materialize trimmed tree");
    assert!(!ws1_root.join("scripts/run.sh").exists());
    assert!(!ws1_root.join("scripts").exists());
    assert!(ws1_root.join("README.md").exists());

    // Second CoW workspace via WorkspaceManager shares the exact same pool and base ChangeSet.
    let manager = WorkspaceManager::with_pool_dir(Arc::clone(&store), &pool_dir);
    let (ws2_ref, mut ws2) = manager
        .create_cow_workspace_from_bookmark("ws2", &ws2_root, "master")
        .expect("create ws2 from master");
    assert_eq!(ws2_ref.head_changeset, base_cs);
    assert_eq!(
        ws2.read_file("scripts/run.sh").unwrap(),
        b"#!/usr/bin/env sh\necho running\n"
    );

    // Editing ws2 does not mutate pool files or ws1.
    ws2.write_file("README.md", b"# edited in ws2\n", FileMode::Regular)
        .expect("edit ws2");
    assert_eq!(ws1.read_file("README.md").unwrap(), b"# gitx repo\n");
    let snap2 = ws2.snapshot_tree(DomainId::public(), store.as_ref()).unwrap();
    let diff = WorkspaceManager::detect_changes(&snap2, &base_tree);
    assert_eq!(
        diff,
        WorkspaceChanges {
            added: vec![],
            modified: vec!["README.md".to_string()],
            removed: vec![],
        }
    );
}

#[test]
fn cow_workspace_ignores_and_snapshot_by_domain_partitioning() {
    let tmp = TempDir::new().expect("tempdir");
    let root = tmp.path().join("repo");
    let pool = tmp.path().join("pool");
    let store = MemoryStore::new();

    let mut ws = CowWorkspace::open(&root, &pool).expect("open");

    // Create default-ignored directories that must never enter snapshots.
    fs::create_dir_all(root.join(".git/objects")).unwrap();
    fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::create_dir_all(root.join(".gitx/cache")).unwrap();
    fs::write(root.join(".gitx/cache/state"), "internal").unwrap();
    fs::create_dir_all(root.join("target/debug")).unwrap();
    fs::write(root.join("target/debug/bin"), "elf").unwrap();
    fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    fs::write(root.join("node_modules/pkg/index.js"), "module.exports={}").unwrap();

    // Create .gitxignore to ignore *.log and dist/
    fs::write(root.join(".gitxignore"), "# comment\n*.log\ndist/\n").unwrap();
    fs::write(root.join("debug.log"), "noisy log").unwrap();
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("dist/bundle.js"), "minified").unwrap();

    // Create real files spanning three Visibility Domains:
    // 1. secret:dev -> .env, .env.local
    // 2. team:private -> packages/private/roadmap.md, packages/private/algo.rs
    // 3. public -> src/lib.rs, .gitxignore
    ws.write_file(".env", b"API_KEY=dev-secret\n", FileMode::Regular)
        .unwrap();
    ws.write_file(".env.local", b"DEBUG=1\n", FileMode::Regular)
        .unwrap();
    ws.write_file(
        "packages/private/roadmap.md",
        b"Q4 secret launch\n",
        FileMode::Regular,
    )
    .unwrap();
    ws.write_file(
        "packages/private/algo.rs",
        b"pub fn score() -> u64 { 42 }\n",
        FileMode::Regular,
    )
    .unwrap();
    ws.write_file("src/lib.rs", b"pub fn hello() {}\n", FileMode::Regular)
        .unwrap();

    let secret_dev = DomainId::secret("dev").unwrap();
    let team_private = DomainId::team("private").unwrap();
    let public = DomainId::public();

    let partitioned = ws
        .snapshot_by_domain(&store, |path| {
            if path == ".env" || path.starts_with(".env.") {
                secret_dev.clone()
            } else if path.starts_with("packages/private/") {
                team_private.clone()
            } else {
                public.clone()
            }
        })
        .expect("snapshot_by_domain");

    assert_eq!(partitioned.len(), 3);

    let secret_keys: Vec<_> = partitioned[&secret_dev].entries.keys().cloned().collect();
    assert_eq!(secret_keys, vec![".env", ".env.local"]);

    let private_keys: Vec<_> = partitioned[&team_private].entries.keys().cloned().collect();
    assert_eq!(
        private_keys,
        vec!["packages/private/algo.rs", "packages/private/roadmap.md"]
    );

    let public_keys: Vec<_> = partitioned[&public].entries.keys().cloned().collect();
    assert_eq!(public_keys, vec![".gitxignore", "src/lib.rs"]);

    // Verify none of the ignored paths leaked into any domain tree.
    for tree in partitioned.values() {
        for p in tree.entries.keys() {
            assert!(!p.starts_with(".git/"));
            assert!(!p.starts_with(".gitx/"));
            assert!(!p.starts_with("target/"));
            assert!(!p.starts_with("node_modules/"));
            assert!(!p.starts_with("dist/"));
            assert!(!p.ends_with(".log"));
        }
    }
}

#[test]
fn fleet_overlay_bundle_export_excludes_os_dirs_and_applies_to_second_machine() {
    let tmp = TempDir::new().expect("tempdir");
    let machine_a = tmp.path().join("machine-a");
    let machine_b = tmp.path().join("machine-b");
    fs::create_dir_all(&machine_a).unwrap();
    fs::create_dir_all(&machine_b).unwrap();

    // Populate machine A with private overlay files + OS/build/VCS dirs containing matching names.
    fs::write(machine_a.join(".env"), b"DATABASE_URL=postgres://localhost/dev\n").unwrap();
    fs::write(machine_a.join(".env.local"), b"LOCAL_OVERRIDE=true\n").unwrap();
    fs::create_dir_all(machine_a.join("apps/web")).unwrap();
    fs::write(machine_a.join("apps/web/.env.local"), b"NEXT_PUBLIC_PORT=3000\n").unwrap();
    fs::create_dir_all(machine_a.join("config")).unwrap();
    fs::write(machine_a.join("config/dev.local.toml"), b"threads = 8\n").unwrap();

    // Executable local helper script matching *.local.sh
    let local_script = machine_a.join("tools.local.sh");
    fs::write(&local_script, b"#!/usr/bin/env sh\necho hi\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&local_script, fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Files inside strictly excluded directories — even if named `.env` or matched by glob!
    fs::create_dir_all(machine_a.join("node_modules/some-pkg")).unwrap();
    fs::write(machine_a.join("node_modules/some-pkg/.env"), b"SHOULD_NOT_SYNC").unwrap();
    fs::create_dir_all(machine_a.join("target/debug")).unwrap();
    fs::write(machine_a.join("target/debug/.env.local"), b"SHOULD_NOT_SYNC").unwrap();
    fs::create_dir_all(machine_a.join(".git")).unwrap();
    fs::write(machine_a.join(".git/.env"), b"SHOULD_NOT_SYNC").unwrap();
    fs::create_dir_all(machine_a.join(".gitx")).unwrap();
    fs::write(machine_a.join(".gitx/.env"), b"SHOULD_NOT_SYNC").unwrap();

    // Regular source file not matching overlay patterns.
    fs::create_dir_all(machine_a.join("src")).unwrap();
    fs::write(machine_a.join("src/main.rs"), b"fn main() {}\n").unwrap();

    // Export even with an aggressive pattern attempting to include `node_modules/**` and `target/**`.
    let meta = FleetWorkspaceMetadata {
        workspace_name: Some("laptop-main".to_string()),
        source_machine: Some("macbook-pro".to_string()),
        ..Default::default()
    };
    let bundle = export_overlay_with_metadata(
        &machine_a,
        &[
            ".env",
            ".env.*",
            "config/*.local.toml",
            "*.local.sh",
            "node_modules/**",
            "target/**",
        ],
        meta,
    )
    .expect("export overlay");

    let exported_paths: Vec<_> = bundle.files.keys().cloned().collect();
    assert_eq!(
        exported_paths,
        vec![
            ".env",
            ".env.local",
            "apps/web/.env.local",
            "config/dev.local.toml",
            "tools.local.sh",
        ]
    );

    // Serialize -> JSON -> Deserialize (simulating cross-machine transport).
    let json = bundle.to_json().expect("serialize bundle");
    let decoded = FleetOverlayBundle::from_json(&json).expect("deserialize bundle");
    assert_eq!(decoded, bundle);
    assert_eq!(
        decoded.workspace.source_machine.as_deref(),
        Some("macbook-pro")
    );

    // Apply onto machine B.
    let restored = apply_overlay(&machine_b, &decoded).expect("apply overlay");
    assert_eq!(restored, exported_paths);
    assert_eq!(
        fs::read(machine_b.join(".env")).unwrap(),
        b"DATABASE_URL=postgres://localhost/dev\n"
    );
    assert_eq!(
        fs::read(machine_b.join(".env.local")).unwrap(),
        b"LOCAL_OVERRIDE=true\n"
    );
    assert_eq!(
        fs::read(machine_b.join("apps/web/.env.local")).unwrap(),
        b"NEXT_PUBLIC_PORT=3000\n"
    );
    assert_eq!(
        fs::read(machine_b.join("config/dev.local.toml")).unwrap(),
        b"threads = 8\n"
    );
    assert!(!machine_b.join("node_modules").exists());
    assert!(!machine_b.join("target").exists());
    assert!(!machine_b.join("src").exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(machine_b.join("tools.local.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0, "executable bit should survive fleet sync");
    }

    // Simple export_overlay helper also works cleanly.
    let simple = export_overlay(&machine_a, &[".env", ".env.local"]).expect("simple export");
    assert!(simple.files.contains_key(".env"));
    assert!(simple.files.contains_key(".env.local"));
    assert!(!simple.files.contains_key("src/main.rs"));
}

#[test]
fn security_and_edge_cases_paths_conflicts_and_manager_lifecycle() {
    // Path traversal and invalid paths are rejected.
    assert!(normalize_rel_path("../secret").is_err());
    assert!(normalize_rel_path("a/../../b").is_err());
    assert!(normalize_rel_path("/etc/passwd").is_err());
    assert!(normalize_rel_path("").is_err());
    assert!(normalize_rel_path("a\0b").is_err());
    assert_eq!(normalize_rel_path("./src\\main.rs").unwrap(), "src/main.rs");

    // Conflict entries materialize cleanly in both MemVfs and CowWorkspace without blocking.
    let store: Arc<dyn ObjectStore> = Arc::new(MemoryStore::new());
    let base_blob = store.put_blob_bytes(b"line = 0\n").unwrap();
    let left_blob = store.put_blob_bytes(b"line = 1\n").unwrap();
    let right_blob = store.put_blob_bytes(b"line = 2\n").unwrap();

    let mut conflict_tree = DomainTree::new(DomainId::public());
    conflict_tree.insert(
        "conflicted.txt",
        EntryKind::Conflict {
            term: ConflictTerm {
                adds: vec![
                    Some(left_blob.manifest_hash()),
                    Some(right_blob.manifest_hash()),
                ],
                removes: vec![Some(base_blob.manifest_hash())],
            },
            mode: FileMode::Regular,
        },
    );

    let mem = MemVfs::from_tree(&conflict_tree, store.as_ref()).expect("materialize conflict mem");
    let rendered = String::from_utf8(mem.read_file("conflicted.txt").unwrap()).unwrap();
    assert!(rendered.contains("<<<<<<< conflict"));
    assert!(rendered.contains("line = 1"));
    assert!(rendered.contains("line = 2"));
    assert!(rendered.contains("line = 0"));

    // EncryptedSecret cannot be materialized raw without decryption.
    let mut secret_tree = DomainTree::new(DomainId::secret("prod").unwrap());
    secret_tree.insert(
        ".env.prod",
        EntryKind::EncryptedSecret {
            envelope_hash: ObjectHash::of_bytes(b"cipher"),
            key_epoch: 3,
            mode: FileMode::Regular,
        },
    );
    let err = MemVfs::from_tree(&secret_tree, store.as_ref()).unwrap_err();
    assert!(matches!(err, GitxError::AccessDenied { .. }));

    // Tampered FleetOverlayBundle is rejected before touching disk.
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join(".env"), b"OK=1\n").unwrap();
    let mut bundle = export_overlay(&src, &[".env"]).unwrap();
    bundle.files.get_mut(".env").unwrap().content = b"TAMPERED=1\n".to_vec();
    assert!(apply_overlay(&dst, &bundle).is_err());
    assert!(!dst.join(".env").exists());

    // WorkspaceManager duplicate name rejection and remove_workspace lifecycle.
    let (base_cs, _) = seed_base_repo(store.as_ref());
    let mgr = WorkspaceManager::new(Arc::clone(&store));
    let _ = mgr.create_mem_workspace("dev", base_cs).unwrap();
    assert!(mgr.create_mem_workspace("dev", base_cs).is_err());
    mgr.remove_workspace("dev").unwrap();
    assert!(mgr.get_workspace("dev").unwrap().is_none());
    assert!(mgr.remove_workspace("dev").is_err());

    // Path traversal workspace names are rejected
    assert!(mgr.create_mem_workspace("../escape", base_cs).is_err());
    assert!(mgr.create_mem_workspace(".", base_cs).is_err());
    assert!(mgr.create_mem_workspace("/abs", base_cs).is_err());
}

#[cfg(unix)]
#[test]
fn cow_and_overlay_reject_symlink_ancestor_escape_and_handle_dir_replacement() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let outside = tmp.path().join("outside");
    let root = tmp.path().join("workspace");
    let pool = tmp.path().join("pool");
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(&root).unwrap();

    // Symlink inside workspace pointing outside
    fs::write(outside.join("outside_secret.txt"), b"top-secret").unwrap();
    symlink(&outside, root.join("linkdir")).unwrap();

    let mut ws = CowWorkspace::open(&root, &pool).unwrap();
    assert!(
        ws.read_file("linkdir/outside_secret.txt").is_err(),
        "CowWorkspace::read_file must reject symlink ancestor escape"
    );
    assert!(
        ws.write_file("linkdir/pwn.txt", b"escaped", FileMode::Regular)
            .is_err(),
        "CowWorkspace::write_file must reject symlink ancestor escape"
    );
    assert!(!outside.join("pwn.txt").exists());

    // apply_overlay must also reject symlink ancestor escape
    let src = tmp.path().join("src");
    fs::create_dir_all(src.join("linkdir")).unwrap();
    fs::write(src.join("linkdir/env"), b"K=V\n").unwrap();
    let bundle = export_overlay(&src, &["linkdir/env"]).unwrap();
    assert!(
        apply_overlay(&root, &bundle).is_err(),
        "apply_overlay must reject symlink ancestor escape"
    );
    assert!(!outside.join("env").exists());

    // Replacing a non-empty directory containing untracked files must fail without wiping them
    fs::create_dir_all(root.join("nonempty_dir/nested")).unwrap();
    fs::write(root.join("nonempty_dir/nested/untracked.txt"), b"keep me").unwrap();
    assert!(
        ws.write_file("nonempty_dir", b"overwrite", FileMode::Regular)
            .is_err(),
        "write_file must not recursively delete non-empty directories containing untracked files"
    );
    assert_eq!(
        fs::read(root.join("nonempty_dir/nested/untracked.txt")).unwrap(),
        b"keep me"
    );

    // Replacing an empty directory with a regular file succeeds cleanly
    fs::create_dir_all(root.join("empty_dir")).unwrap();
    ws.write_file("empty_dir", b"now a file", FileMode::Regular)
        .expect("replacing empty directory with file should not fail with EISDIR");
    assert_eq!(ws.read_file("empty_dir").unwrap(), b"now a file");

    // Materializing a tree that replaces a tracked directory (`sub/victim.txt`) with a symlink
    // (`sub -> outside`) must NOT delete `outside/victim.txt` outside the workspace root!
    let store = MemoryStore::new();
    let victim_outside = outside.join("victim.txt");
    fs::write(&victim_outside, b"do not delete me").unwrap();

    let mat_root = tmp.path().join("mat_workspace");
    let mat_pool = tmp.path().join("mat_pool");
    let mut mat_ws = CowWorkspace::open(&mat_root, &mat_pool).unwrap();

    let mut t1 = DomainTree::new(DomainId::public());
    let b1 = store.put_blob_bytes(b"inside").unwrap();
    t1.insert(
        "sub/victim.txt",
        EntryKind::File {
            blob_hash: b1.manifest_hash(),
            mode: FileMode::Regular,
            size: b1.total_size,
        },
    );
    mat_ws.materialize_tree(&t1, &store).unwrap();
    assert!(mat_root.join("sub/victim.txt").is_file());

    let mut t2 = DomainTree::new(DomainId::public());
    let sym_bytes = outside.to_string_lossy().into_owned().into_bytes();
    let b2 = store.put_blob_bytes(&sym_bytes).unwrap();
    t2.insert(
        "sub",
        EntryKind::File {
            blob_hash: b2.manifest_hash(),
            mode: FileMode::Symlink,
            size: b2.total_size,
        },
    );
    mat_ws.materialize_tree(&t2, &store).unwrap();
    assert!(
        victim_outside.is_file(),
        "materialize_tree must never delete files outside workspace via symlink replacement"
    );
    assert_eq!(fs::read(&victim_outside).unwrap(), b"do not delete me");
}
