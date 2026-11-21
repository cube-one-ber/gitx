use gitx_core::oplog::{OpId, OpLogEntry, WorkspaceBackendKind};
use gitx_core::{
    ChangeId, ChangeSet, ChangeSetBuilder, ChunkedBlob, DomainId, DomainTree, EntryKind, FileMode,
    GitxError, Identity, ObjectHash, Result, Stack, WorkspaceRef,
};
use gitx_crypto::UserKeyPair;
use gitx_store::{LandRecord, MemoryStore, ObjectStore};
use gitx_vfs::{
    EncryptedFleetBundle, LazyStats, LazyWorkspace, WorkspaceBackend, WorkspaceChanges,
    WorkspaceManager, apply_encrypted_overlay, export_encrypted_overlay,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::TempDir;
use walkdir::WalkDir;

/// Instrumentation wrapper around [`MemoryStore`] that counts blob reads and writes so tests
/// can prove O(1) lazy mount and O(dirty_files) snapshot behavior.
struct CountingStore {
    inner: MemoryStore,
    blob_reads: AtomicUsize,
    blob_writes: AtomicUsize,
}

impl CountingStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            blob_reads: AtomicUsize::new(0),
            blob_writes: AtomicUsize::new(0),
        }
    }

    fn reset_counts(&self) {
        self.blob_reads.store(0, Ordering::SeqCst);
        self.blob_writes.store(0, Ordering::SeqCst);
    }

    fn blob_reads(&self) -> usize {
        self.blob_reads.load(Ordering::SeqCst)
    }

    fn blob_writes(&self) -> usize {
        self.blob_writes.load(Ordering::SeqCst)
    }
}

impl ObjectStore for CountingStore {
    fn put_chunk(&self, hash: ObjectHash, data: &[u8]) -> Result<()> {
        self.inner.put_chunk(hash, data)
    }

    fn get_chunk(&self, hash: ObjectHash) -> Result<Vec<u8>> {
        self.inner.get_chunk(hash)
    }

    fn has_chunk(&self, hash: ObjectHash) -> Result<bool> {
        self.inner.has_chunk(hash)
    }

    fn put_blob_bytes(&self, data: &[u8]) -> Result<ChunkedBlob> {
        self.blob_writes.fetch_add(1, Ordering::SeqCst);
        self.inner.put_blob_bytes(data)
    }

    fn read_blob_bytes(&self, manifest_hash: ObjectHash) -> Result<Vec<u8>> {
        self.blob_reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read_blob_bytes(manifest_hash)
    }

    fn put_raw_object(&self, hash: ObjectHash, bytes: &[u8]) -> Result<()> {
        self.inner.put_raw_object(hash, bytes)
    }

    fn get_raw_object(&self, hash: ObjectHash) -> Result<Vec<u8>> {
        self.inner.get_raw_object(hash)
    }

    fn put_changeset(&self, cs: &ChangeSet) -> Result<ObjectHash> {
        self.inner.put_changeset(cs)
    }

    fn get_changeset(&self, id: ObjectHash) -> Result<ChangeSet> {
        self.inner.get_changeset(id)
    }

    fn list_changesets(&self) -> Result<Vec<ChangeSet>> {
        self.inner.list_changesets()
    }

    fn get_revisions_for_change(&self, change_id: ChangeId) -> Result<Vec<ChangeSet>> {
        self.inner.get_revisions_for_change(change_id)
    }

    fn put_stack(&self, stack: &Stack) -> Result<()> {
        self.inner.put_stack(stack)
    }

    fn get_stack(&self, name: &str) -> Result<Stack> {
        self.inner.get_stack(name)
    }

    fn list_stacks(&self) -> Result<Vec<Stack>> {
        self.inner.list_stacks()
    }

    fn delete_stack(&self, name: &str) -> Result<()> {
        self.inner.delete_stack(name)
    }

    fn append_op(&self, op: &OpLogEntry) -> Result<()> {
        self.inner.append_op(op)
    }

    fn get_op(&self, id: OpId) -> Result<OpLogEntry> {
        self.inner.get_op(id)
    }

    fn latest_op(&self) -> Result<Option<OpLogEntry>> {
        self.inner.latest_op()
    }

    fn list_ops(&self, limit: usize) -> Result<Vec<OpLogEntry>> {
        self.inner.list_ops(limit)
    }

    fn record_land(
        &self,
        target: &str,
        expected_previous: Option<ObjectHash>,
        new_head: ObjectHash,
        changes: Vec<ChangeId>,
    ) -> Result<LandRecord> {
        self.inner
            .record_land(target, expected_previous, new_head, changes)
    }

    fn get_land(&self, land_seq: u64) -> Result<LandRecord> {
        self.inner.get_land(land_seq)
    }

    fn list_lands(&self, target: &str, limit: usize) -> Result<Vec<LandRecord>> {
        self.inner.list_lands(target, limit)
    }

    fn mark_reverted(&self, land_seq: u64, reverted_by: u64) -> Result<()> {
        self.inner.mark_reverted(land_seq, reverted_by)
    }

    fn get_bookmark(&self, name: &str) -> Result<Option<ObjectHash>> {
        self.inner.get_bookmark(name)
    }

    fn set_bookmark(&self, name: &str, hash: ObjectHash) -> Result<()> {
        self.inner.set_bookmark(name, hash)
    }

    fn list_bookmarks(&self) -> Result<BTreeMap<String, ObjectHash>> {
        self.inner.list_bookmarks()
    }

    fn put_workspace(&self, ws: &WorkspaceRef) -> Result<()> {
        self.inner.put_workspace(ws)
    }

    fn get_workspace(&self, name: &str) -> Result<Option<WorkspaceRef>> {
        self.inner.get_workspace(name)
    }

    fn list_workspaces(&self) -> Result<BTreeMap<String, WorkspaceRef>> {
        self.inner.list_workspaces()
    }

    fn remove_workspace(&self, name: &str) -> Result<()> {
        self.inner.remove_workspace(name)
    }
}

fn count_files_on_disk(root: &Path) -> usize {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.depth() > 0 && !e.file_type().is_dir())
        .count()
}

fn build_virtual_tree(store: &dyn ObjectStore, count: usize) -> DomainTree {
    let mut tree = DomainTree::new(DomainId::public());
    for i in 0..count {
        let dir = i / 100;
        let path = format!("pkg_{dir:02}/file_{i:04}.txt");
        let payload = format!("virtual file payload #{i}\n");
        let blob = store.put_blob_bytes(payload.as_bytes()).expect("put blob");
        tree.insert(
            path,
            EntryKind::File {
                blob_hash: blob.manifest_hash(),
                mode: FileMode::Regular,
                size: blob.total_size,
            },
        );
    }
    tree
}

#[test]
fn lazy_workspace_2000_files_zero_disk_mount_demand_paging_and_fast_snapshot() {
    let tmp = TempDir::new().expect("tempdir");
    let overlay_root = tmp.path().join("lazy-overlay");

    let counting = Arc::new(CountingStore::new());
    let store: Arc<dyn ObjectStore> = counting.clone();
    let base_tree = build_virtual_tree(store.as_ref(), 2_000);
    assert_eq!(base_tree.entries.len(), 2_000);

    // Reset counters before mounting so we measure strictly mount + workspace operations.
    counting.reset_counts();

    // 1. Mount 2,000-file virtual tree -> assert 0 files on disk and 0 store reads.
    let mut ws = LazyWorkspace::mount(&overlay_root, Arc::clone(&store), base_tree.clone())
        .expect("lazy mount");
    assert_eq!(ws.backend_kind(), WorkspaceBackendKind::LazyMount);
    assert_eq!(
        count_files_on_disk(&overlay_root),
        0,
        "mount must write zero base files to disk"
    );
    assert_eq!(counting.blob_reads(), 0);
    assert_eq!(
        ws.stats(),
        LazyStats {
            total_virtual_files: 2_000,
            hydrated_reads: 0,
            overlay_dirty_files: 0,
            tombstones: 0,
            cache_hits: 0,
        }
    );
    assert_eq!(ws.list_files().unwrap().len(), 2_000);
    assert_eq!(ws.list_dir("pkg_05").unwrap().len(), 100);

    // 2. Read 2 files on demand -> hydrated lazily from store, still 0 files on disk!
    let f1 = ws.read_file("pkg_00/file_0042.txt").expect("read file 42");
    assert_eq!(f1, b"virtual file payload #42\n");
    let f2 = ws
        .read_file("pkg_19/file_1999.txt")
        .expect("read file 1999");
    assert_eq!(f2, b"virtual file payload #1999\n");

    assert_eq!(count_files_on_disk(&overlay_root), 0);
    assert_eq!(counting.blob_reads(), 2);
    assert_eq!(
        ws.stats(),
        LazyStats {
            total_virtual_files: 2_000,
            hydrated_reads: 2,
            overlay_dirty_files: 0,
            tombstones: 0,
            cache_hits: 0,
        }
    );

    // Re-reading a hydrated file hits the in-memory cache with zero additional store reads.
    let f1_cached = ws
        .read_file("pkg_00/file_0042.txt")
        .expect("cached read 42");
    assert_eq!(f1_cached, b"virtual file payload #42\n");
    assert_eq!(counting.blob_reads(), 2);
    assert_eq!(ws.stats().cache_hits, 1);

    // 3. Write 1 new file + delete 1 base file -> assert ONLY 1 file on disk!
    ws.write_file(
        "pkg_custom/added.txt",
        b"fresh overlay payload\n",
        FileMode::Regular,
    )
    .expect("write 1 file");
    ws.remove_file("pkg_00/file_0042.txt")
        .expect("delete 1 base file");

    assert_eq!(
        count_files_on_disk(&overlay_root),
        1,
        "only the 1 dirty overlay file should exist on disk"
    );
    assert!(overlay_root.join("pkg_custom/added.txt").is_file());
    assert!(matches!(
        ws.read_file("pkg_00/file_0042.txt"),
        Err(GitxError::NotFound(_))
    ));
    assert_eq!(
        ws.read_file("pkg_custom/added.txt").unwrap(),
        b"fresh overlay payload\n"
    );
    assert_eq!(
        ws.stats(),
        LazyStats {
            total_virtual_files: 2_000,
            hydrated_reads: 2,
            overlay_dirty_files: 1,
            tombstones: 1,
            cache_hits: 1,
        }
    );

    // 4. snapshot_tree reflects exact 2,000-file result cleanly in O(dirty_files) uploads!
    counting.reset_counts();
    let snap = ws
        .snapshot_tree(DomainId::public(), store.as_ref())
        .expect("fast snapshot_tree");
    assert_eq!(snap.entries.len(), 2_000);
    assert_eq!(
        counting.blob_reads(),
        0,
        "snapshot_tree must not read unmodified base blobs from store"
    );
    assert_eq!(
        counting.blob_writes(),
        1,
        "snapshot_tree must only upload dirty overlay files"
    );

    let changes = WorkspaceManager::detect_changes(&snap, &base_tree);
    assert_eq!(
        changes,
        WorkspaceChanges {
            added: vec!["pkg_custom/added.txt".to_string()],
            modified: vec![],
            removed: vec!["pkg_00/file_0042.txt".to_string()],
        }
    );

    // Verify unmodified base entries kept their exact original EntryKind / blob_hash.
    assert_eq!(
        snap.entries.get("pkg_19/file_1999.txt"),
        base_tree.entries.get("pkg_19/file_1999.txt")
    );
}

#[test]
fn lazy_workspace_cow_overwrite_snapshot_by_domain_and_manager_integration() {
    let tmp = TempDir::new().expect("tempdir");
    let overlay_root = tmp.path().join("mgr-lazy");

    let counting = Arc::new(CountingStore::new());
    let store: Arc<dyn ObjectStore> = counting.clone();

    let mut base_tree = DomainTree::new(DomainId::public());
    for (path, content) in [
        ("src/lib.rs", b"pub fn v1() {}\n".as_slice()),
        ("packages/private/plan.md", b"roadmap v1\n".as_slice()),
        ("README.md", b"# repo\n".as_slice()),
    ] {
        let blob = store.put_blob_bytes(content).unwrap();
        base_tree.insert(
            path,
            EntryKind::File {
                blob_hash: blob.manifest_hash(),
                mode: FileMode::Regular,
                size: blob.total_size,
            },
        );
    }

    let tree_hash = store.put_tree(&base_tree).unwrap();
    let cs = ChangeSetBuilder::new(Identity {
        name: "Lazy Tester".to_string(),
        email: "lazy@gitx.dev".to_string(),
        key_fingerprint: None,
    })
    .domain_tree(DomainId::public(), tree_hash)
    .description("seed for lazy workspace")
    .build();
    let cs_id = store.put_changeset(&cs).unwrap();
    store.set_bookmark("master", cs_id).unwrap();

    let manager = WorkspaceManager::new(Arc::clone(&store));
    let (ws_ref, mut ws) = manager
        .create_lazy_workspace_from_bookmark("agent-lazy", &overlay_root, "master")
        .expect("create_lazy_workspace_from_bookmark");
    assert_eq!(ws_ref.backend, WorkspaceBackendKind::LazyMount);
    assert_eq!(ws_ref.head_changeset, cs_id);
    assert_eq!(count_files_on_disk(&overlay_root), 0);

    // Overwrite an existing base file -> CoW writes only that file to overlay_root.
    ws.write_file("src/lib.rs", b"pub fn v2() {}\n", FileMode::Regular)
        .unwrap();
    assert_eq!(count_files_on_disk(&overlay_root), 1);
    assert_eq!(ws.read_file("src/lib.rs").unwrap(), b"pub fn v2() {}\n");

    // Delete and then re-create a base file -> clears tombstone and writes new overlay copy.
    ws.remove_file("README.md").unwrap();
    assert!(!ws.contains("README.md"));
    ws.write_file("README.md", b"# revived\n", FileMode::Regular)
        .unwrap();
    assert!(ws.contains("README.md"));
    assert_eq!(ws.stats().tombstones, 0);
    assert_eq!(ws.stats().overlay_dirty_files, 2);

    // snapshot_by_domain partitions cleanly while uploading only dirty files.
    counting.reset_counts();
    let team_private = DomainId::team("private").unwrap();
    let public = DomainId::public();
    let by_domain = ws
        .snapshot_by_domain(store.as_ref(), |path| {
            if path.starts_with("packages/private/") {
                team_private.clone()
            } else {
                public.clone()
            }
        })
        .expect("snapshot_by_domain");

    assert_eq!(counting.blob_reads(), 0);
    assert_eq!(counting.blob_writes(), 2);
    assert_eq!(
        by_domain[&team_private]
            .entries
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["packages/private/plan.md"]
    );
    assert_eq!(
        by_domain[&public]
            .entries
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["README.md", "src/lib.rs"]
    );
    assert_eq!(
        by_domain[&team_private].entries.get("packages/private/plan.md"),
        base_tree.entries.get("packages/private/plan.md")
    );
}

#[test]
fn encrypted_fleet_overlay_hides_env_plaintext_restores_authorized_and_rejects_unauthorized() {
    let tmp = TempDir::new().expect("tempdir");
    let laptop = tmp.path().join("machine-laptop");
    let workstation = tmp.path().join("machine-workstation");
    let intruder_dir = tmp.path().join("machine-intruder");
    fs::create_dir_all(&laptop).unwrap();
    fs::create_dir_all(&workstation).unwrap();
    fs::create_dir_all(&intruder_dir).unwrap();

    let secret_token = "SUPER_SECRET_STRIPE_KEY=sk_live_9999999999_do_not_leak";
    fs::write(
        laptop.join(".env"),
        format!("{secret_token}\nDATABASE_URL=postgres://admin:pw@db/prod\n"),
    )
    .unwrap();
    fs::write(laptop.join(".env.local"), b"LOCAL_FEATURE_FLAG=enabled\n").unwrap();
    fs::create_dir_all(laptop.join("config")).unwrap();
    fs::write(laptop.join("config/local.toml"), b"workers = 16\n").unwrap();

    // Excluded directory with a `.env` file that must never be exported.
    fs::create_dir_all(laptop.join("node_modules/pkg")).unwrap();
    fs::write(laptop.join("node_modules/pkg/.env"), b"IGNORED=true\n").unwrap();

    // Machine keypairs: laptop (sender), workstation (authorized peer), intruder (unauthorized).
    let laptop_key = UserKeyPair::generate_with_label("laptop-m3");
    let workstation_key = UserKeyPair::generate_with_label("workstation-linux");
    let intruder_key = UserKeyPair::generate_with_label("intruder-box");

    let domain = DomainId::secret("fleet").unwrap();
    let recipients = [laptop_key.public_bundle(), workstation_key.public_bundle()];

    let encrypted = export_encrypted_overlay(
        &laptop,
        &[".env", ".env.*", "config/*.toml", "node_modules/**"],
        "laptop-m3",
        &domain,
        7,
        &recipients,
    )
    .expect("export_encrypted_overlay");

    assert_eq!(encrypted.machine_id, "laptop-m3");
    assert_eq!(encrypted.file_count, 3);
    assert_eq!(encrypted.envelope.domain, domain);
    assert_eq!(encrypted.envelope.key_epoch, 7);
    assert!(encrypted.envelope.has_recipient(&workstation_key.fingerprint()));
    assert!(!encrypted.envelope.has_recipient(&intruder_key.fingerprint()));

    // Verify `.env` plaintext is completely hidden in raw ciphertext AND serialized JSON.
    let raw_ct_lossy = String::from_utf8_lossy(&encrypted.envelope.ciphertext);
    assert!(
        !raw_ct_lossy.contains("SUPER_SECRET_STRIPE_KEY"),
        "secret plaintext must not appear in ciphertext"
    );
    assert!(!raw_ct_lossy.contains("sk_live_9999999999"));

    let wire_json = encrypted.to_json().expect("serialize encrypted bundle");
    assert!(!wire_json.contains("SUPER_SECRET_STRIPE_KEY"));
    assert!(!wire_json.contains("sk_live_9999999999"));
    assert!(!wire_json.contains("DATABASE_URL"));

    let received = EncryptedFleetBundle::from_json(&wire_json).expect("deserialize bundle");
    assert_eq!(received, encrypted);

    // Unauthorized machine key is rejected cleanly without touching disk.
    let err = apply_encrypted_overlay(&intruder_dir, &received, &intruder_key).unwrap_err();
    assert!(
        matches!(err, GitxError::AccessDenied { .. }),
        "expected AccessDenied for unauthorized key, got {err:?}"
    );
    assert_eq!(count_files_on_disk(&intruder_dir), 0);

    // Tampered machine_id header fails AEAD authentication.
    let mut tampered = received.clone();
    tampered.machine_id = "spoofed-machine".to_string();
    assert!(matches!(
        apply_encrypted_overlay(&intruder_dir, &tampered, &workstation_key),
        Err(GitxError::Crypto(_))
    ));
    assert_eq!(count_files_on_disk(&intruder_dir), 0);

    // Authorized workstation key decrypts and restores all 3 overlay files cleanly.
    let restored =
        apply_encrypted_overlay(&workstation, &received, &workstation_key).expect("apply encrypted");
    assert_eq!(restored, vec![".env", ".env.local", "config/local.toml"]);
    assert_eq!(
        fs::read_to_string(workstation.join(".env")).unwrap(),
        format!("{secret_token}\nDATABASE_URL=postgres://admin:pw@db/prod\n")
    );
    assert_eq!(
        fs::read_to_string(workstation.join(".env.local")).unwrap(),
        "LOCAL_FEATURE_FLAG=enabled\n"
    );
    assert_eq!(
        fs::read_to_string(workstation.join("config/local.toml")).unwrap(),
        "workers = 16\n"
    );
    assert!(!workstation.join("node_modules").exists());
}
