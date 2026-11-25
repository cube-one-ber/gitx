use gitx_core::{
    ChangeId, ChangeSet, ChunkedBlob, DomainId, DomainTree, EntryKind, FileMode, GitxError,
    ObjectHash, OpId, OpLogEntry, Result, Stack, WorkspaceRef,
};
use gitx_store::{LandRecord, MemoryStore, ObjectStore};
use gitx_vfs::{
    FuseCore, LazyStats, LazyWorkspace, LoopbackVfsClient, LoopbackVfsServer, ROOT_INO,
    VfsFileType, WorkspaceChanges, WorkspaceManager,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::TempDir;
use walkdir::WalkDir;

#[cfg(all(target_os = "linux", feature = "fuse"))]
use gitx_vfs::FuseMountHandle;

/// Instrumentation wrapper around [`MemoryStore`] that counts blob reads and writes so tests
/// can prove O(1) lazy mount and O(dirty_files) snapshot behavior across OS mounts.
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

fn seed_sample_tree(store: &dyn ObjectStore) -> DomainTree {
    let mut tree = DomainTree::new(DomainId::public());
    let files: &[(&str, &[u8], FileMode)] = &[
        ("README.md", b"# GitX Virtual Mount\n", FileMode::Regular),
        (
            "src/lib.rs",
            b"pub fn hello() -> &'static str {\n    \"hello from vfs\"\n}\n",
            FileMode::Regular,
        ),
        (
            "src/nested/mod.rs",
            b"pub const ANSWER: u64 = 42;\n",
            FileMode::Regular,
        ),
        ("bin/run.sh", b"#!/bin/sh\necho ok\n", FileMode::Executable),
        ("docs/guide.txt", b"0123456789abcdef", FileMode::Regular),
    ];

    for &(path, bytes, mode) in files {
        let blob = store.put_blob_bytes(bytes).expect("put blob");
        tree.insert(
            path,
            EntryKind::File {
                blob_hash: blob.manifest_hash(),
                mode,
                size: blob.total_size,
            },
        );
    }

    // Add 100 extra virtual files across subdirectories to verify zero-hydration scaling.
    for i in 0..100 {
        let dir = i / 25;
        let path = format!("packages/pkg_{dir}/item_{i:03}.txt");
        let body = format!("package item {i}\n");
        let blob = store.put_blob_bytes(body.as_bytes()).expect("put blob");
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
fn fuse_core_full_posix_lifecycle_demand_paging_and_o_dirty_snapshot() {
    let tmp = TempDir::new().expect("tempdir");
    let overlay_root = tmp.path().join("fuse-core-overlay");

    let counting = Arc::new(CountingStore::new());
    let store: Arc<dyn ObjectStore> = counting.clone();
    let base_tree = seed_sample_tree(store.as_ref());
    let base_count = base_tree.entries.len();
    assert_eq!(base_count, 105);

    counting.reset_counts();
    let ws = LazyWorkspace::mount(&overlay_root, Arc::clone(&store), base_tree.clone())
        .expect("lazy mount");
    let mut core = FuseCore::new(ws, Arc::clone(&store));

    // Zero disk files and zero blob reads on mount + getattr + lookup + readdir!
    assert_eq!(count_files_on_disk(&overlay_root), 0);
    assert_eq!(counting.blob_reads(), 0);

    let root_attr = core.getattr(ROOT_INO).expect("root getattr");
    assert_eq!(root_attr.ino, ROOT_INO);
    assert_eq!(root_attr.kind, VfsFileType::Directory);

    let root_entries = core.readdir(ROOT_INO).expect("root readdir");
    let root_names: Vec<&str> = root_entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        root_names,
        vec![".", "..", "README.md", "bin", "docs", "packages", "src"]
    );
    assert_eq!(
        counting.blob_reads(),
        0,
        "readdir must never hydrate base blobs"
    );

    // Deterministic bidirectional inode lookup.
    let src_attr = core.lookup(ROOT_INO, "src").expect("lookup src");
    assert_eq!(src_attr.kind, VfsFileType::Directory);
    assert_eq!(core.resolve_path(src_attr.ino), Some("src"));
    assert_eq!(core.resolve_inode("src"), Some(src_attr.ino));

    let lib_attr = core.lookup(src_attr.ino, "lib.rs").expect("lookup lib.rs");
    assert_eq!(lib_attr.kind, VfsFileType::RegularFile);
    assert_eq!(lib_attr.perm, 0o644);
    assert_eq!(
        lib_attr.size,
        b"pub fn hello() -> &'static str {\n    \"hello from vfs\"\n}\n".len() as u64
    );
    assert_eq!(
        counting.blob_reads(),
        0,
        "lookup/getattr must read size from metadata without hydrating blob"
    );

    let bin_attr = core.lookup(ROOT_INO, "bin").expect("lookup bin");
    let run_attr = core.lookup(bin_attr.ino, "run.sh").expect("lookup run.sh");
    assert_eq!(run_attr.perm, 0o755);

    // Demand-paged read + partial offset read + in-memory cache hit.
    let _fh = core.open(lib_attr.ino, libc::O_RDONLY).expect("open lib.rs");
    let full_bytes = core.read(lib_attr.ino, 0, 4096).expect("read lib.rs");
    assert_eq!(
        full_bytes,
        b"pub fn hello() -> &'static str {\n    \"hello from vfs\"\n}\n"
    );
    assert_eq!(counting.blob_reads(), 1);
    assert_eq!(count_files_on_disk(&overlay_root), 0);

    let slice = core.read(lib_attr.ino, 7, 5).expect("offset read");
    assert_eq!(slice, b"hello");
    assert_eq!(
        counting.blob_reads(),
        1,
        "second read should hit LazyWorkspace cache"
    );
    assert_eq!(core.stats().cache_hits, 1);

    // Create + write a new file in an existing dir.
    let (new_attr, _fh) = core
        .create(src_attr.ino, "created.rs", 0o644, libc::O_CREAT | libc::O_WRONLY)
        .expect("create created.rs");
    let written = core
        .write(new_attr.ino, 0, b"pub const NEW: bool = true;\n")
        .expect("write created.rs");
    assert_eq!(written as usize, b"pub const NEW: bool = true;\n".len());
    assert_eq!(
        core.read(new_attr.ino, 0, 128).expect("read back created.rs"),
        b"pub const NEW: bool = true;\n"
    );

    // Partial CoW write on an existing base file (`docs/guide.txt`: "0123456789abcdef").
    let docs_attr = core.lookup(ROOT_INO, "docs").expect("lookup docs");
    let guide_attr = core
        .lookup(docs_attr.ino, "guide.txt")
        .expect("lookup guide.txt");
    core.write(guide_attr.ino, 4, b"XXXX").expect("cow patch");
    assert_eq!(
        core.read(guide_attr.ino, 0, 64).expect("read patched guide"),
        b"0123XXXX89abcdef"
    );

    // setattr: truncate and extend + chmod executable.
    let shrunk = core
        .setattr(guide_attr.ino, None, Some(8))
        .expect("truncate guide");
    assert_eq!(shrunk.size, 8);
    assert_eq!(
        core.read(guide_attr.ino, 0, 64).expect("read shrunk guide"),
        b"0123XXXX"
    );

    let extended = core
        .setattr(guide_attr.ino, Some(0o755), Some(10))
        .expect("extend + chmod guide");
    assert_eq!(extended.size, 10);
    assert_eq!(extended.perm, 0o755);
    assert_eq!(
        core.read(guide_attr.ino, 0, 64).expect("read extended"),
        b"0123XXXX\0\0"
    );

    // Truncate README.md to 0 without hydrating its base blob from ObjectStore!
    let reads_before_trunc = counting.blob_reads();
    let readme_attr = core.lookup(ROOT_INO, "README.md").expect("lookup README");
    let trunc_attr = core
        .setattr(readme_attr.ino, None, Some(0))
        .expect("truncate to 0");
    assert_eq!(trunc_attr.size, 0);
    assert_eq!(
        counting.blob_reads(),
        reads_before_trunc,
        "truncating to 0 must not hydrate base blob"
    );
    core.write(readme_attr.ino, 0, b"# Updated\n")
        .expect("rewrite README");

    // mkdir, nested create, rmdir ENOTEMPTY guard, unlink, then rmdir.
    let scratch_attr = core.mkdir(ROOT_INO, "scratch").expect("mkdir scratch");
    assert_eq!(scratch_attr.kind, VfsFileType::Directory);
    assert_eq!(core.mkdir(ROOT_INO, "scratch"), Err(libc::EEXIST));

    let (tmp_file, _) = core
        .create(scratch_attr.ino, "temp.txt", 0o644, 0)
        .expect("create temp.txt");
    core.write(tmp_file.ino, 0, b"ephemeral").expect("write temp");
    assert_eq!(
        core.rmdir(ROOT_INO, "scratch"),
        Err(libc::ENOTEMPTY),
        "non-empty dir must fail rmdir with ENOTEMPTY"
    );
    core.unlink(scratch_attr.ino, "temp.txt")
        .expect("unlink temp.txt");
    core.rmdir(ROOT_INO, "scratch").expect("rmdir empty scratch");
    assert_eq!(core.lookup(ROOT_INO, "scratch"), Err(libc::ENOENT));

    // Rename file across directories (preserving inode number!).
    let moved_dir = core.mkdir(ROOT_INO, "moved").expect("mkdir moved");
    let orig_ino = new_attr.ino;
    core.rename(src_attr.ino, "created.rs", moved_dir.ino, "relocated.rs", 0)
        .expect("rename file");
    assert_eq!(core.lookup(src_attr.ino, "created.rs"), Err(libc::ENOENT));
    let relocated_attr = core
        .lookup(moved_dir.ino, "relocated.rs")
        .expect("lookup relocated.rs");
    assert_eq!(
        relocated_attr.ino, orig_ino,
        "POSIX rename must preserve inode number"
    );
    assert_eq!(
        core.read(relocated_attr.ino, 0, 128).expect("read relocated"),
        b"pub const NEW: bool = true;\n"
    );

    // Unlink a base file -> creates tombstone, keeps rest untouched.
    core.unlink(bin_attr.ino, "run.sh").expect("unlink base file");
    assert_eq!(core.lookup(bin_attr.ino, "run.sh"), Err(libc::ENOENT));
    assert_eq!(core.stats().tombstones, 1);

    // Verify ONLY the 3 dirty files exist on disk in overlay_root!
    // Dirty files: README.md, docs/guide.txt, moved/relocated.rs
    assert_eq!(count_files_on_disk(&overlay_root), 3);

    // Snapshot is strictly O(dirty_files): 0 base blob reads, 3 dirty blob writes!
    counting.reset_counts();
    let snap = core
        .snapshot(DomainId::public())
        .expect("O(dirty_files) snapshot");
    assert_eq!(
        counting.blob_reads(),
        0,
        "snapshot must not read unmodified base blobs"
    );
    assert_eq!(
        counting.blob_writes(),
        3,
        "snapshot must upload strictly the 3 dirty overlay files"
    );

    let changes = WorkspaceManager::detect_changes(&snap, &base_tree);
    assert_eq!(
        changes,
        WorkspaceChanges {
            added: vec!["moved/relocated.rs".to_string()],
            modified: vec!["README.md".to_string(), "docs/guide.txt".to_string()],
            removed: vec!["bin/run.sh".to_string()],
        }
    );
    // Unmodified base entry retained exact original EntryKind.
    assert_eq!(
        snap.entries.get("packages/pkg_3/item_099.txt"),
        base_tree.entries.get("packages/pkg_3/item_099.txt")
    );
}

#[test]
fn loopback_vfs_server_and_client_end_to_end_over_tcp() {
    let tmp = TempDir::new().expect("tempdir");
    let overlay_root = tmp.path().join("loopback-overlay");

    let counting = Arc::new(CountingStore::new());
    let store: Arc<dyn ObjectStore> = counting.clone();
    let base_tree = seed_sample_tree(store.as_ref());

    counting.reset_counts();
    let ws = LazyWorkspace::mount(&overlay_root, Arc::clone(&store), base_tree.clone())
        .expect("lazy mount");
    let server =
        LoopbackVfsServer::start("127.0.0.1:0", ws, Arc::clone(&store)).expect("start server");
    assert_eq!(server.addr().ip().to_string(), "127.0.0.1");
    assert_ne!(server.addr().port(), 0);
    assert_eq!(count_files_on_disk(&overlay_root), 0);

    let mut client = LoopbackVfsClient::connect(server.addr()).expect("connect client");
    let mut client2 = LoopbackVfsClient::connect(server.addr()).expect("connect second client");

    // 1. GetAttr & ReadDir on root (zero blob hydrations).
    let root = client.getattr(ROOT_INO).expect("root getattr");
    assert_eq!(root.kind, VfsFileType::Directory);
    let root_entries = client.readdir(ROOT_INO).expect("root readdir");
    assert!(root_entries.iter().any(|e| e.name == "README.md"));
    assert!(root_entries.iter().any(|e| e.name == "src"));
    assert_eq!(counting.blob_reads(), 0);

    // 2. Lookup & demand-paged Read over TCP.
    let src = client.lookup(ROOT_INO, "src").expect("lookup src");
    let nested = client.lookup(src.ino, "nested").expect("lookup nested");
    let mod_rs = client.lookup(nested.ino, "mod.rs").expect("lookup mod.rs");
    let content = client.read(mod_rs.ino, 0, 1024).expect("read mod.rs");
    assert_eq!(content, b"pub const ANSWER: u64 = 42;\n");
    assert_eq!(counting.blob_reads(), 1);
    assert_eq!(count_files_on_disk(&overlay_root), 0);

    // Second client reads cached file -> cache hit, still 1 store read!
    let cached = client2.read(mod_rs.ino, 10, 6).expect("client2 offset read");
    assert_eq!(cached, b"ANSWER");
    assert_eq!(counting.blob_reads(), 1);

    // 3. Mkdir, Create, Write, SetAttr, Rename, Remove over TCP.
    let sub = client.mkdir(ROOT_INO, "agent_out").expect("mkdir agent_out");
    let created = client
        .create(sub.ino, "draft.txt", false)
        .expect("create draft.txt");
    let n = client
        .write(created.ino, 0, b"hello via loopback tcp\n")
        .expect("write draft.txt");
    assert_eq!(n as usize, b"hello via loopback tcp\n".len());

    client
        .rename(sub.ino, "draft.txt", sub.ino, "final.txt")
        .expect("rename draft -> final");
    assert!(matches!(
        client.lookup(sub.ino, "draft.txt"),
        Err(GitxError::NotFound(_))
    ));
    let final_attr = client.lookup(sub.ino, "final.txt").expect("lookup final.txt");
    assert_eq!(
        client.read(final_attr.ino, 0, 256).expect("read final.txt"),
        b"hello via loopback tcp\n"
    );

    // Truncate final.txt to first 5 bytes ("hello").
    let shrunk = client
        .setattr(final_attr.ino, Some(5), Some(true))
        .expect("setattr shrink + exec");
    assert_eq!(shrunk.size, 5);
    assert_eq!(shrunk.perm, 0o755);
    assert_eq!(
        client2.read(final_attr.ino, 0, 64).expect("client2 read shrunk"),
        b"hello"
    );

    // Delete a base file over TCP.
    client.remove(ROOT_INO, "README.md").expect("remove README.md");
    assert!(matches!(
        client.lookup(ROOT_INO, "README.md"),
        Err(GitxError::NotFound(_))
    ));

    // 4. Stats & O(dirty_files) Snapshot over TCP.
    let stats = client.stats().expect("stats");
    assert_eq!(
        stats,
        LazyStats {
            total_virtual_files: 105,
            hydrated_reads: 1,
            overlay_dirty_files: 1,
            tombstones: 1,
            cache_hits: 1,
        }
    );
    assert_eq!(count_files_on_disk(&overlay_root), 1);

    counting.reset_counts();
    let snap = client
        .snapshot(DomainId::public())
        .expect("snapshot over tcp");
    assert_eq!(counting.blob_reads(), 0);
    assert_eq!(counting.blob_writes(), 1);

    let changes = WorkspaceManager::detect_changes(&snap, &base_tree);
    assert_eq!(
        changes,
        WorkspaceChanges {
            added: vec!["agent_out/final.txt".to_string()],
            modified: vec![],
            removed: vec!["README.md".to_string()],
        }
    );

    drop(client);
    drop(client2);
    server.shutdown();
}

#[cfg(all(target_os = "linux", feature = "fuse"))]
#[test]
fn live_linux_fuse3_mount_std_fs_read_write_delete_snapshot_unmount() {
    let tmp = TempDir::new().expect("tempdir");
    let overlay_root = tmp.path().join("live-fuse-overlay");
    let mountpoint = tmp.path().join("mnt");
    fs::create_dir_all(&mountpoint).expect("create mountpoint");

    let counting = Arc::new(CountingStore::new());
    let store: Arc<dyn ObjectStore> = counting.clone();
    let base_tree = seed_sample_tree(store.as_ref());

    counting.reset_counts();
    let ws = LazyWorkspace::mount(&overlay_root, Arc::clone(&store), base_tree.clone())
        .expect("lazy mount");

    let handle = match FuseMountHandle::mount_background(&mountpoint, ws, Arc::clone(&store)) {
        Ok(h) => h,
        Err(GitxError::Io(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
            ) || matches!(
                err.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENODEV | libc::ENOENT)
            ) =>
        {
            eprintln!("skipping live Linux FUSE3 mount test (sandbox restricted): {err}");
            return;
        }
        Err(err) => {
            let msg = err.to_string().to_lowercase();
            if msg.contains("permission denied")
                || msg.contains("operation not permitted")
                || msg.contains("fusermount")
            {
                eprintln!("skipping live Linux FUSE3 mount test (sandbox restricted): {err}");
                return;
            }
            panic!("unexpected FUSE3 mount failure: {err:?}");
        }
    };

    assert_eq!(handle.mountpoint(), mountpoint.as_path());
    assert_eq!(
        count_files_on_disk(&overlay_root),
        0,
        "mount must write zero base files to overlay_root"
    );

    // 1. Standard std::fs::read_dir and std::fs::read_to_string through Linux kernel FUSE3!
    let mut root_names: Vec<String> = fs::read_dir(&mountpoint)
        .expect("std::fs::read_dir on FUSE3 mount")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    root_names.sort();
    assert_eq!(
        root_names,
        vec!["README.md", "bin", "docs", "packages", "src"]
    );
    assert_eq!(
        counting.blob_reads(),
        0,
        "std::fs::read_dir must not hydrate blobs"
    );

    let readme = fs::read_to_string(mountpoint.join("README.md")).expect("read README via FUSE");
    assert_eq!(readme, "# GitX Virtual Mount\n");
    let nested =
        fs::read_to_string(mountpoint.join("src/nested/mod.rs")).expect("read nested via FUSE");
    assert_eq!(nested, "pub const ANSWER: u64 = 42;\n");
    assert_eq!(counting.blob_reads(), 2);
    assert_eq!(
        count_files_on_disk(&overlay_root),
        0,
        "reads must stay in memory without writing base files to overlay_root"
    );

    // 2. Write a brand new file, overwrite a base file, mkdir + rename, and delete a base file!
    fs::create_dir(mountpoint.join("generated")).expect("mkdir via FUSE");
    fs::write(mountpoint.join("generated/tmp.txt"), "hello kernel fuse3\n")
        .expect("write new file via FUSE");
    fs::rename(
        mountpoint.join("generated/tmp.txt"),
        mountpoint.join("generated/output.txt"),
    )
    .expect("rename via FUSE");
    assert_eq!(
        fs::read_to_string(mountpoint.join("generated/output.txt")).expect("read renamed"),
        "hello kernel fuse3\n"
    );

    fs::write(mountpoint.join("README.md"), "# Edited through FUSE3\n")
        .expect("overwrite base file via FUSE");
    assert_eq!(
        fs::read_to_string(mountpoint.join("README.md")).expect("read overwritten"),
        "# Edited through FUSE3\n"
    );

    fs::remove_file(mountpoint.join("docs/guide.txt")).expect("unlink base file via FUSE");
    assert!(!mountpoint.join("docs/guide.txt").exists());

    // Only the 2 dirty files (README.md and generated/output.txt) should exist in overlay_root!
    assert_eq!(count_files_on_disk(&overlay_root), 2);
    let stats = handle.stats();
    assert_eq!(stats.overlay_dirty_files, 2);
    assert_eq!(stats.tombstones, 1);

    // 3. Snapshot in O(dirty_files) directly from the live FUSE mount handle!
    counting.reset_counts();
    let snap = handle
        .snapshot(DomainId::public())
        .expect("snapshot live FUSE3 mount");
    assert_eq!(counting.blob_reads(), 0);
    assert_eq!(counting.blob_writes(), 2);

    let changes = WorkspaceManager::detect_changes(&snap, &base_tree);
    assert_eq!(
        changes,
        WorkspaceChanges {
            added: vec!["generated/output.txt".to_string()],
            modified: vec!["README.md".to_string()],
            removed: vec!["docs/guide.txt".to_string()],
        }
    );

    // 4. Clean explicit unmount.
    handle.unmount().expect("clean FUSE3 unmount");
}

#[test]
fn loopback_vfs_server_rejects_non_loopback_bind_addr() {
    let store: Arc<dyn ObjectStore> = Arc::new(CountingStore::new());
    let base_tree = DomainTree::new(DomainId::public());
    let tmp = TempDir::new().unwrap();
    let ws = LazyWorkspace::mount(tmp.path().join("overlay"), Arc::clone(&store), base_tree)
        .unwrap();
    let res = LoopbackVfsServer::start("0.0.0.0:0", ws, store);
    let err = match res {
        Ok(_) => panic!("expected non-loopback bind address to be rejected"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("loopback"),
        "expected loopback bind rejection, got: {err}"
    );
}
