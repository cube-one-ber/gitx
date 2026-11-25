use chrono::{Duration, Utc};
use gitx_core::{
    Actor, ChangeId, ChangeSetBuilder, ConflictTerm, DomainId, DomainTree, EntryKind, FileMode,
    GitxError, Identity, ObjectHash, OpId, OpKind, OpLogEntry, Stack, StackState, VisibilityPolicy,
    WorkspaceRef, oplog::WorkspaceBackendKind,
};
use gitx_store::{LocalStore, MemoryStore, ObjectStore};
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};
use tempfile::TempDir;

fn test_identity() -> Identity {
    Identity {
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
        key_fingerprint: Some("fp-alice".to_string()),
    }
}

/// Deterministic pseudo-random byte generator (xorshift64*) so FastCDC produces multiple chunks
/// cleanly without pulling extra crates.
fn pseudo_random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.max(1);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let val = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        for b in val.to_le_bytes() {
            if out.len() < len {
                out.push(b);
            }
        }
    }
    out
}

fn run_fastcdc_blob_suite(store: &dyn ObjectStore) {
    // 1. Empty blob
    let empty_manifest = store.put_blob_bytes(&[]).unwrap();
    assert_eq!(empty_manifest.total_size, 0);
    assert_eq!(
        store
            .get_blob_manifest(empty_manifest.manifest_hash())
            .unwrap(),
        empty_manifest
    );
    assert_eq!(
        store
            .read_blob_bytes(empty_manifest.manifest_hash())
            .unwrap(),
        Vec::<u8>::new()
    );

    // 2. Small blob (<= 64 KiB inline threshold)
    let small = b"hello gitx content-addressed store!\n".repeat(100);
    let small_manifest = store.put_blob_bytes(&small).unwrap();
    assert_eq!(small_manifest.total_size, small.len() as u64);
    assert_eq!(small_manifest.chunks.len(), 1);
    assert!(store.has_chunk(small_manifest.chunks[0].hash).unwrap());
    assert_eq!(
        store
            .read_blob_bytes(small_manifest.manifest_hash())
            .unwrap(),
        small
    );

    // 3. Large blob (> 200 KiB -> multiple FastCDC chunks)
    let large = pseudo_random_bytes(320 * 1024, 0xCAFE_BABE_1234_5678);
    let large_manifest = store.put_blob_bytes(&large).unwrap();
    assert_eq!(large_manifest.total_size, large.len() as u64);
    assert!(
        large_manifest.chunks.len() > 1,
        "expected FastCDC to split 320 KiB into multiple chunks, got {}",
        large_manifest.chunks.len()
    );
    for chunk in &large_manifest.chunks {
        assert!(store.has_chunk(chunk.hash).unwrap());
        let raw_chunk = store.get_chunk(chunk.hash).unwrap();
        assert_eq!(raw_chunk.len() as u64, chunk.length);
    }
    let fetched_manifest = store
        .get_blob_manifest(large_manifest.manifest_hash())
        .unwrap();
    assert_eq!(fetched_manifest, large_manifest);
    let reconstructed = store
        .read_blob_bytes(large_manifest.manifest_hash())
        .unwrap();
    assert_eq!(reconstructed, large);

    // Missing chunk / manifest returns NotFound
    let missing = ObjectHash::of_bytes(b"does-not-exist");
    assert!(!store.has_chunk(missing).unwrap());
    assert!(matches!(
        store.get_chunk(missing),
        Err(GitxError::NotFound(_))
    ));
    assert!(matches!(
        store.get_blob_manifest(missing),
        Err(GitxError::NotFound(_))
    ));
}

fn run_raw_and_tree_suite(store: &dyn ObjectStore) {
    // Opaque raw object (e.g. encrypted secret envelope)
    let envelope = b"encrypted-secret-envelope-ciphertext-v1";
    let env_hash = ObjectHash::of_typed("gitx:envelope:v1", envelope);
    store.put_raw_object(env_hash, envelope).unwrap();
    assert_eq!(store.get_raw_object(env_hash).unwrap(), envelope);

    let missing = ObjectHash::of_bytes(b"missing-raw-obj");
    assert!(matches!(
        store.get_raw_object(missing),
        Err(GitxError::NotFound(_))
    ));

    // DomainTree with File, EncryptedSecret, and Conflict entries
    let blob = store.put_blob_bytes(b"fn main() {}\n").unwrap();
    let mut tree = DomainTree::new(DomainId::public());
    tree.insert(
        "src/main.rs",
        EntryKind::File {
            blob_hash: blob.manifest_hash(),
            mode: FileMode::Regular,
            size: blob.total_size,
        },
    );
    tree.insert(
        ".env.prod",
        EntryKind::EncryptedSecret {
            envelope_hash: env_hash,
            key_epoch: 7,
            mode: FileMode::Regular,
        },
    );
    tree.insert(
        "README.md",
        EntryKind::Conflict {
            term: ConflictTerm {
                adds: vec![Some(blob.manifest_hash()), Some(env_hash)],
                removes: vec![None],
            },
            mode: FileMode::Regular,
        },
    );

    let tree_hash = store.put_tree(&tree).unwrap();
    assert_eq!(tree_hash, tree.hash());
    let loaded = store.get_tree(tree_hash).unwrap();
    assert_eq!(loaded, tree);
    assert!(loaded.has_conflicts());

    assert!(matches!(
        store.get_tree(missing),
        Err(GitxError::NotFound(_))
    ));
}

fn run_changeset_history_suite(store: &dyn ObjectStore) {
    let author = test_identity();
    let change_a = ChangeId::new();
    let change_b = ChangeId::new();

    let base_time = Utc::now();
    // Create 3 revisions of `change_a` sharing identical timestamp to verify `previous_revision`
    // topological ordering even when inserted out of order.
    let rev1 = ChangeSetBuilder::new(author.clone())
        .change_id(change_a)
        .created_at(base_time)
        .description("v1: initial draft")
        .build();
    let rev2 = ChangeSetBuilder::new(author.clone())
        .change_id(change_a)
        .previous_revision(Some(rev1.id))
        .created_at(base_time)
        .description("v2: address review comments")
        .build();
    let rev3 = ChangeSetBuilder::new(author.clone())
        .change_id(change_a)
        .previous_revision(Some(rev2.id))
        .committer(Actor::Agent {
            harness: "t3".to_string(),
            model: "test-model".to_string(),
            session_id: "sess-1".to_string(),
            initiated_by: author.clone(),
        })
        .created_at(base_time)
        .description("v3: agent polish")
        .build();

    let other = ChangeSetBuilder::new(author)
        .change_id(change_b)
        .created_at(base_time + Duration::seconds(5))
        .description("unrelated change")
        .build();

    // Insert intentionally out of order (rev3, other, rev1, rev2) + duplicate rev1
    assert_eq!(store.put_changeset(&rev3).unwrap(), rev3.id);
    assert_eq!(store.put_changeset(&other).unwrap(), other.id);
    assert_eq!(store.put_changeset(&rev1).unwrap(), rev1.id);
    assert_eq!(store.put_changeset(&rev2).unwrap(), rev2.id);
    assert_eq!(store.put_changeset(&rev1).unwrap(), rev1.id); // idempotent

    assert_eq!(store.get_changeset(rev1.id).unwrap(), rev1);
    assert_eq!(store.get_changeset(rev2.id).unwrap(), rev2);
    assert_eq!(store.get_changeset(rev3.id).unwrap(), rev3);
    assert_eq!(store.get_changeset(other.id).unwrap(), other);

    let all = store.list_changesets().unwrap();
    assert_eq!(all.len(), 4);

    let history = store.get_revisions_for_change(change_a).unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].id, rev1.id);
    assert_eq!(history[1].id, rev2.id);
    assert_eq!(history[2].id, rev3.id);

    let other_hist = store.get_revisions_for_change(change_b).unwrap();
    assert_eq!(other_hist, vec![other]);

    let empty_hist = store.get_revisions_for_change(ChangeId::new()).unwrap();
    assert!(empty_hist.is_empty());

    assert!(matches!(
        store.get_changeset(ObjectHash::of_bytes(b"nope")),
        Err(GitxError::NotFound(_))
    ));
}

fn run_stack_suite(store: &dyn ObjectStore) {
    let now = Utc::now();
    let c1 = ChangeId::new();
    let c2 = ChangeId::new();

    let mut stack = Stack {
        name: "feat/auth".to_string(),
        base_target: "main".to_string(),
        changes: vec![c1],
        visibility: VisibilityPolicy::public(),
        state: StackState::Draft,
        created_at: now,
        updated_at: now,
    };

    store.put_stack(&stack).unwrap();
    assert_eq!(store.get_stack("feat/auth").unwrap(), stack);

    // Upsert updates existing stack
    stack.changes.push(c2);
    stack.state = StackState::InReview;
    stack.updated_at = now + Duration::seconds(10);
    store.put_stack(&stack).unwrap();
    assert_eq!(store.get_stack("feat/auth").unwrap(), stack);

    let stack2 = Stack {
        name: "fix/perf".to_string(),
        base_target: "main".to_string(),
        changes: vec![],
        visibility: VisibilityPolicy::private(DomainId::team("core").unwrap(), true),
        state: StackState::Approved,
        created_at: now,
        updated_at: now,
    };
    store.put_stack(&stack2).unwrap();

    let listed = store.list_stacks().unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].name, "feat/auth");
    assert_eq!(listed[1].name, "fix/perf");

    store.delete_stack("feat/auth").unwrap();
    assert!(matches!(
        store.get_stack("feat/auth"),
        Err(GitxError::NotFound(_))
    ));
    assert_eq!(store.list_stacks().unwrap().len(), 1);
    // Idempotent delete
    store.delete_stack("feat/auth").unwrap();
}

fn run_oplog_and_undo_suite(store: &dyn ObjectStore) {
    assert_eq!(store.latest_op().unwrap(), None);
    assert!(store.list_ops(10).unwrap().is_empty());

    let h1 = ObjectHash::of_bytes(b"cs-1");
    let h2 = ObjectHash::of_bytes(b"cs-2");
    let c1 = ChangeId::new();
    let c2 = ChangeId::new();

    let ws1 = WorkspaceRef {
        name: "default".to_string(),
        root_path: Some("/tmp/ws".to_string()),
        backend: WorkspaceBackendKind::CopyOnWrite,
        head_changeset: h1,
        head_change_id: c1,
    };

    // Initial state recorded in op1
    store.set_bookmark("main", h1).unwrap();
    store.put_workspace(&ws1).unwrap();

    let op1 = OpLogEntry {
        id: OpId::new(),
        parent: None,
        timestamp: Utc::now(),
        kind: OpKind::Init,
        summary: "init repo".to_string(),
        bookmarks: store.list_bookmarks().unwrap(),
        workspaces: store.list_workspaces().unwrap(),
        change_heads: BTreeMap::from([(c1, h1)]),
    };
    store.append_op(&op1).unwrap();
    assert_eq!(store.latest_op().unwrap(), Some(op1.clone()));
    assert_eq!(store.get_op(op1.id).unwrap(), op1);

    // Duplicate OpId should fail
    assert!(store.append_op(&op1).is_err());

    // Mutate state in op2
    let ws2 = WorkspaceRef {
        name: "default".to_string(),
        root_path: Some("/tmp/ws".to_string()),
        backend: WorkspaceBackendKind::Memory,
        head_changeset: h2,
        head_change_id: c2,
    };
    store.set_bookmark("main", h2).unwrap();
    store.set_bookmark("dev", h2).unwrap();
    store.put_workspace(&ws2).unwrap();

    let op2 = OpLogEntry {
        id: OpId::new(),
        parent: Some(op1.id),
        timestamp: Utc::now(),
        kind: OpKind::NewChange { change_id: c2 },
        summary: "advance main and create dev".to_string(),
        bookmarks: store.list_bookmarks().unwrap(),
        workspaces: store.list_workspaces().unwrap(),
        change_heads: BTreeMap::from([(c1, h1), (c2, h2)]),
    };
    store.append_op(&op2).unwrap();

    // Undo to op1 by recovering its snapshot
    let target = store.get_op(op1.id).unwrap();
    for (name, hash) in &target.bookmarks {
        store.set_bookmark(name, *hash).unwrap();
    }
    for ws in target.workspaces.values() {
        store.put_workspace(ws).unwrap();
    }

    let op3 = OpLogEntry {
        id: OpId::new(),
        parent: Some(op2.id),
        timestamp: Utc::now(),
        kind: OpKind::Undo { target_op: op1.id },
        summary: "undo back to op1".to_string(),
        bookmarks: target.bookmarks.clone(),
        workspaces: target.workspaces.clone(),
        change_heads: target.change_heads.clone(),
    };
    store.append_op(&op3).unwrap();

    assert_eq!(store.get_bookmark("main").unwrap(), Some(h1));
    assert_eq!(store.get_workspace("default").unwrap(), Some(ws1));
    assert_eq!(store.latest_op().unwrap(), Some(op3.clone()));

    let recent_two = store.list_ops(2).unwrap();
    assert_eq!(recent_two.len(), 2);
    assert_eq!(recent_two[0].id, op3.id);
    assert_eq!(recent_two[1].id, op2.id);

    let all_ops = store.list_ops(10).unwrap();
    assert_eq!(all_ops.len(), 3);
    assert_eq!(all_ops[2].id, op1.id);

    assert!(matches!(
        store.get_op(OpId::new()),
        Err(GitxError::NotFound(_))
    ));
}

fn run_land_ledger_and_cas_suite(store: &dyn ObjectStore) {
    let h1 = ObjectHash::of_bytes(b"head-1");
    let h2 = ObjectHash::of_bytes(b"head-2");
    let h3 = ObjectHash::of_bytes(b"head-3");
    let h_stale = ObjectHash::of_bytes(b"head-stale");
    let h_rel = ObjectHash::of_bytes(b"release-1");
    let c1 = ChangeId::new();
    let c2 = ChangeId::new();
    let c3 = ChangeId::new();

    // First land onto brand-new target fails if expected_previous is Some(...)
    let err = store
        .record_land("main", Some(h1), h2, vec![c1])
        .unwrap_err();
    assert!(matches!(err, GitxError::Merge(_)));
    assert_eq!(store.get_bookmark("main").unwrap(), None);

    // First land succeeds with expected_previous = None
    let l1 = store.record_land("main", None, h1, vec![c1]).unwrap();
    assert_eq!(l1.land_seq, 1);
    assert_eq!(l1.target, "main");
    assert_eq!(l1.previous_head, None);
    assert_eq!(l1.new_head, h1);
    assert_eq!(l1.landed_changes, vec![c1]);
    assert_eq!(l1.reverted_by, None);
    assert_eq!(store.get_bookmark("main").unwrap(), Some(h1));
    assert_eq!(store.get_land(1).unwrap(), l1);

    // Second land with correct expected_previous succeeds
    let l2 = store.record_land("main", Some(h1), h2, vec![c2]).unwrap();
    assert_eq!(l2.land_seq, 2);
    assert_eq!(l2.previous_head, Some(h1));
    assert_eq!(l2.new_head, h2);
    assert_eq!(store.get_bookmark("main").unwrap(), Some(h2));

    // Stale CAS attempts (None or old h1) MUST be rejected without mutating head or ledger
    assert!(matches!(
        store.record_land("main", None, h_stale, vec![c3]),
        Err(GitxError::Merge(_))
    ));
    assert!(matches!(
        store.record_land("main", Some(h1), h_stale, vec![c3]),
        Err(GitxError::Merge(_))
    ));
    assert_eq!(store.get_bookmark("main").unwrap(), Some(h2));

    // Independent target has its own head but shares global monotonic land_seq
    let l3 = store.record_land("release", None, h_rel, vec![c3]).unwrap();
    assert_eq!(l3.land_seq, 3);
    assert_eq!(store.get_bookmark("release").unwrap(), Some(h_rel));

    // Revert land 2 via a new land 4 pointing back to h1
    let l4 = store.record_land("main", Some(h2), h3, vec![]).unwrap();
    assert_eq!(l4.land_seq, 4);
    store.mark_reverted(l2.land_seq, l4.land_seq).unwrap();
    assert_eq!(
        store.get_land(l2.land_seq).unwrap().reverted_by,
        Some(l4.land_seq)
    );

    // Idempotent with same reverter, rejected with different reverter
    store.mark_reverted(l2.land_seq, l4.land_seq).unwrap();
    assert!(matches!(
        store.mark_reverted(l2.land_seq, 999),
        Err(GitxError::Merge(_))
    ));
    assert!(matches!(
        store.mark_reverted(999, 1),
        Err(GitxError::NotFound(_))
    ));

    // list_lands filters by target, newest first, respects limit
    let main_top_2 = store.list_lands("main", 2).unwrap();
    assert_eq!(main_top_2.len(), 2);
    assert_eq!(main_top_2[0].land_seq, 4);
    assert_eq!(main_top_2[1].land_seq, 2);
    assert_eq!(main_top_2[1].reverted_by, Some(4));

    let rel_lands = store.list_lands("release", 10).unwrap();
    assert_eq!(rel_lands.len(), 1);
    assert_eq!(rel_lands[0].land_seq, 3);
}

fn run_bookmarks_and_workspaces_suite(store: &dyn ObjectStore) {
    let h1 = ObjectHash::of_bytes(b"bm-1");
    let h2 = ObjectHash::of_bytes(b"bm-2");

    assert_eq!(store.get_bookmark("main").unwrap(), None);
    store.set_bookmark("main", h1).unwrap();
    store.set_bookmark("feat", h2).unwrap();
    assert_eq!(store.get_bookmark("main").unwrap(), Some(h1));
    assert_eq!(
        store.list_bookmarks().unwrap(),
        BTreeMap::from([("feat".to_string(), h2), ("main".to_string(), h1)])
    );

    let ws_a = WorkspaceRef {
        name: "alpha".to_string(),
        root_path: None,
        backend: WorkspaceBackendKind::Memory,
        head_changeset: h1,
        head_change_id: ChangeId::new(),
    };
    let ws_b = WorkspaceRef {
        name: "beta".to_string(),
        root_path: Some("/mnt/lazy/beta".to_string()),
        backend: WorkspaceBackendKind::LazyMount,
        head_changeset: h2,
        head_change_id: ChangeId::new(),
    };

    assert_eq!(store.get_workspace("alpha").unwrap(), None);
    store.put_workspace(&ws_a).unwrap();
    store.put_workspace(&ws_b).unwrap();
    assert_eq!(store.get_workspace("alpha").unwrap(), Some(ws_a.clone()));
    assert_eq!(store.list_workspaces().unwrap().len(), 2);

    store.remove_workspace("alpha").unwrap();
    assert_eq!(store.get_workspace("alpha").unwrap(), None);
    assert_eq!(store.list_workspaces().unwrap().len(), 1);
    // Idempotent remove
    store.remove_workspace("alpha").unwrap();
}

#[test]
fn memory_store_full_suite() {
    let store: Arc<dyn ObjectStore> = Arc::new(MemoryStore::new());
    run_fastcdc_blob_suite(store.as_ref());
    run_raw_and_tree_suite(store.as_ref());
    run_changeset_history_suite(store.as_ref());
    run_stack_suite(store.as_ref());

    let oplog_store = MemoryStore::new();
    run_oplog_and_undo_suite(&oplog_store);

    let bm_store = MemoryStore::new();
    run_bookmarks_and_workspaces_suite(&bm_store);

    let land_store = MemoryStore::new();
    run_land_ledger_and_cas_suite(&land_store);
}

#[test]
fn local_store_full_suite() {
    let dir = TempDir::new().unwrap();
    let local = LocalStore::open(dir.path()).unwrap();
    assert_eq!(local.root_dir(), dir.path());
    let store: Arc<dyn ObjectStore> = Arc::new(local);
    run_fastcdc_blob_suite(store.as_ref());
    run_raw_and_tree_suite(store.as_ref());
    run_changeset_history_suite(store.as_ref());
    run_stack_suite(store.as_ref());

    let oplog_dir = TempDir::new().unwrap();
    let oplog_store = LocalStore::open(oplog_dir.path()).unwrap();
    run_oplog_and_undo_suite(&oplog_store);

    let bm_dir = TempDir::new().unwrap();
    let bm_store = LocalStore::open(bm_dir.path()).unwrap();
    run_bookmarks_and_workspaces_suite(&bm_store);

    let land_dir = TempDir::new().unwrap();
    let land_store = LocalStore::open(land_dir.path()).unwrap();
    run_land_ledger_and_cas_suite(&land_store);
}

#[test]
fn local_store_sharded_cas_layout_and_compression() {
    let dir = TempDir::new().unwrap();
    let store = LocalStore::open(dir.path()).unwrap();

    // Highly compressible payload to verify LZ4 compression on disk
    let payload = vec![b'A'; 128 * 1024];
    let hash = ObjectHash::of_typed("gitx:chunk:v1", &payload);
    store.put_chunk(hash, &payload).unwrap();

    let hex = hash.to_hex();
    let expected_path = dir.path().join("cas").join(&hex[..2]).join(&hex);
    assert!(
        expected_path.is_file(),
        "expected sharded CAS file at {:?}",
        expected_path
    );

    let on_disk_len = std::fs::metadata(&expected_path).unwrap().len();
    assert!(
        on_disk_len < 4096,
        "expected LZ4-compressed 128 KiB repeated buffer to be < 4 KiB on disk, got {on_disk_len}"
    );
    assert_eq!(store.get_chunk(hash).unwrap(), payload);
}

#[test]
fn local_store_persistence_across_reopen() {
    let dir = TempDir::new().unwrap();
    let large_data = pseudo_random_bytes(260 * 1024, 0x00DE_ADBE_EF42);
    let author = test_identity();
    let cid = ChangeId::new();
    let now = Utc::now();

    let (manifest_hash, tree_hash, rev1, rev2, stack, op, land1, land2, ws) = {
        let store = LocalStore::open(dir.path()).unwrap();

        let blob = store.put_blob_bytes(&large_data).unwrap();
        let manifest_hash = blob.manifest_hash();

        let mut tree = DomainTree::new(DomainId::public());
        tree.insert(
            "assets/model.bin",
            EntryKind::File {
                blob_hash: manifest_hash,
                mode: FileMode::Regular,
                size: blob.total_size,
            },
        );
        let tree_hash = store.put_tree(&tree).unwrap();

        let rev1 = ChangeSetBuilder::new(author.clone())
            .change_id(cid)
            .domain_tree(DomainId::public(), tree_hash)
            .created_at(now)
            .description("rev 1")
            .build();
        let rev2 = ChangeSetBuilder::new(author)
            .change_id(cid)
            .previous_revision(Some(rev1.id))
            .domain_tree(DomainId::public(), tree_hash)
            .created_at(now + Duration::seconds(1))
            .description("rev 2")
            .build();
        store.put_changeset(&rev1).unwrap();
        store.put_changeset(&rev2).unwrap();

        let stack = Stack {
            name: "stack-persist".to_string(),
            base_target: "main".to_string(),
            changes: vec![cid],
            visibility: VisibilityPolicy::public(),
            state: StackState::Approved,
            created_at: now,
            updated_at: now,
        };
        store.put_stack(&stack).unwrap();

        let ws = WorkspaceRef {
            name: "primary".to_string(),
            root_path: Some("/repo/primary".to_string()),
            backend: WorkspaceBackendKind::CopyOnWrite,
            head_changeset: rev2.id,
            head_change_id: cid,
        };
        store.put_workspace(&ws).unwrap();

        let land1 = store.record_land("main", None, rev1.id, vec![cid]).unwrap();
        let land2 = store
            .record_land("main", Some(rev1.id), rev2.id, vec![cid])
            .unwrap();
        store.mark_reverted(land1.land_seq, land2.land_seq).unwrap();

        let op = OpLogEntry {
            id: OpId::new(),
            parent: None,
            timestamp: now,
            kind: OpKind::Land {
                target: "main".to_string(),
                land_seq: land2.land_seq,
                changes: vec![cid],
            },
            summary: "landed rev2".to_string(),
            bookmarks: store.list_bookmarks().unwrap(),
            workspaces: store.list_workspaces().unwrap(),
            change_heads: BTreeMap::from([(cid, rev2.id)]),
        };
        store.append_op(&op).unwrap();

        (
            manifest_hash,
            tree_hash,
            rev1,
            rev2,
            stack,
            op,
            land1,
            land2,
            ws,
        )
    };

    // Reopen from scratch and verify every piece of state persisted accurately
    let reopened = LocalStore::open(dir.path()).unwrap();

    assert_eq!(reopened.read_blob_bytes(manifest_hash).unwrap(), large_data);
    let tree = reopened.get_tree(tree_hash).unwrap();
    assert!(tree.entries.contains_key("assets/model.bin"));

    let revs = reopened.get_revisions_for_change(cid).unwrap();
    assert_eq!(revs, vec![rev1.clone(), rev2.clone()]);
    assert_eq!(reopened.get_stack("stack-persist").unwrap(), stack);
    assert_eq!(reopened.latest_op().unwrap(), Some(op.clone()));
    assert_eq!(reopened.get_op(op.id).unwrap(), op);
    assert_eq!(reopened.get_workspace("primary").unwrap(), Some(ws));
    assert_eq!(reopened.get_bookmark("main").unwrap(), Some(rev2.id));

    let reloaded_land1 = reopened.get_land(land1.land_seq).unwrap();
    assert_eq!(reloaded_land1.reverted_by, Some(land2.land_seq));
    assert_eq!(reopened.get_land(land2.land_seq).unwrap(), land2);

    // CAS must still reject stale head after reopen, and next land_seq must remain monotonic
    assert!(matches!(
        reopened.record_land(
            "main",
            Some(rev1.id),
            ObjectHash::of_bytes(b"stale"),
            vec![]
        ),
        Err(GitxError::Merge(_))
    ));
    let h3 = ObjectHash::of_bytes(b"head-after-reopen");
    let land3 = reopened
        .record_land("main", Some(rev2.id), h3, vec![])
        .unwrap();
    assert_eq!(land3.land_seq, land2.land_seq + 1);
    assert_eq!(reopened.get_bookmark("main").unwrap(), Some(h3));
}

#[test]
fn concurrent_record_land_prevents_split_brain() {
    let dir = TempDir::new().unwrap();
    let stores: Vec<Arc<dyn ObjectStore>> = vec![
        Arc::new(MemoryStore::new()),
        Arc::new(LocalStore::open(dir.path()).unwrap()),
    ];

    for store in stores {
        let initial = ObjectHash::of_bytes(b"base");
        store.set_bookmark("main", initial).unwrap();

        let threads = 8;
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::with_capacity(threads);

        for i in 0..threads {
            let s = Arc::clone(&store);
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let candidate = ObjectHash::of_bytes(format!("candidate-{i}").as_bytes());
                b.wait();
                s.record_land("main", Some(initial), candidate, vec![ChangeId::new()])
            }));
        }

        let mut successes = Vec::new();
        let mut conflicts = 0usize;
        for h in handles {
            match h.join().unwrap() {
                Ok(rec) => successes.push(rec),
                Err(GitxError::Merge(_)) => conflicts += 1,
                Err(other) => panic!("unexpected error: {other}"),
            }
        }

        assert_eq!(
            successes.len(),
            1,
            "exactly one concurrent lander must win CAS"
        );
        assert_eq!(conflicts, threads - 1);
        assert_eq!(
            store.get_bookmark("main").unwrap(),
            Some(successes[0].new_head)
        );
        assert_eq!(store.list_lands("main", 10).unwrap().len(), 1);
    }
}
