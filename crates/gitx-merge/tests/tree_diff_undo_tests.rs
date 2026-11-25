use gitx_core::{DomainId, DomainTree, EntryKind, FileMode, GitxError, ObjectHash, Result};
use gitx_merge::{
    DiffStatus, MergeOutcome, diff_trees, materialize_conflict, merge_domain_trees,
    render_interdiff, resolve_conflict_by_deletion, resolve_conflict_in_tree, revert_agent_step,
    revert_agent_tree_step, unified_diff,
};
use std::cell::RefCell;
use std::collections::HashMap;

struct MemStore {
    blobs: RefCell<HashMap<ObjectHash, Vec<u8>>>,
}

impl MemStore {
    fn new() -> Self {
        Self {
            blobs: RefCell::new(HashMap::new()),
        }
    }

    fn put(&self, data: &[u8]) -> (ObjectHash, u64) {
        let hash = ObjectHash::of_bytes(data);
        let size = data.len() as u64;
        self.blobs.borrow_mut().insert(hash, data.to_vec());
        (hash, size)
    }

    fn get(&self, hash: ObjectHash) -> Result<Vec<u8>> {
        self.blobs
            .borrow()
            .get(&hash)
            .cloned()
            .ok_or_else(|| GitxError::NotFound(hash.to_hex()))
    }

    fn file_entry(&self, data: &[u8]) -> EntryKind {
        let (blob_hash, size) = self.put(data);
        EntryKind::File {
            blob_hash,
            mode: FileMode::Regular,
            size,
        }
    }
}

#[test]
fn algebraic_tree_merge_stores_conflicts_and_supports_partial_resolution() {
    let store = MemStore::new();

    let mut base = DomainTree::new(DomainId::public());
    base.insert("clean.txt", store.file_entry(b"a\nb\nc\nd\n"));
    base.insert("conflict_a.txt", store.file_entry(b"x = 1\n"));
    base.insert("conflict_b.txt", store.file_entry(b"y = 1\n"));
    base.insert(
        "Cargo.toml",
        store.file_entry(b"[dependencies]\nserde = \"1\"\n"),
    );

    let mut ours = base.clone();
    ours.insert("clean.txt", store.file_entry(b"A_OURS\nb\nc\nd\n"));
    ours.insert("conflict_a.txt", store.file_entry(b"x = 2\n"));
    ours.insert("conflict_b.txt", store.file_entry(b"y = 2\n"));
    ours.insert(
        "Cargo.toml",
        store.file_entry(b"[dependencies]\nserde = \"1\"\ntokio = \"1\"\n"),
    );

    let mut theirs = base.clone();
    theirs.insert("clean.txt", store.file_entry(b"a\nb\nc\nD_THEIRS\n"));
    theirs.insert("conflict_a.txt", store.file_entry(b"x = 3\n"));
    theirs.insert("conflict_b.txt", store.file_entry(b"y = 3\n"));
    theirs.insert(
        "Cargo.toml",
        store.file_entry(b"[dependencies]\nserde = \"1\"\naxum = \"0.8\"\n"),
    );

    let mut result = merge_domain_trees(
        &base,
        &ours,
        &theirs,
        |h| store.get(h),
        |bytes| Ok(store.put(bytes)),
    )
    .expect("algebraic tree merge must never fail on conflicts");

    // Clean paths merged, conflicts recorded natively in tree
    assert!(result.clean_paths.contains(&"clean.txt".to_string()));
    assert!(result.clean_paths.contains(&"Cargo.toml".to_string()));
    assert_eq!(
        result.conflict_paths,
        vec!["conflict_a.txt", "conflict_b.txt"]
    );
    assert!(result.tree.has_conflicts());
    assert_eq!(
        result.tree.conflict_paths(),
        vec!["conflict_a.txt", "conflict_b.txt"]
    );

    // Verify clean merged file contents
    if let Some(EntryKind::File { blob_hash, .. }) = result.tree.entries.get("clean.txt") {
        assert_eq!(store.get(*blob_hash).unwrap(), b"A_OURS\nb\nc\nD_THEIRS\n");
    } else {
        panic!("expected clean.txt to be a File");
    }

    // Verify conflict_a.txt stores ConflictTerm and materializes on demand
    let term_a = match result.tree.entries.get("conflict_a.txt") {
        Some(EntryKind::Conflict { term, mode }) => {
            assert_eq!(*mode, FileMode::Regular);
            assert_eq!(term.adds.len(), 2);
            assert_eq!(term.removes.len(), 1);
            term.clone()
        }
        other => panic!("expected Conflict entry, got {other:?}"),
    };

    let materialized = materialize_conflict(&term_a, "conflict_a.txt", |h| store.get(h)).unwrap();
    let materialized_str = String::from_utf8(materialized).unwrap();
    assert!(materialized_str.contains("<<<<<<< OURS\nx = 2\n"));
    assert!(materialized_str.contains("||||||| BASE\nx = 1\n"));
    assert!(materialized_str.contains("=======\nx = 3\n>>>>>>> THEIRS\n"));

    // Resolve ONLY conflict_a.txt; conflict_b.txt remains EntryKind::Conflict!
    let (resolved_hash, resolved_size) = store.put(b"x = 23\n");
    assert!(resolve_conflict_in_tree(
        &mut result.tree,
        "conflict_a.txt",
        resolved_hash,
        FileMode::Regular,
        resolved_size,
    ));
    // Resolving a non-conflict path returns false
    assert!(!resolve_conflict_in_tree(
        &mut result.tree,
        "clean.txt",
        resolved_hash,
        FileMode::Regular,
        resolved_size,
    ));
    assert!(result.tree.has_conflicts());
    assert_eq!(result.tree.conflict_paths(), vec!["conflict_b.txt"]);

    // Resolve conflict_b.txt -> tree is now completely conflict-free
    let (resolved_b_hash, resolved_b_size) = store.put(b"y = 23\n");
    assert!(resolve_conflict_in_tree(
        &mut result.tree,
        "conflict_b.txt",
        resolved_b_hash,
        FileMode::Regular,
        resolved_b_size,
    ));
    assert!(!result.tree.has_conflicts());
}

#[test]
fn algebraic_modify_delete_conflict_and_deletion_resolution() {
    let store = MemStore::new();

    let mut base = DomainTree::new(DomainId::public());
    base.insert("gone.txt", store.file_entry(b"original\n"));

    let mut ours = DomainTree::new(DomainId::public());
    ours.insert("gone.txt", store.file_entry(b"modified by ours\n"));

    let theirs = DomainTree::new(DomainId::public()); // deleted gone.txt

    let mut res = merge_domain_trees(
        &base,
        &ours,
        &theirs,
        |h| store.get(h),
        |bytes| Ok(store.put(bytes)),
    )
    .unwrap();

    assert_eq!(res.conflict_paths, vec!["gone.txt"]);
    let term = match res.tree.entries.get("gone.txt") {
        Some(EntryKind::Conflict { term, .. }) => term.clone(),
        other => panic!("expected conflict, got {other:?}"),
    };
    assert_eq!(term.adds.len(), 2);
    assert!(term.adds[0].is_some());
    assert!(term.adds[1].is_none());

    let mat = String::from_utf8(materialize_conflict(&term, "gone.txt", |h| store.get(h)).unwrap())
        .unwrap();
    assert!(mat.contains("modified by ours"));
    assert!(mat.contains("THEIRS (deleted)"));

    assert!(resolve_conflict_by_deletion(&mut res.tree, "gone.txt"));
    assert!(!res.tree.has_conflicts());
    assert!(!res.tree.entries.contains_key("gone.txt"));
}

#[test]
fn merge_domain_trees_rejects_mismatched_domains() {
    let store = MemStore::new();
    let base = DomainTree::new(DomainId::public());
    let ours = DomainTree::new(DomainId::team("core").unwrap());
    let theirs = DomainTree::new(DomainId::public());

    let err = merge_domain_trees(
        &base,
        &ours,
        &theirs,
        |h| store.get(h),
        |bytes| Ok(store.put(bytes)),
    )
    .unwrap_err();
    assert!(matches!(err, GitxError::Merge(_)));
}

#[test]
fn diff_trees_and_unified_diff_statuses() {
    let store = MemStore::new();

    let mut old = DomainTree::new(DomainId::public());
    old.insert("same.txt", store.file_entry(b"same\n"));
    old.insert("mod.txt", store.file_entry(b"old\n"));
    old.insert("del.txt", store.file_entry(b"gone\n"));

    let mut new = DomainTree::new(DomainId::public());
    new.insert("same.txt", store.file_entry(b"same\n"));
    new.insert("mod.txt", store.file_entry(b"new\n"));
    new.insert("add.txt", store.file_entry(b"fresh\n"));
    new.insert(
        "conf.txt",
        EntryKind::Conflict {
            term: gitx_core::ConflictTerm {
                adds: vec![
                    Some(ObjectHash::of_bytes(b"1")),
                    Some(ObjectHash::of_bytes(b"2")),
                ],
                removes: vec![Some(ObjectHash::of_bytes(b"0"))],
            },
            mode: FileMode::Regular,
        },
    );

    let entries = diff_trees(&old, &new);
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].path, "add.txt");
    assert_eq!(entries[0].status, DiffStatus::Added);
    assert_eq!(entries[1].path, "conf.txt");
    assert_eq!(entries[1].status, DiffStatus::Conflicted);
    assert_eq!(entries[2].path, "del.txt");
    assert_eq!(entries[2].status, DiffStatus::Deleted);
    assert_eq!(entries[3].path, "mod.txt");
    assert_eq!(entries[3].status, DiffStatus::Modified);

    let udiff = unified_diff("mod.txt", b"old\n", b"new\n");
    assert!(udiff.contains("--- a/mod.txt"));
    assert!(udiff.contains("+++ b/mod.txt"));
    assert!(udiff.contains("-old\n"));
    assert!(udiff.contains("+new\n"));
    assert!(unified_diff("same.txt", b"same\n", b"same\n").is_empty());
}

#[test]
fn render_interdiff_ignores_rebase_noise_and_shows_only_author_delta() {
    let store = MemStore::new();

    // v1_base: initial main
    let mut v1_base = DomainTree::new(DomainId::public());
    v1_base.insert(
        "src/feature.rs",
        store.file_entry(b"fn upstream() { 1 }\n\nfn helper() {}\n\nfn feature() { 10 }\n"),
    );
    v1_base.insert(
        "src/unrelated.rs",
        store.file_entry(b"pub const V: u32 = 1;\n"),
    );

    // v1_head: author implemented feature() -> 11
    let mut v1_head = v1_base.clone();
    v1_head.insert(
        "src/feature.rs",
        store.file_entry(b"fn upstream() { 1 }\n\nfn helper() {}\n\nfn feature() { 11 }\n"),
    );

    // v2_base: main moved forward (edited unrelated.rs AND top of feature.rs)
    let mut v2_base = DomainTree::new(DomainId::public());
    v2_base.insert(
        "src/feature.rs",
        store.file_entry(b"fn upstream() { 2 }\n\nfn helper() {}\n\nfn feature() { 10 }\n"),
    );
    v2_base.insert(
        "src/unrelated.rs",
        store.file_entry(b"pub const V: u32 = 2;\n"),
    );

    // Case 1: pure mechanical rebase with ZERO author changes -> interdiff is empty!
    let mut v2_head_pure_rebase = v2_base.clone();
    v2_head_pure_rebase.insert(
        "src/feature.rs",
        store.file_entry(b"fn upstream() { 2 }\n\nfn helper() {}\n\nfn feature() { 11 }\n"),
    );

    let pure_interdiff =
        render_interdiff(&v1_base, &v1_head, &v2_base, &v2_head_pure_rebase, |h| {
            store.get(h)
        })
        .unwrap();
    assert!(
        pure_interdiff.is_empty(),
        "pure rebase should have empty interdiff, got:\n{pure_interdiff}"
    );

    // Case 2: rebase + author amended feature() from 11 -> 12
    let mut v2_head_amended = v2_base.clone();
    v2_head_amended.insert(
        "src/feature.rs",
        store.file_entry(b"fn upstream() { 2 }\n\nfn helper() {}\n\nfn feature() { 12 }\n"),
    );

    let amended_interdiff = render_interdiff(&v1_base, &v1_head, &v2_base, &v2_head_amended, |h| {
        store.get(h)
    })
    .unwrap();
    assert!(amended_interdiff.contains("src/feature.rs"));
    assert!(amended_interdiff.contains("-fn feature() { 11 }"));
    assert!(amended_interdiff.contains("+fn feature() { 12 }"));
    // Must NOT include upstream noise!
    assert!(!amended_interdiff.contains("unrelated.rs"));
    assert!(!amended_interdiff.contains("-fn upstream() { 1 }"));
}

#[test]
fn render_interdiff_handles_overlapping_rebase_conflict_fallback() {
    let store = MemStore::new();

    let mut v1_base = DomainTree::new(DomainId::public());
    v1_base.insert("val.txt", store.file_entry(b"val = 0\n"));

    let mut v1_head = DomainTree::new(DomainId::public());
    v1_head.insert("val.txt", store.file_entry(b"val = 1\n"));

    let mut v2_base = DomainTree::new(DomainId::public());
    v2_base.insert("val.txt", store.file_entry(b"val = 10\n"));

    let mut v2_head = DomainTree::new(DomainId::public());
    v2_head.insert("val.txt", store.file_entry(b"val = 11\n"));

    let interdiff =
        render_interdiff(&v1_base, &v1_head, &v2_base, &v2_head, |h| store.get(h)).unwrap();
    assert!(interdiff.contains("v1/val.txt"));
    assert!(interdiff.contains("v2/val.txt"));
    assert!(interdiff.contains("+val = 11"));
}

#[test]
fn revert_agent_step_preserves_subsequent_human_edits() {
    // Text file: agent edits top, human edits bottom; undo agent preserves human edit
    let before_agent = b"fn a() { 1 }\n\nfn b() { 2 }\n\nfn c() { 3 }\n";
    let after_agent = b"fn a() { 999 }\n\nfn b() { 2 }\n\nfn c() { 3 }\n";
    let current = b"fn a() { 999 }\n\nfn b() { 2 }\n\nfn c() { 300 }\n";

    let outcome = revert_agent_step("src/lib.rs", before_agent, after_agent, current);
    assert_eq!(
        outcome,
        MergeOutcome::Clean(b"fn a() { 1 }\n\nfn b() { 2 }\n\nfn c() { 300 }\n".to_vec())
    );

    // TOML file: agent added `bad_crate`, human later added `good_crate` -> undo removes only `bad_crate`
    let before_toml = b"[dependencies]\nserde = \"1\"\n";
    let after_toml = b"[dependencies]\nserde = \"1\"\nbad_crate = \"0.1\"\n";
    let current_toml =
        b"[dependencies]\nserde = \"1\"\nbad_crate = \"0.1\"\ngood_crate = \"2.0\"\n";

    let toml_outcome = revert_agent_step("Cargo.toml", before_toml, after_toml, current_toml);
    match toml_outcome {
        MergeOutcome::Clean(bytes) => {
            let table: toml::Table = std::str::from_utf8(&bytes).unwrap().parse().unwrap();
            let deps = table["dependencies"].as_table().unwrap();
            assert_eq!(deps["serde"].as_str(), Some("1"));
            assert_eq!(deps["good_crate"].as_str(), Some("2.0"));
            assert!(!deps.contains_key("bad_crate"));
        }
        MergeOutcome::Conflict { materialized, .. } => {
            panic!(
                "expected clean TOML undo, got:\n{}",
                String::from_utf8_lossy(&materialized)
            );
        }
    }

    // Conflict if human edited the exact same line the agent changed
    let human_same_line = b"fn a() { 42 }\n\nfn b() { 2 }\n\nfn c() { 3 }\n";
    let conflict = revert_agent_step("src/lib.rs", before_agent, after_agent, human_same_line);
    assert!(conflict.is_conflict());
}

#[test]
fn revert_agent_tree_step_preserves_human_file_additions_and_edits() {
    let store = MemStore::new();

    let mut before = DomainTree::new(DomainId::public());
    before.insert("app.rs", store.file_entry(b"a\nb\nc\nd\n"));

    let mut after = DomainTree::new(DomainId::public());
    after.insert("app.rs", store.file_entry(b"AGENT\nb\nc\nd\n"));
    after.insert("agent_temp.rs", store.file_entry(b"// junk\n"));

    let mut current = after.clone();
    current.insert("app.rs", store.file_entry(b"AGENT\nb\nc\nHUMAN\n"));
    current.insert("human_notes.md", store.file_entry(b"# Notes\n"));

    let res = revert_agent_tree_step(
        &before,
        &after,
        &current,
        |h| store.get(h),
        |bytes| Ok(store.put(bytes)),
    )
    .unwrap();

    assert!(!res.tree.has_conflicts());
    assert!(!res.tree.entries.contains_key("agent_temp.rs"));
    assert!(res.tree.entries.contains_key("human_notes.md"));
    if let Some(EntryKind::File { blob_hash, .. }) = res.tree.entries.get("app.rs") {
        assert_eq!(store.get(*blob_hash).unwrap(), b"a\nb\nc\nHUMAN\n");
    } else {
        panic!("expected app.rs to be a File");
    }
}
