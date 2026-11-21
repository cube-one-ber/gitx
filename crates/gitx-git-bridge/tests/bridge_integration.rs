use chrono::{TimeZone, Utc};
use gitx_core::{
    Actor, ChangeSetBuilder, ConflictTerm, DomainId, DomainTree, EntryKind, FileMode, Identity,
    ObjectHash, VisibilityPolicy,
};
use gitx_git_bridge::{
    UPLOAD_PACK_ADVERTISEMENT_CONTENT_TYPE, UPLOAD_PACK_RESULT_CONTENT_TYPE,
    advertise_upload_pack_refs_with_protocol, export_to_git_repo, handle_upload_pack_with_protocol,
    import_from_git_repo,
};
use gitx_store::{MemoryStore, ObjectStore};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::thread;
use tempfile::TempDir;

fn run_git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("failed to execute git");
    assert!(
        output.status.success(),
        "git {:?} failed in {}:\nstdout: {}\nstderr: {}",
        args,
        dir.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn build_multi_domain_store() -> (MemoryStore, BTreeMap<String, ObjectHash>) {
    let store = MemoryStore::new();
    let alice = Identity {
        name: "Alice Example".to_string(),
        email: "alice@example.com".to_string(),
        key_fingerprint: None,
    };
    let agent = Actor::Agent {
        harness: "gitx-bot".to_string(),
        model: "v1".to_string(),
        session_id: "sess-42".to_string(),
        initiated_by: alice.clone(),
    };

    let public_dom = DomainId::public();
    let team_core = DomainId::team("core").unwrap();
    let team_security = DomainId::team("security").unwrap();
    let secret_prod = DomainId::secret("prod").unwrap();

    // Blobs for Commit 1
    let main_v1 = store
        .put_blob_bytes(b"fn main() { println!(\"hello public\"); }\n")
        .unwrap();
    let util_v1 = store
        .put_blob_bytes(b"pub fn answer() -> u32 { 42 }\n")
        .unwrap();
    let script_blob = store.put_blob_bytes(b"#!/bin/sh\necho ok\n").unwrap();
    let symlink_blob = store.put_blob_bytes(b"src/main.rs").unwrap();
    let sort_a = store.put_blob_bytes(b"a").unwrap();
    let sort_b = store.put_blob_bytes(b"b").unwrap();
    let sort_c = store.put_blob_bytes(b"c").unwrap();
    let sort_d = store.put_blob_bytes(b"d").unwrap();

    let algo_blob = store
        .put_blob_bytes(b"pub fn proprietary_score(x: i64) -> i64 { x * 9001 }\n")
        .unwrap();
    let env_blob = store
        .put_blob_bytes(b"DATABASE_URL=postgres://supersecret@prod/db\n")
        .unwrap();

    // Commit 1: Public primary domain, with additional team:core and secret:prod trees
    let mut pub_tree_1 = DomainTree::new(public_dom.clone());
    pub_tree_1.insert(
        "src/main.rs",
        EntryKind::File {
            blob_hash: main_v1.manifest_hash(),
            mode: FileMode::Regular,
            size: main_v1.total_size,
        },
    );
    pub_tree_1.insert(
        "src/nested/util.rs",
        EntryKind::File {
            blob_hash: util_v1.manifest_hash(),
            mode: FileMode::Regular,
            size: util_v1.total_size,
        },
    );
    pub_tree_1.insert(
        "scripts/run.sh",
        EntryKind::File {
            blob_hash: script_blob.manifest_hash(),
            mode: FileMode::Executable,
            size: script_blob.total_size,
        },
    );
    pub_tree_1.insert(
        "LATEST",
        EntryKind::File {
            blob_hash: symlink_blob.manifest_hash(),
            mode: FileMode::Symlink,
            size: symlink_blob.total_size,
        },
    );
    // Deliberate Git tree sort-order edge cases: '-' < '.' < '/' (dir) < '0'
    pub_tree_1.insert(
        "foo-bar.txt",
        EntryKind::File {
            blob_hash: sort_a.manifest_hash(),
            mode: FileMode::Regular,
            size: sort_a.total_size,
        },
    );
    pub_tree_1.insert(
        "foo.txt",
        EntryKind::File {
            blob_hash: sort_b.manifest_hash(),
            mode: FileMode::Regular,
            size: sort_b.total_size,
        },
    );
    pub_tree_1.insert(
        "foo/child.txt",
        EntryKind::File {
            blob_hash: sort_c.manifest_hash(),
            mode: FileMode::Regular,
            size: sort_c.total_size,
        },
    );
    pub_tree_1.insert(
        "foo0.txt",
        EntryKind::File {
            blob_hash: sort_d.manifest_hash(),
            mode: FileMode::Regular,
            size: sort_d.total_size,
        },
    );

    let mut team_tree_1 = DomainTree::new(team_core.clone());
    team_tree_1.insert(
        "packages/private/algo.rs",
        EntryKind::File {
            blob_hash: algo_blob.manifest_hash(),
            mode: FileMode::Regular,
            size: algo_blob.total_size,
        },
    );

    let mut secret_tree_1 = DomainTree::new(secret_prod.clone());
    secret_tree_1.insert(
        ".env",
        EntryKind::EncryptedSecret {
            envelope_hash: env_blob.manifest_hash(),
            key_epoch: 1,
            mode: FileMode::Regular,
        },
    );

    let pub_tree_1_hash = store.put_tree(&pub_tree_1).unwrap();
    let team_tree_1_hash = store.put_tree(&team_tree_1).unwrap();
    let secret_tree_1_hash = store.put_tree(&secret_tree_1).unwrap();

    let cs1 = ChangeSetBuilder::new(alice.clone())
        .domain_tree(public_dom.clone(), pub_tree_1_hash)
        .domain_tree(team_core.clone(), team_tree_1_hash)
        .domain_tree(secret_prod.clone(), secret_tree_1_hash)
        .visibility(VisibilityPolicy::public())
        .created_at(Utc.with_ymd_and_hms(2026, 1, 10, 12, 0, 0).unwrap())
        .description("Initial public commit")
        .build();
    let cs1_id = store.put_changeset(&cs1).unwrap();

    // Commit 2: Embargoed security fix (embargo:cve-2026-1, allowed only to team:security)
    let main_sec = store
        .put_blob_bytes(b"fn main() { /* CVE-2026-1 fix */ }\n")
        .unwrap();
    let mut pub_tree_embargo = pub_tree_1.clone();
    pub_tree_embargo.insert(
        "src/main.rs",
        EntryKind::File {
            blob_hash: main_sec.manifest_hash(),
            mode: FileMode::Regular,
            size: main_sec.total_size,
        },
    );
    let pub_tree_embargo_hash = store.put_tree(&pub_tree_embargo).unwrap();

    let embargo_vis =
        VisibilityPolicy::embargoed("cve-2026-1", vec![team_security], None).unwrap();
    let cs2 = ChangeSetBuilder::new(alice.clone())
        .parents(vec![cs1_id])
        .domain_tree(public_dom.clone(), pub_tree_embargo_hash)
        .domain_tree(team_core.clone(), team_tree_1_hash)
        .domain_tree(secret_prod.clone(), secret_tree_1_hash)
        .visibility(embargo_vis)
        .created_at(Utc.with_ymd_and_hms(2026, 1, 11, 12, 0, 0).unwrap())
        .description("EMBARGO CVE-2026-1: critical auth bypass fix")
        .build();
    let cs2_id = store.put_changeset(&cs2).unwrap();

    // Commit 3: Public follow-up whose parent is the embargoed commit (tests parent remapping!)
    let readme_blob = store.put_blob_bytes(b"# GitX Public Repo\n").unwrap();
    let mut pub_tree_3 = pub_tree_1.clone();
    pub_tree_3.insert(
        "README.md",
        EntryKind::File {
            blob_hash: readme_blob.manifest_hash(),
            mode: FileMode::Regular,
            size: readme_blob.total_size,
        },
    );
    // Also add an unresolved conflict entry to verify it is omitted safely and counted.
    pub_tree_3.insert(
        "CONFLICTED.txt",
        EntryKind::Conflict {
            term: ConflictTerm {
                adds: vec![Some(main_v1.manifest_hash()), Some(main_sec.manifest_hash())],
                removes: vec![None],
            },
            mode: FileMode::Regular,
        },
    );
    let pub_tree_3_hash = store.put_tree(&pub_tree_3).unwrap();

    let cs3 = ChangeSetBuilder::new(alice)
        .committer(agent)
        .parents(vec![cs2_id])
        .public_parents(vec![cs1.public_projection_hash])
        .domain_tree(public_dom, pub_tree_3_hash)
        .domain_tree(team_core, team_tree_1_hash)
        .domain_tree(secret_prod, secret_tree_1_hash)
        .visibility(VisibilityPolicy::public())
        .has_conflicts(true)
        .created_at(Utc.with_ymd_and_hms(2026, 1, 12, 12, 0, 0).unwrap())
        .description("Add README documentation")
        .build();
    let cs3_id = store.put_changeset(&cs3).unwrap();

    let mut bookmarks = BTreeMap::new();
    bookmarks.insert("master".to_string(), cs3_id);
    (store, bookmarks)
}

#[test]
fn export_public_only_passes_strict_fsck_and_strips_private_and_embargo() {
    let (store, bookmarks) = build_multi_domain_store();
    let temp = TempDir::new().unwrap();
    let bare_dir = temp.path().join("public.git");

    let report = export_to_git_repo(&store, &bare_dir, &[DomainId::public()], &bookmarks).unwrap();

    assert_eq!(report.exported_commits, 2);
    assert_eq!(report.skipped_private_commits, 1);
    // Commit 1 omits 2 entries (algo.rs + .env); Commit 3 omits 3 entries (algo.rs + .env + CONFLICTED.txt).
    assert_eq!(report.omitted_private_files, 5);
    assert!(report.ref_map.contains_key("master"));

    // Real git fsck --full --strict MUST pass with exit code 0!
    run_git(&bare_dir, &["fsck", "--full", "--strict"]);

    // Verify ls-tree contains ONLY public files and ZERO private/secret/conflict paths.
    let files_out = run_git(&bare_dir, &["ls-tree", "-r", "--name-only", "master"]);
    let files: Vec<&str> = files_out.lines().collect();
    assert!(files.contains(&"src/main.rs"));
    assert!(files.contains(&"src/nested/util.rs"));
    assert!(files.contains(&"README.md"));
    assert!(files.contains(&"scripts/run.sh"));
    assert!(files.contains(&"LATEST"));
    assert!(files.contains(&"foo-bar.txt"));
    assert!(files.contains(&"foo.txt"));
    assert!(files.contains(&"foo/child.txt"));
    assert!(files.contains(&"foo0.txt"));

    assert!(!files.contains(&".env"), "secret .env leaked into public export!");
    assert!(
        !files.contains(&"packages/private/algo.rs"),
        "team:core file leaked into public export!"
    );
    assert!(
        !files.contains(&"CONFLICTED.txt"),
        "unresolved conflict entry leaked into export!"
    );

    // Verify file modes (executable & symlink) are preserved.
    let full_tree = run_git(&bare_dir, &["ls-tree", "-r", "master"]);
    assert!(full_tree.contains("100755 blob "));
    assert!(full_tree.contains("\tscripts/run.sh"));
    assert!(full_tree.contains("120000 blob "));
    assert!(full_tree.contains("\tLATEST"));

    // Verify commit history: ZERO embargo commit messages anywhere in git log --all!
    let log_all = run_git(&bare_dir, &["log", "--all", "--format=%s"]);
    let subjects: Vec<&str> = log_all.lines().collect();
    assert_eq!(
        subjects,
        vec!["Add README documentation", "Initial public commit"]
    );
    assert!(!log_all.contains("EMBARGO"));
    assert!(!log_all.contains("CVE-2026-1"));
    assert!(!log_all.contains("auth bypass"));

    // Verify commit 3's parent was cleanly remapped to commit 1.
    let rev_list = run_git(&bare_dir, &["rev-list", "master"]);
    let shas: Vec<&str> = rev_list.lines().collect();
    assert_eq!(shas.len(), 2);
    let parent_of_head = run_git(&bare_dir, &["rev-parse", "master^"]);
    assert_eq!(parent_of_head.trim(), shas[1]);
}

#[test]
fn export_with_team_core_includes_private_algo_but_still_strips_secret_and_embargo() {
    let (store, bookmarks) = build_multi_domain_store();
    let temp = TempDir::new().unwrap();
    let bare_dir = temp.path().join("team-core.git");

    let allowed = vec![DomainId::public(), DomainId::team("core").unwrap()];
    let report = export_to_git_repo(&store, &bare_dir, &allowed, &bookmarks).unwrap();

    assert_eq!(report.exported_commits, 2);
    assert_eq!(report.skipped_private_commits, 1);

    run_git(&bare_dir, &["fsck", "--full", "--strict"]);

    let files_out = run_git(&bare_dir, &["ls-tree", "-r", "--name-only", "master"]);
    let files: Vec<&str> = files_out.lines().collect();
    assert!(files.contains(&"src/main.rs"));
    assert!(files.contains(&"packages/private/algo.rs"));
    assert!(!files.contains(&".env"));

    let algo_content = run_git(&bare_dir, &["show", "master:packages/private/algo.rs"]);
    assert_eq!(
        algo_content,
        "pub fn proprietary_score(x: i64) -> i64 { x * 9001 }\n"
    );

    let log_all = run_git(&bare_dir, &["log", "--all", "--format=%B"]);
    assert!(!log_all.contains("EMBARGO"));
    assert!(!log_all.contains("CVE-2026-1"));
}

#[test]
fn export_with_embargo_authorization_includes_security_commit() {
    let (store, bookmarks) = build_multi_domain_store();
    let temp = TempDir::new().unwrap();
    let bare_dir = temp.path().join("security.git");

    let allowed = vec![
        DomainId::public(),
        DomainId::team("core").unwrap(),
        DomainId::team("security").unwrap(),
        DomainId::embargo("cve-2026-1").unwrap(),
    ];
    let report = export_to_git_repo(&store, &bare_dir, &allowed, &bookmarks).unwrap();

    assert_eq!(report.exported_commits, 3);
    assert_eq!(report.skipped_private_commits, 0);

    run_git(&bare_dir, &["fsck", "--full", "--strict"]);

    let log_all = run_git(&bare_dir, &["log", "--all", "--format=%s"]);
    let subjects: Vec<&str> = log_all.lines().collect();
    assert_eq!(
        subjects,
        vec![
            "Add README documentation",
            "EMBARGO CVE-2026-1: critical auth bypass fix",
            "Initial public commit",
        ]
    );
}

#[test]
fn import_from_real_git_repo_roundtrips_losslessly_including_packed_objects() {
    let temp = TempDir::new().unwrap();
    let src_repo = temp.path().join("src-repo");
    fs::create_dir_all(&src_repo).unwrap();

    run_git(&src_repo, &["init", "-b", "main"]);
    run_git(&src_repo, &["config", "user.name", "Bob Builder"]);
    run_git(&src_repo, &["config", "user.email", "bob@example.com"]);

    // Commit 1: root + nested files + binary blob
    fs::create_dir_all(src_repo.join("crates/app/src")).unwrap();
    fs::write(src_repo.join("README.md"), "# Demo\n").unwrap();
    fs::write(
        src_repo.join("crates/app/src/lib.rs"),
        "pub fn greet() -> &'static str { \"hi\" }\n",
    )
    .unwrap();
    let binary_data: Vec<u8> = vec![0x00, 0xFF, 0x10, 0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x00];
    fs::write(src_repo.join("assets/logo.bin"), {
        fs::create_dir_all(src_repo.join("assets")).unwrap();
        &binary_data
    })
    .unwrap();

    run_git(&src_repo, &["add", "."]);
    run_git(&src_repo, &["commit", "-m", "Initial import commit"]);

    // Commit 2: modify file, add executable script, add symlink
    fs::write(
        src_repo.join("crates/app/src/lib.rs"),
        "pub fn greet() -> &'static str { \"hello world\" }\n",
    )
    .unwrap();
    let script_path = src_repo.join("bin/deploy.sh");
    fs::create_dir_all(script_path.parent().unwrap()).unwrap();
    fs::write(&script_path, "#!/usr/bin/env bash\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();
        std::os::unix::fs::symlink("README.md", src_repo.join("DOCS.md")).unwrap();
    }

    run_git(&src_repo, &["add", "."]);
    run_git(
        &src_repo,
        &[
            "commit",
            "-m",
            "Second commit with scripts\n\nDetailed multi-line body.",
        ],
    );

    // Pack all objects into a real Git packfile to verify packed-object import works seamlessly!
    run_git(&src_repo, &["gc", "--aggressive"]);

    // Import into MemoryStore
    let store = MemoryStore::new();
    let import_report = import_from_git_repo(&src_repo, &store, DomainId::public()).unwrap();

    assert_eq!(import_report.imported_commits, 2);
    assert_eq!(import_report.branch, "main");
    let head_id = import_report.head_changeset.expect("head changeset");
    assert_eq!(store.get_bookmark("main").unwrap(), Some(head_id));

    // Inspect imported ChangeSets and trees directly in gitx-store
    let head_cs = store.get_changeset(head_id).unwrap();
    assert_eq!(
        head_cs.description,
        "Second commit with scripts\n\nDetailed multi-line body."
    );
    assert_eq!(head_cs.author.name, "Bob Builder");
    assert_eq!(head_cs.author.email, "bob@example.com");
    assert_eq!(head_cs.parents.len(), 1);

    let parent_cs = store.get_changeset(head_cs.parents[0]).unwrap();
    assert_eq!(parent_cs.description, "Initial import commit");
    assert!(parent_cs.parents.is_empty());

    let head_tree_hash = head_cs.domain_trees[&DomainId::public()];
    let head_tree = store.get_tree(head_tree_hash).unwrap();
    match &head_tree.entries["assets/logo.bin"] {
        EntryKind::File {
            blob_hash, mode, ..
        } => {
            assert_eq!(*mode, FileMode::Regular);
            assert_eq!(store.read_blob_bytes(*blob_hash).unwrap(), binary_data);
        }
        other => panic!("expected regular file, got {other:?}"),
    }
    #[cfg(unix)]
    {
        assert!(matches!(
            head_tree.entries["bin/deploy.sh"],
            EntryKind::File {
                mode: FileMode::Executable,
                ..
            }
        ));
        assert!(matches!(
            head_tree.entries["DOCS.md"],
            EntryKind::File {
                mode: FileMode::Symlink,
                ..
            }
        ));
    }

    // Export back out to a brand-new Git repo and verify strict fsck + byte-for-byte content match
    let roundtrip_dir = temp.path().join("roundtrip.git");
    let bookmarks = store.list_bookmarks().unwrap();
    export_to_git_repo(&store, &roundtrip_dir, &[DomainId::public()], &bookmarks).unwrap();

    run_git(&roundtrip_dir, &["fsck", "--full", "--strict"]);
    assert_eq!(
        run_git(&roundtrip_dir, &["show", "main:crates/app/src/lib.rs"]),
        "pub fn greet() -> &'static str { \"hello world\" }\n"
    );
    assert_eq!(
        run_git(&roundtrip_dir, &["show", "main^:crates/app/src/lib.rs"]),
        "pub fn greet() -> &'static str { \"hi\" }\n"
    );
    let log_subjects = run_git(&roundtrip_dir, &["log", "--format=%s", "main"]);
    assert_eq!(
        log_subjects.lines().collect::<Vec<_>>(),
        vec!["Second commit with scripts", "Initial import commit"]
    );
}

#[test]
fn smart_http_helpers_serve_real_git_clone_with_acl_filtering() {
    let (store, bookmarks) = build_multi_domain_store();
    let temp = TempDir::new().unwrap();
    let bare_dir = temp.path().join("served-public.git");
    export_to_git_repo(&store, &bare_dir, &[DomainId::public()], &bookmarks).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served_dir = bare_dir.clone();

    // Minimal one-off HTTP/1.1 Smart HTTP server exercising our pktline helpers.
    let server = thread::spawn(move || {
        // A git clone makes 2-3 HTTP requests (GET /info/refs + POST /git-upload-pack).
        for _ in 0..4 {
            listener.set_nonblocking(false).unwrap();
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut req_line = String::new();
            if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                continue;
            }
            let parts: Vec<&str> = req_line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let method = parts[0];
            let path = parts[1];

            let mut content_length: usize = 0;
            let mut git_protocol: Option<String> = None;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                let trimmed = header.trim();
                if trimmed.is_empty() {
                    break;
                }
                if let Some((k, v)) = trimmed.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        content_length = v.trim().parse().unwrap_or(0);
                    } else if k.eq_ignore_ascii_case("git-protocol") {
                        git_protocol = Some(v.trim().to_string());
                    }
                }
            }

            let mut req_body = vec![0u8; content_length];
            if content_length > 0 {
                reader.read_exact(&mut req_body).unwrap();
            }

            let (content_type, resp_body) = if method == "GET"
                && path.contains("/info/refs?service=git-upload-pack")
            {
                let body =
                    advertise_upload_pack_refs_with_protocol(&served_dir, git_protocol.as_deref())
                        .unwrap();
                (UPLOAD_PACK_ADVERTISEMENT_CONTENT_TYPE, body)
            } else if method == "POST" && path.ends_with("/git-upload-pack") {
                let body = handle_upload_pack_with_protocol(
                    &served_dir,
                    &req_body,
                    git_protocol.as_deref(),
                )
                .unwrap();
                (UPLOAD_PACK_RESULT_CONTENT_TYPE, body)
            } else {
                ("text/plain", b"not found".to_vec())
            };

            let resp_head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                resp_body.len()
            );
            stream.write_all(resp_head.as_bytes()).unwrap();
            stream.write_all(&resp_body).unwrap();
            stream.flush().unwrap();
        }
    });

    let clone_dest = temp.path().join("cloned");
    let url = format!("http://{addr}/repo.git");
    let output = Command::new("git")
        .args(["clone", &url, clone_dest.to_str().unwrap()])
        .output()
        .expect("failed to execute git clone");
    assert!(
        output.status.success(),
        "git clone over Smart HTTP failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Verify cloned working tree contains ONLY authorized public files!
    assert!(clone_dest.join("src/main.rs").exists());
    assert!(clone_dest.join("src/nested/util.rs").exists());
    assert!(clone_dest.join("README.md").exists());
    assert!(!clone_dest.join(".env").exists());
    assert!(!clone_dest.join("packages/private/algo.rs").exists());

    let log_all = run_git(&clone_dest, &["log", "--all", "--format=%B"]);
    assert!(!log_all.contains("EMBARGO"));
    assert!(!log_all.contains("CVE-2026-1"));
    assert!(log_all.contains("Initial public commit"));
    assert!(log_all.contains("Add README documentation"));

    // Cleanly wake and finish server thread if it didn't receive all 4 connections.
    for _ in 0..4 {
        let _ = std::net::TcpStream::connect(addr);
    }
    let _ = server.join();
}
