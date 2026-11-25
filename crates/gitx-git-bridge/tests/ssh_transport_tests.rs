use chrono::{TimeZone, Utc};
use gitx_core::{
    ChangeSetBuilder, DomainId, DomainTree, EntryKind, FileMode, GitxError, Identity,
    VisibilityPolicy,
};
use gitx_git_bridge::{
    GitSshService, GitSshSession, PktLine, advertise_ssh_upload_pack_refs, decode_pkt_lines,
    encode_flush_pkt, encode_pkt_line, handle_ssh_command, parse_advertised_refs,
    parse_ssh_command,
};
use gitx_store::{MemoryStore, ObjectStore};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn run_git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {:?} failed:\nstdout: {}\nstderr: {}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn build_multi_domain_repo() -> MemoryStore {
    let store = MemoryStore::new();
    let alice = Identity {
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
        key_fingerprint: None,
    };

    let public_dom = DomainId::public();
    let team_core = DomainId::team("core").unwrap();
    let team_sec = DomainId::team("security").unwrap();
    let secret_prod = DomainId::secret("prod").unwrap();

    // Public blobs
    let main_blob = store
        .put_blob_bytes(b"fn main() { println!(\"SSH_PUBLIC_VISIBLE\"); }\n")
        .unwrap();
    let readme_blob = store
        .put_blob_bytes(b"# Public Repo\nWelcome to GitX SSH transport.\n")
        .unwrap();

    // Private team:core blob
    let algo_blob = store
        .put_blob_bytes(b"pub const CORE_PRIVATE_ALGO: &str = \"SSH_PRIVATE_CORE_LEAK_GUARD\";\n")
        .unwrap();

    // Secret prod blob
    let env_blob = store
        .put_blob_bytes(b"DATABASE_PASSWORD=SSH_SECRET_PROD_NEVER_LEAK\n")
        .unwrap();

    // Embargoed fix blob
    let cve_blob = store
        .put_blob_bytes(b"pub fn cve_patch() { /* SSH_EMBARGO_CVE_2026_77 */ }\n")
        .unwrap();

    let mut pub_tree = DomainTree::new(public_dom.clone());
    pub_tree.insert(
        "src/main.rs",
        EntryKind::File {
            blob_hash: main_blob.manifest_hash(),
            mode: FileMode::Regular,
            size: main_blob.total_size,
        },
    );
    pub_tree.insert(
        "README.md",
        EntryKind::File {
            blob_hash: readme_blob.manifest_hash(),
            mode: FileMode::Regular,
            size: readme_blob.total_size,
        },
    );

    let mut core_tree = DomainTree::new(team_core.clone());
    core_tree.insert(
        "packages/private/algo.rs",
        EntryKind::File {
            blob_hash: algo_blob.manifest_hash(),
            mode: FileMode::Regular,
            size: algo_blob.total_size,
        },
    );

    let mut secret_tree = DomainTree::new(secret_prod.clone());
    secret_tree.insert(
        ".env",
        EntryKind::EncryptedSecret {
            envelope_hash: env_blob.manifest_hash(),
            key_epoch: 1,
            mode: FileMode::Regular,
        },
    );

    let pub_hash = store.put_tree(&pub_tree).unwrap();
    let core_hash = store.put_tree(&core_tree).unwrap();
    let secret_hash = store.put_tree(&secret_tree).unwrap();

    // Commit 1: Public + team:core + secret:prod trees
    let cs1 = ChangeSetBuilder::new(alice.clone())
        .domain_tree(public_dom.clone(), pub_hash)
        .domain_tree(team_core.clone(), core_hash)
        .domain_tree(secret_prod.clone(), secret_hash)
        .visibility(VisibilityPolicy::public())
        .created_at(Utc.with_ymd_and_hms(2026, 2, 1, 10, 0, 0).unwrap())
        .description("Initial public release")
        .build();
    let cs1_id = store.put_changeset(&cs1).unwrap();

    // Commit 2: Embargoed security commit visible only to team:security
    let mut emb_pub_tree = pub_tree.clone();
    emb_pub_tree.insert(
        "src/cve_patch.rs",
        EntryKind::File {
            blob_hash: cve_blob.manifest_hash(),
            mode: FileMode::Regular,
            size: cve_blob.total_size,
        },
    );
    let emb_pub_hash = store.put_tree(&emb_pub_tree).unwrap();
    let cs2 = ChangeSetBuilder::new(alice.clone())
        .parents(vec![cs1_id])
        .domain_tree(public_dom.clone(), emb_pub_hash)
        .domain_tree(team_core.clone(), core_hash)
        .domain_tree(secret_prod.clone(), secret_hash)
        .visibility(VisibilityPolicy::embargoed("cve-2026-77", vec![team_sec], None).unwrap())
        .created_at(Utc.with_ymd_and_hms(2026, 2, 2, 10, 0, 0).unwrap())
        .description("EMBARGOED CVE-2026-77 security patch")
        .build();
    let cs2_id = store.put_changeset(&cs2).unwrap();

    // Commit 3: Public follow-up on top of embargoed commit
    let mut pub_tree_3 = pub_tree;
    let changelog_blob = store.put_blob_bytes(b"## v0.2\n- Public update\n").unwrap();
    pub_tree_3.insert(
        "CHANGELOG.md",
        EntryKind::File {
            blob_hash: changelog_blob.manifest_hash(),
            mode: FileMode::Regular,
            size: changelog_blob.total_size,
        },
    );
    let pub_hash_3 = store.put_tree(&pub_tree_3).unwrap();
    let cs3 = ChangeSetBuilder::new(alice)
        .parents(vec![cs2_id])
        .public_parents(vec![cs1.public_projection_hash])
        .domain_tree(public_dom, pub_hash_3)
        .domain_tree(team_core, core_hash)
        .domain_tree(secret_prod, secret_hash)
        .visibility(VisibilityPolicy::public())
        .created_at(Utc.with_ymd_and_hms(2026, 2, 3, 10, 0, 0).unwrap())
        .description("Add CHANGELOG.md")
        .build();
    let cs3_id = store.put_changeset(&cs3).unwrap();

    store.set_bookmark("master", cs3_id).unwrap();
    store
}

/// Extracts raw `PACK...` bytes from a `git-upload-pack` SSH response (after `0008NAK\n`).
fn extract_pack_bytes(wire_response: &[u8]) -> &[u8] {
    let pos = wire_response
        .windows(4)
        .position(|w| w == b"PACK")
        .expect("expected PACK header in upload-pack response");
    &wire_response[pos..]
}

/// Unpacks a raw Git PACK stream into a fresh bare repo, verifies `git fsck --full --strict`,
/// and returns all unpacked object contents concatenated for leak inspection.
fn unpack_and_verify_pack(pack_bytes: &[u8]) -> (TempDir, Vec<String>, String) {
    let dir = TempDir::new().unwrap();
    run_git(dir.path(), &["init", "--bare"]);

    let mut unpack = Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .arg("unpack-objects")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn git unpack-objects");
    unpack
        .stdin
        .as_mut()
        .unwrap()
        .write_all(pack_bytes)
        .expect("write pack bytes");
    let output = unpack.wait_with_output().expect("wait unpack-objects");
    assert!(
        output.status.success(),
        "git unpack-objects failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Every unpacked object must pass strict Git fsck!
    run_git(dir.path(), &["fsck", "--full", "--strict"]);

    // Enumerate EVERY unpacked object (commits, trees, blobs)
    let all_oids_raw = run_git(
        dir.path(),
        &["cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)"],
    );
    let mut oids = Vec::new();
    let mut all_contents = String::new();
    for line in all_oids_raw.lines() {
        let Some((oid, kind)) = line.split_once(' ') else {
            continue;
        };
        oids.push(format!("{oid} {kind}"));
        let obj_text = run_git(dir.path(), &["cat-file", "-p", oid]);
        all_contents.push_str(&obj_text);
        all_contents.push('\n');
    }

    (dir, oids, all_contents)
}

#[test]
fn ssh_upload_pack_public_projection_negotiation_and_zero_leak() {
    let store = build_multi_domain_repo();
    let public_only = vec![DomainId::public()];

    // 1. Ref advertisement over SSH pkt-line framing
    let (adv_bytes, adv_report) =
        advertise_ssh_upload_pack_refs(&store, &public_only, None).unwrap();
    assert_eq!(adv_report.exported_commits, 2);
    assert_eq!(adv_report.skipped_private_commits, 1);
    assert!(adv_report.omitted_private_files > 0);

    let frames = decode_pkt_lines(&adv_bytes).unwrap();
    assert!(
        frames.iter().any(|f| matches!(f, PktLine::Flush)),
        "advertisement must terminate with flush packet 0000"
    );

    let refs = parse_advertised_refs(&adv_bytes).unwrap();
    let master_oid = *refs
        .get("refs/heads/master")
        .expect("refs/heads/master advertised");
    assert_eq!(refs.get("HEAD"), Some(&master_oid));

    // 2. Full SSH packfile negotiation (`want <oid>\n` + `0000` + `done\n`)
    let mut client_req = encode_pkt_line(format!("want {master_oid}\n").as_bytes());
    client_req.extend_from_slice(&encode_flush_pkt());
    client_req.extend_from_slice(&encode_pkt_line(b"done\n"));

    let mut wire_out = Vec::new();
    let report = handle_ssh_command(
        "git-upload-pack '/acme/mono.git'",
        &store,
        &public_only,
        client_req.as_slice(),
        &mut wire_out,
    )
    .unwrap();

    assert_eq!(report.service, GitSshService::UploadPack);
    assert_eq!(report.repo_path, "acme/mono");
    assert_eq!(report.bytes_written, wire_out.len());
    assert!(wire_out.windows(8).any(|w| w == b"0008NAK\n"));

    let pack_bytes = extract_pack_bytes(&wire_out);
    let (unpacked_dir, oids, all_contents) = unpack_and_verify_pack(pack_bytes);

    // Public commit content MUST be present
    assert!(all_contents.contains("SSH_PUBLIC_VISIBLE"));
    assert!(all_contents.contains("CHANGELOG.md"));
    assert!(all_contents.contains("Initial public release"));
    assert!(all_contents.contains("Add CHANGELOG.md"));

    // Verify ZERO private, secret, or embargoed data exists in unpacked objects OR raw wire bytes
    for forbidden in [
        "packages/private",
        "algo.rs",
        "SSH_PRIVATE_CORE_LEAK_GUARD",
        ".env",
        "SSH_SECRET_PROD_NEVER_LEAK",
        "cve_patch.rs",
        "SSH_EMBARGO_CVE_2026_77",
        "EMBARGOED CVE-2026-77",
    ] {
        assert!(
            !all_contents.contains(forbidden),
            "public SSH packfile leaked '{forbidden}' in objects: {oids:?}"
        );
        assert!(
            !wire_out
                .windows(forbidden.len())
                .any(|w| w == forbidden.as_bytes()),
            "public SSH wire stream leaked raw '{forbidden}'"
        );
    }

    // Verify exported master commit has exactly 2 commits in public history (embargo skipped & remapped)
    let log = run_git(
        unpacked_dir.path(),
        &["rev-list", "--count", &master_oid.to_hex()],
    );
    assert_eq!(log.trim(), "2");
}

#[test]
fn ssh_upload_pack_authorized_core_domain_includes_core_but_still_hides_secrets() {
    let store = build_multi_domain_repo();
    let core_domains = vec![DomainId::public(), DomainId::team("core").unwrap()];

    let (adv_bytes, _) = advertise_ssh_upload_pack_refs(&store, &core_domains, None).unwrap();
    let refs = parse_advertised_refs(&adv_bytes).unwrap();
    let master_oid = *refs.get("refs/heads/master").expect("master ref");

    let mut client_req = encode_pkt_line(format!("want {master_oid}\n").as_bytes());
    client_req.extend_from_slice(&encode_flush_pkt());
    client_req.extend_from_slice(&encode_pkt_line(b"done\n"));

    let mut wire_out = Vec::new();
    let session = GitSshSession::new(&store, core_domains);
    session
        .run(
            "git-upload-pack '/acme/mono.git'",
            client_req.as_slice(),
            &mut wire_out,
        )
        .unwrap();

    let pack_bytes = extract_pack_bytes(&wire_out);
    let (_dir, _oids, all_contents) = unpack_and_verify_pack(pack_bytes);

    // Authorized team:core sees both public and team:core files
    assert!(all_contents.contains("SSH_PUBLIC_VISIBLE"));
    assert!(all_contents.contains("SSH_PRIVATE_CORE_LEAK_GUARD"));

    // Still ZERO secret:prod or unauthorized embargo:cve-2026-77 objects
    assert!(!all_contents.contains("SSH_SECRET_PROD_NEVER_LEAK"));
    assert!(!all_contents.contains("SSH_EMBARGO_CVE_2026_77"));
}

#[test]
fn ssh_receive_pack_enforces_write_acl_and_rejects_malicious_commands() {
    let store = build_multi_domain_repo();
    let public_only = vec![DomainId::public()];

    // Read-only session rejects git-receive-pack with AccessDenied AND emits a Git pkt-line ERR
    let mut out = Vec::new();
    let err = handle_ssh_command(
        "git-receive-pack '/acme/mono.git'",
        &store,
        &public_only,
        &[][..],
        &mut out,
    )
    .unwrap_err();
    assert!(matches!(err, GitxError::AccessDenied { .. }));
    let frames = decode_pkt_lines(&out).unwrap();
    assert!(matches!(frames.first(), Some(PktLine::Data(d)) if d.starts_with(b"ERR ")));

    // Session whose write_domain is outside allowed_domains is also denied
    let mut out2 = Vec::new();
    let session = GitSshSession::new(&store, public_only.clone())
        .with_write_domain(DomainId::team("core").unwrap());
    let err2 = session
        .run("git-receive-pack '/acme/mono.git'", &[][..], &mut out2)
        .unwrap_err();
    assert!(matches!(err2, GitxError::AccessDenied { .. }));

    // Malicious / invalid SSH commands are rejected cleanly before spawning any process
    for bad_cmd in [
        "git-upload-pack '/acme/../../etc/passwd'",
        "git-upload-pack '/acme/repo.git; cat /etc/passwd'",
        "sh -c id",
        "",
    ] {
        assert!(
            parse_ssh_command(bad_cmd).is_err(),
            "expected command '{bad_cmd}' to be rejected"
        );
    }
}

#[test]
fn ssh_receive_pack_preserves_other_domains_and_blocks_public_secret_push() {
    let store = build_multi_domain_repo();
    let public_only = vec![DomainId::public()];

    // Record original team:core and secret:prod tree hashes before push
    let before_head = store.get_bookmark("master").unwrap().unwrap();
    let before_cs = store.get_changeset(before_head).unwrap();
    let team_core = DomainId::team("core").unwrap();
    let secret_prod = DomainId::secret("prod").unwrap();
    let orig_core_tree = before_cs.domain_trees[&team_core];
    let orig_secret_tree = before_cs.domain_trees[&secret_prod];

    // Clone public view into a temporary working repo by exporting it via git-export
    let tmp = TempDir::new().unwrap();
    let bare_clone = tmp.path().join("projected.git");
    let mut bookmarks = std::collections::BTreeMap::new();
    bookmarks.insert("master".to_string(), before_head);
    gitx_git_bridge::export_to_git_repo(&store, &bare_clone, &public_only, &bookmarks).unwrap();
    let work_dir = tmp.path().join("work");
    run_git(
        tmp.path(),
        &[
            "clone",
            bare_clone.to_str().unwrap(),
            work_dir.to_str().unwrap(),
        ],
    );
    run_git(&work_dir, &["config", "user.name", "Alice"]);
    run_git(&work_dir, &["config", "user.email", "alice@acme.dev"]);
    let old_oid = run_git(&work_dir, &["rev-parse", "HEAD"]).trim().to_string();

    // 1. Clean public commit pushed through GitSshSession::ReceivePack
    std::fs::write(work_dir.join("PUBLIC_NOTE.md"), "clean public update\n").unwrap();
    run_git(&work_dir, &["add", "PUBLIC_NOTE.md"]);
    run_git(&work_dir, &["commit", "-m", "Public SSH push"]);
    let new_oid = run_git(&work_dir, &["rev-parse", "HEAD"]).trim().to_string();

    // Build packfile for old_oid..new_oid using `git pack-objects --stdout`
    let mut pack_child = Command::new("git")
        .arg("-C")
        .arg(&work_dir)
        .args(["pack-objects", "--stdout", "--revs"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    pack_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{new_oid}\n^{old_oid}\n").as_bytes())
        .unwrap();
    let pack_out = pack_child.wait_with_output().unwrap();
    assert!(pack_out.status.success());

    let mut req = encode_pkt_line(
        format!("{old_oid} {new_oid} refs/heads/master\0report-status\n").as_bytes(),
    );
    req.extend_from_slice(&encode_flush_pkt());
    req.extend_from_slice(&pack_out.stdout);

    let session = GitSshSession::new(&store, public_only.clone()).with_write_domain(DomainId::public());
    let mut wire_out = Vec::new();
    session
        .run("git-receive-pack '/acme/mono.git'", req.as_slice(), &mut wire_out)
        .expect("clean public SSH receive-pack should succeed");

    let after_head = store.get_bookmark("master").unwrap().unwrap();
    assert_ne!(after_head, before_head);
    let after_cs = store.get_changeset(after_head).unwrap();
    // Untouched private/secret domains MUST be preserved!
    assert_eq!(after_cs.domain_trees.get(&team_core), Some(&orig_core_tree));
    assert_eq!(after_cs.domain_trees.get(&secret_prod), Some(&orig_secret_tree));
    let pub_tree = store.get_tree(after_cs.domain_trees[&DomainId::public()]).unwrap();
    assert!(pub_tree.entries.contains_key("PUBLIC_NOTE.md"));

    // 2. Pushing a leaked secret credential to public MUST be rejected
    let old_oid2 = new_oid;
    std::fs::write(
        work_dir.join("leaked.txt"),
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    run_git(&work_dir, &["add", "leaked.txt"]);
    run_git(&work_dir, &["commit", "-m", "Accidental AWS key"]);
    let secret_oid = run_git(&work_dir, &["rev-parse", "HEAD"]).trim().to_string();

    let mut pack_child2 = Command::new("git")
        .arg("-C")
        .arg(&work_dir)
        .args(["pack-objects", "--stdout", "--revs"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    pack_child2
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{secret_oid}\n^{old_oid2}\n").as_bytes())
        .unwrap();
    let pack_out2 = pack_child2.wait_with_output().unwrap();
    assert!(pack_out2.status.success());

    let mut req2 = encode_pkt_line(
        format!("{old_oid2} {secret_oid} refs/heads/master\0report-status\n").as_bytes(),
    );
    req2.extend_from_slice(&encode_flush_pkt());
    req2.extend_from_slice(&pack_out2.stdout);

    let mut wire_out2 = Vec::new();
    let secret_err = session
        .run("git-receive-pack '/acme/mono.git'", req2.as_slice(), &mut wire_out2)
        .unwrap_err();
    assert!(
        matches!(secret_err, GitxError::AccessDenied { .. }),
        "expected AccessDenied for leaked secret push, got: {secret_err:?}"
    );
    let wire2_text = String::from_utf8_lossy(&wire_out2);
    assert!(
        !wire2_text.contains("unpack ok") && !wire2_text.contains("ok refs/heads/master"),
        "rejected SSH receive-pack must never report unpack ok / ok ref to client, got:\n{wire2_text}"
    );
    assert!(
        wire2_text.contains("ERR "),
        "rejected SSH receive-pack should emit ERR pkt-line, got:\n{wire2_text}"
    );
    // Bookmark must remain unchanged after rejected push
    assert_eq!(store.get_bookmark("master").unwrap(), Some(after_head));

    // 3. Branch deletion over single-domain SSH receive-pack MUST be rejected and keep bookmark intact
    let zero_oid = "0".repeat(40);
    let mut del_req = encode_pkt_line(
        format!("{old_oid2} {zero_oid} refs/heads/master\0report-status\n").as_bytes(),
    );
    del_req.extend_from_slice(&encode_flush_pkt());
    let mut del_out = Vec::new();
    let _ = session.run(
        "git-receive-pack '/acme/mono.git'",
        del_req.as_slice(),
        &mut del_out,
    );
    let del_text = String::from_utf8_lossy(&del_out);
    assert!(
        del_text.contains("deletion prohibited") || del_text.contains("ng refs/heads/master"),
        "expected git-receive-pack to reject branch deletion, got:\n{del_text}"
    );
    assert_eq!(store.get_bookmark("master").unwrap(), Some(after_head));
}

#[test]
fn export_to_git_repo_never_leaks_active_embargo_via_flat_embargo_domain_id() {
    let store = build_multi_domain_repo();
    let pub_dom = DomainId::public();
    let embargo_dom = DomainId::embargo("cve-2026-77").unwrap();
    let mallory_dom = DomainId::new("private:user:mallory").unwrap();

    // Even if a flat allowlist mistakenly includes `embargo:cve-2026-77` alongside Mallory's domain,
    // `export_to_git_repo` MUST NOT expose the `team:security`-only embargoed changeset blobs!
    let tmp = TempDir::new().unwrap();
    let bare_dir = tmp.path().join("mallory.git");
    let bookmarks = store.list_bookmarks().unwrap();
    let report = gitx_git_bridge::export_to_git_repo(
        &store,
        &bare_dir,
        &[pub_dom, mallory_dom, embargo_dom],
        &bookmarks,
    )
    .unwrap();
    assert_eq!(report.exported_commits, 2);
    assert_eq!(report.skipped_private_commits, 1);

    let all_oids = run_git(
        &bare_dir,
        &["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"],
    );
    for oid in all_oids.lines() {
        if oid.trim().is_empty() {
            continue;
        }
        let body = run_git(&bare_dir, &["cat-file", "-p", oid.trim()]);
        assert!(
            !body.contains("SSH_EMBARGO_CVE_2026_77") && !body.contains("cve_patch.rs"),
            "flat embargo domain id leaked active embargo commit/blob {oid}"
        );
    }
}

#[test]
fn ssh_receive_pack_authorized_secret_updates_acl_admin_and_atomic_multiref() {
    use gitx_crypto::{AclPolicy, Principal};

    let store = MemoryStore::new();
    let alice = Identity {
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
        key_fingerprint: None,
    };
    let pub_dom = DomainId::public();
    let team_core = DomainId::team("core").unwrap();
    let secret_prod = DomainId::secret("prod").unwrap();

    let acl_text = "\
path ** -> public
path packages/private/** -> team:core
path secrets/** -> secret:prod
domain public read=* write=*
domain team:core read=team:core write=team:core
domain secret:prod read=team:ops write=team:ops
";
    let acl_blob = store.put_blob_bytes(acl_text.as_bytes()).unwrap();
    let readme_blob = store.put_blob_bytes(b"hello\n").unwrap();
    let secret_blob = store.put_blob_bytes(b"TOKEN=v1\n").unwrap();

    let mut pub_tree = DomainTree::new(pub_dom.clone());
    pub_tree.insert(
        ".gitxacl",
        EntryKind::File {
            blob_hash: acl_blob.manifest_hash(),
            mode: FileMode::Regular,
            size: acl_blob.total_size,
        },
    );
    pub_tree.insert(
        "README.md",
        EntryKind::File {
            blob_hash: readme_blob.manifest_hash(),
            mode: FileMode::Regular,
            size: readme_blob.total_size,
        },
    );

    let mut sec_tree = DomainTree::new(secret_prod.clone());
    sec_tree.insert(
        "secrets/app.env",
        EntryKind::File {
            blob_hash: secret_blob.manifest_hash(),
            mode: FileMode::Regular,
            size: secret_blob.total_size,
        },
    );

    let pub_h = store.put_tree(&pub_tree).unwrap();
    let sec_h = store.put_tree(&sec_tree).unwrap();
    let cs1 = ChangeSetBuilder::new(alice)
        .domain_tree(pub_dom.clone(), pub_h)
        .domain_tree(secret_prod.clone(), sec_h)
        .visibility(VisibilityPolicy::public())
        .created_at(Utc.with_ymd_and_hms(2026, 3, 1, 10, 0, 0).unwrap())
        .description("Initial")
        .build();
    let cs1_id = store.put_changeset(&cs1).unwrap();
    store.set_bookmark("master", cs1_id).unwrap();

    let build_pack = |work_dir: &Path, revs: &str| -> Vec<u8> {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(work_dir)
            .args(["pack-objects", "--stdout", "--revs"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(revs.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        out.stdout
    };

    // 1. Authorized `secret:prod` SSH session WITHOUT explicit Principal can update existing secret!
    let tmp = TempDir::new().unwrap();
    let sec_bare = tmp.path().join("sec.git");
    let bookmarks = store.list_bookmarks().unwrap();
    gitx_git_bridge::export_receive_pack_staging(&store, &sec_bare, &secret_prod, &bookmarks)
        .unwrap();
    let sec_work = tmp.path().join("sec-work");
    run_git(
        tmp.path(),
        &[
            "clone",
            sec_bare.to_str().unwrap(),
            sec_work.to_str().unwrap(),
        ],
    );
    run_git(&sec_work, &["config", "user.name", "Ops"]);
    run_git(&sec_work, &["config", "user.email", "ops@acme.dev"]);
    let sec_old = run_git(&sec_work, &["rev-parse", "HEAD"]).trim().to_string();
    std::fs::write(sec_work.join("secrets/app.env"), "TOKEN=v2\n").unwrap();
    run_git(&sec_work, &["add", "secrets/app.env"]);
    run_git(&sec_work, &["commit", "-m", "Rotate secret"]);
    let sec_new = run_git(&sec_work, &["rev-parse", "HEAD"]).trim().to_string();
    let sec_pack = build_pack(&sec_work, &format!("{sec_new}\n^{sec_old}\n"));

    let mut sec_req = encode_pkt_line(
        format!("{sec_old} {sec_new} refs/heads/master\0report-status\n").as_bytes(),
    );
    sec_req.extend_from_slice(&encode_flush_pkt());
    sec_req.extend_from_slice(&sec_pack);

    let sec_session = GitSshSession::new(&store, vec![pub_dom.clone(), secret_prod.clone()])
        .with_write_domain(secret_prod.clone());
    let mut sec_out = Vec::new();
    sec_session
        .run("git-receive-pack '/acme/app.git'", sec_req.as_slice(), &mut sec_out)
        .expect("authorized secret:prod SSH session must be able to update existing secret");
    assert!(String::from_utf8_lossy(&sec_out).contains("unpack ok"));
    let updated_head = store.get_bookmark("master").unwrap().unwrap();
    let updated_cs = store.get_changeset(updated_head).unwrap();
    let updated_sec_tree = store.get_tree(updated_cs.domain_trees[&secret_prod]).unwrap();
    let EntryKind::File { blob_hash, .. } = updated_sec_tree.entries["secrets/app.env"] else {
        panic!("expected File entry");
    };
    assert_eq!(store.read_blob_bytes(blob_hash).unwrap(), b"TOKEN=v2\n");

    // 2. Multi-ref SSH push on `public`: `master` (valid) + `zz-bad` (disallowed `team:core` path)
    //    MUST fail atomically: client NEVER sees `unpack ok`, and `master` is untouched!
    let pub_bare = tmp.path().join("pub.git");
    let bookmarks2 = store.list_bookmarks().unwrap();
    gitx_git_bridge::export_receive_pack_staging_filtered(
        &store,
        &pub_bare,
        &pub_dom,
        &bookmarks2,
        |cs| [pub_dom.clone(), secret_prod.clone()].contains(&cs.visibility.primary_domain),
    )
    .unwrap();
    let pub_work = tmp.path().join("pub-work");
    run_git(
        tmp.path(),
        &[
            "clone",
            pub_bare.to_str().unwrap(),
            pub_work.to_str().unwrap(),
        ],
    );
    run_git(&pub_work, &["config", "user.name", "Alice"]);
    run_git(&pub_work, &["config", "user.email", "alice@acme.dev"]);
    let pub_old = run_git(&pub_work, &["rev-parse", "HEAD"]).trim().to_string();

    std::fs::write(pub_work.join("good.txt"), "ok\n").unwrap();
    run_git(&pub_work, &["add", "good.txt"]);
    run_git(&pub_work, &["commit", "-m", "Valid master commit"]);
    let good_oid = run_git(&pub_work, &["rev-parse", "HEAD"]).trim().to_string();

    run_git(&pub_work, &["checkout", "-b", "zz-bad"]);
    std::fs::create_dir_all(pub_work.join("packages/private")).unwrap();
    std::fs::write(pub_work.join("packages/private/forbidden.rs"), "nope\n").unwrap();
    run_git(&pub_work, &["add", "packages/private/forbidden.rs"]);
    run_git(&pub_work, &["commit", "-m", "Bad ref commit"]);
    let bad_oid = run_git(&pub_work, &["rev-parse", "HEAD"]).trim().to_string();

    let multi_pack = build_pack(&pub_work, &format!("{good_oid}\n{bad_oid}\n^{pub_old}\n"));
    let zero_oid = "0".repeat(40);
    let mut multi_req = encode_pkt_line(
        format!("{pub_old} {good_oid} refs/heads/master\0report-status\n").as_bytes(),
    );
    multi_req.extend_from_slice(&encode_pkt_line(
        format!("{zero_oid} {bad_oid} refs/heads/zz-bad\n").as_bytes(),
    ));
    multi_req.extend_from_slice(&encode_flush_pkt());
    multi_req.extend_from_slice(&multi_pack);

    let pub_session = GitSshSession::new(&store, vec![pub_dom.clone(), secret_prod.clone()])
        .with_write_domain(pub_dom.clone());
    let mut multi_out = Vec::new();
    let err = pub_session
        .run("git-receive-pack '/acme/app.git'", multi_req.as_slice(), &mut multi_out)
        .unwrap_err();
    assert!(matches!(err, GitxError::AccessDenied { .. }));
    let multi_out_str = String::from_utf8_lossy(&multi_out);
    assert!(
        !multi_out_str.contains("unpack ok") && !multi_out_str.contains("ok refs/heads/master"),
        "rejected multi-ref SSH push must NEVER send unpack ok, got:\n{multi_out_str}"
    );
    assert!(multi_out_str.contains("ERR "));
    assert_eq!(
        store.get_bookmark("master").unwrap(),
        Some(updated_head),
        "failed multi-ref SSH push must leave master completely untouched"
    );
    assert_eq!(store.get_bookmark("zz-bad").unwrap(), None);

    // 3. `GitSshSession::with_principal` + `with_acl_admin(true)` CAN update `.gitxacl` on `master`!
    run_git(&pub_work, &["checkout", "master"]);
    let updated_acl = format!("{acl_text}# updated by admin\n");
    std::fs::write(pub_work.join(".gitxacl"), &updated_acl).unwrap();
    run_git(&pub_work, &["add", ".gitxacl"]);
    run_git(&pub_work, &["commit", "-m", "Admin updates .gitxacl"]);
    let acl_oid = run_git(&pub_work, &["rev-parse", "HEAD"]).trim().to_string();
    let acl_pack = build_pack(&pub_work, &format!("{acl_oid}\n^{pub_old}\n"));
    let mut acl_req = encode_pkt_line(
        format!("{pub_old} {acl_oid} refs/heads/master\0report-status\n").as_bytes(),
    );
    acl_req.extend_from_slice(&encode_flush_pkt());
    acl_req.extend_from_slice(&acl_pack);

    let admin_principal = Principal {
        id: "alice".to_string(),
        teams: vec!["ops".to_string(), "core".to_string()],
        roles: vec!["admin".to_string()],
        is_anonymous: false,
        fingerprint: None,
    };
    let parsed_policy = AclPolicy::parse(acl_text).unwrap();
    let admin_session = GitSshSession::new(
        &store,
        vec![pub_dom.clone(), team_core, secret_prod],
    )
    .with_write_domain(pub_dom)
    .with_acl_policy(parsed_policy)
    .with_principal(admin_principal)
    .with_acl_admin(true);
    let mut acl_out = Vec::new();
    admin_session
        .run("git-receive-pack '/acme/app.git'", acl_req.as_slice(), &mut acl_out)
        .expect("admin SSH session with with_acl_admin(true) must be allowed to update .gitxacl");
    assert!(String::from_utf8_lossy(&acl_out).contains("unpack ok"));
}

#[test]
fn ssh_receive_pack_full_duplex_open_stdin_never_deadlocks_and_cas_bookmarks_is_atomic() {
    use gitx_store::LocalStore;
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::time::Duration;

    let tmp = TempDir::new().unwrap();
    let store = Arc::new(LocalStore::open(tmp.path().join("store")).unwrap());
    let alice = Identity {
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
        key_fingerprint: None,
    };
    let pub_dom = DomainId::public();
    let readme = store.put_blob_bytes(b"v1\n").unwrap();
    let mut tree = DomainTree::new(pub_dom.clone());
    tree.insert(
        "README.md",
        EntryKind::File {
            blob_hash: readme.manifest_hash(),
            mode: FileMode::Regular,
            size: readme.total_size,
        },
    );
    let tree_h = store.put_tree(&tree).unwrap();
    let cs1 = ChangeSetBuilder::new(alice)
        .domain_tree(pub_dom.clone(), tree_h)
        .visibility(VisibilityPolicy::public())
        .created_at(Utc.with_ymd_and_hms(2026, 3, 2, 10, 0, 0).unwrap())
        .description("Initial")
        .build();
    let cs1_id = store.put_changeset(&cs1).unwrap();
    store.set_bookmark("master", cs1_id).unwrap();

    // Clone public staging view so we have real Git commits + packfiles
    let bare = tmp.path().join("bare.git");
    let bookmarks = store.list_bookmarks().unwrap();
    gitx_git_bridge::export_to_git_repo(
        store.as_ref(),
        &bare,
        std::slice::from_ref(&pub_dom),
        &bookmarks,
    )
    .unwrap();
    let work = tmp.path().join("work");
    run_git(
        tmp.path(),
        &["clone", bare.to_str().unwrap(), work.to_str().unwrap()],
    );
    run_git(&work, &["config", "user.name", "Alice"]);
    run_git(&work, &["config", "user.email", "alice@acme.dev"]);
    let old_oid = run_git(&work, &["rev-parse", "HEAD"]).trim().to_string();

    // Helper: read pkt-lines from a live TCP stream until a `0000` flush packet (without requiring EOF!)
    fn read_until_flush(stream: &mut TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut hdr = [0u8; 4];
            stream
                .read_exact(&mut hdr)
                .expect("read pkt-line hdr without timeout/deadlock");
            out.extend_from_slice(&hdr);
            if &hdr == b"0000" {
                break;
            }
            let len = usize::from_str_radix(std::str::from_utf8(&hdr).unwrap(), 16).unwrap();
            if len > 4 {
                let mut body = vec![0u8; len - 4];
                stream
                    .read_exact(&mut body)
                    .expect("read pkt-line body without timeout/deadlock");
                out.extend_from_slice(&body);
            }
        }
        out
    }

    let build_pack = |revs: &str| -> Vec<u8> {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&work)
            .args(["pack-objects", "--stdout", "--revs"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(revs.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        out.stdout
    };

    // 1. Live full-duplex ACCEPTED push with `side-band-64k report-status` where client keeps its
    //    write side OPEN (just like `git send-pack`) until reading the Phase-2 status + `0000`!
    std::fs::write(work.join("ok.txt"), "hello full duplex\n").unwrap();
    run_git(&work, &["add", "ok.txt"]);
    run_git(&work, &["commit", "-m", "Clean full-duplex push"]);
    let good_oid = run_git(&work, &["rev-parse", "HEAD"]).trim().to_string();
    let good_pack = build_pack(&format!("{good_oid}\n^{old_oid}\n"));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let store_srv = Arc::clone(&store);
    let srv_thread = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let reader = sock.try_clone().unwrap();
        let writer = sock;
        let session = GitSshSession::new(store_srv.as_ref(), vec![DomainId::public()])
            .with_write_domain(DomainId::public());
        session.run("git-receive-pack '/acme/app.git'", reader, writer)
    });

    let mut client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let adv = read_until_flush(&mut client);
    assert!(String::from_utf8_lossy(&adv).contains("refs/heads/master"));

    // Send update + packfile WITHOUT shutting down client write side!
    let mut push_msg = encode_pkt_line(
        format!("{old_oid} {good_oid} refs/heads/master\0report-status side-band-64k\n").as_bytes(),
    );
    push_msg.extend_from_slice(&encode_flush_pkt());
    push_msg.extend_from_slice(&good_pack);
    client.write_all(&push_msg).unwrap();
    client.flush().unwrap();

    // Must receive Phase-2 status BEFORE closing write pipe (proves zero deadlock!)
    let status_resp = read_until_flush(&mut client);
    assert!(
        String::from_utf8_lossy(&status_resp).contains("unpack ok"),
        "expected unpack ok while client stdin still open, got: {:?}",
        String::from_utf8_lossy(&status_resp)
    );
    drop(client); // Now client closes socket just like git send-pack does after reading status
    srv_thread
        .join()
        .unwrap()
        .expect("live full-duplex push must succeed cleanly");
    let head_after_good = store.get_bookmark("master").unwrap().unwrap();
    assert_ne!(head_after_good, cs1_id);

    // 2. Live full-duplex REJECTED push (leaked secret) with open stdin: client MUST receive
    //    Band-3 fatal rejection (NEVER `unpack ok`!) BEFORE closing write pipe, with zero deadlock!
    std::fs::write(
        work.join("leak.txt"),
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    run_git(&work, &["add", "leak.txt"]);
    run_git(&work, &["commit", "-m", "Leaked secret full-duplex"]);
    let bad_oid = run_git(&work, &["rev-parse", "HEAD"]).trim().to_string();
    let bad_pack = build_pack(&format!("{bad_oid}\n^{good_oid}\n"));

    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap();
    let store_srv2 = Arc::clone(&store);
    let srv_thread2 = std::thread::spawn(move || {
        let (sock, _) = listener2.accept().unwrap();
        let reader = sock.try_clone().unwrap();
        let writer = sock;
        let session = GitSshSession::new(store_srv2.as_ref(), vec![DomainId::public()])
            .with_write_domain(DomainId::public());
        session.run("git-receive-pack '/acme/app.git'", reader, writer)
    });

    let mut client2 = TcpStream::connect(addr2).unwrap();
    client2
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let _adv2 = read_until_flush(&mut client2);

    let mut bad_msg = encode_pkt_line(
        format!("{good_oid} {bad_oid} refs/heads/master\0report-status side-band-64k\n").as_bytes(),
    );
    bad_msg.extend_from_slice(&encode_flush_pkt());
    bad_msg.extend_from_slice(&bad_pack);
    client2.write_all(&bad_msg).unwrap();
    client2.flush().unwrap();

    let reject_resp = read_until_flush(&mut client2);
    let reject_str = String::from_utf8_lossy(&reject_resp);
    assert!(
        !reject_str.contains("unpack ok") && !reject_str.contains("ok refs/heads/master"),
        "rejected full-duplex push must never send unpack ok, got: {reject_str:?}"
    );
    assert!(
        reject_resp.len() >= 5 && reject_resp[4] == 3u8,
        "side-band-64k rejection must use Band 3 (fatal error), got: {reject_resp:?}"
    );
    drop(client2);
    let err = srv_thread2.join().unwrap().unwrap_err();
    assert!(matches!(err, GitxError::AccessDenied { .. }));
    assert_eq!(store.get_bookmark("master").unwrap(), Some(head_after_good));

    // 3. Atomic multi-bookmark `cas_bookmarks` rollback on LocalStore:
    //    If the second bookmark CAS fails, the first bookmark MUST NOT advance!
    let fake_new1 = gitx_core::ObjectHash::of_bytes(b"new1");
    let fake_new2 = gitx_core::ObjectHash::of_bytes(b"new2");
    let wrong_expected = gitx_core::ObjectHash::of_bytes(b"wrong");
    let cas_err = store
        .cas_bookmarks(&[
            ("master".to_string(), Some(head_after_good), fake_new1),
            ("other".to_string(), Some(wrong_expected), fake_new2),
        ])
        .unwrap_err();
    assert!(matches!(cas_err, GitxError::Merge(_)));
    assert_eq!(
        store.get_bookmark("master").unwrap(),
        Some(head_after_good),
        "failed multi-bookmark cas_bookmarks must roll back earlier bookmark updates atomically"
    );
    assert_eq!(store.get_bookmark("other").unwrap(), None);
}
