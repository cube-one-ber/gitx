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
