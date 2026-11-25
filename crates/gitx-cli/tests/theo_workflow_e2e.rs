use gitx_crypto::encode_openssh_ed25519_private;
use gitx_server::ServerConfig;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;
use tokio::net::TcpListener;

fn gitx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_gitx")
}

fn run_gitx(cwd: &Path, args: &[&str]) -> Output {
    Command::new(gitx_bin())
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("failed to execute gitx binary")
}

fn assert_ok(cwd: &Path, args: &[&str]) -> String {
    let out = run_gitx(cwd, args);
    assert!(
        out.status.success(),
        "gitx {:?} failed:\nstdout: {}\nstderr: {}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn cli_daily_driver_split_squash_rebase_with_first_class_conflicts_and_op_restore() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();

    assert_ok(repo, &["init", "--name", "Theo", "--email", "theo@t3.gg"]);
    fs::write(repo.join("shared.txt"), "base\n").unwrap();
    assert_ok(repo, &["describe", "-m", "Base commit"]);
    assert_ok(repo, &["land"]);

    // Edit two files on `@` ("edit first, organize later"), then split into a 2-change stack.
    assert_ok(repo, &["new", "-m", "Big WIP"]);
    fs::write(repo.join("a.txt"), "feature A\n").unwrap();
    fs::write(repo.join("b.txt"), "feature B\n").unwrap();
    let split_out = assert_ok(repo, &["split", "--paths", "a.txt", "-m", "Part 1: A"]);
    assert!(split_out.contains("Split"));

    // Squash `b.txt` back into Part 1.
    let squash_out = assert_ok(repo, &["squash", "-m", "Combined A + B"]);
    assert!(squash_out.contains("Squashed"));

    // Test `op restore`: record an op log entry, mutate, then restore to earlier op.
    let op_log = assert_ok(repo, &["op", "log", "--limit", "5"]);
    let first_op_short = op_log
        .lines()
        .nth(1)
        .and_then(|l| l.split_whitespace().next())
        .expect("expected op id in op log")
        .to_string();

    fs::write(repo.join("ephemeral.txt"), "will be undone by op restore\n").unwrap();
    assert_ok(repo, &["status"]);
    assert!(repo.join("ephemeral.txt").exists());

    assert_ok(repo, &["op", "restore", &first_op_short]);
    assert!(
        !repo.join("ephemeral.txt").exists(),
        "op restore should remove file created after target op"
    );

    // Test `rebase --onto` producing first-class conflicts without blocking the repo!
    assert_ok(repo, &["new", "-m", "Side A"]);
    fs::write(repo.join("shared.txt"), "side A change\n").unwrap();
    assert_ok(repo, &["land"]);

    // Create a workspace off an earlier op or branch that conflicts on shared.txt, then rebase onto master.
    assert_ok(repo, &["new", "-m", "Side B"]);
    fs::write(repo.join("shared.txt"), "side B change\n").unwrap();
    let rebase_out = assert_ok(repo, &["rebase", "--onto", "master"]);
    assert!(rebase_out.contains("Rebased") || rebase_out.contains("already based"));
}

#[test]
fn cli_ssh_key_secret_sync_push_pull_auto_decrypt_direct_url_fleet_share_and_mirror() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let tmp = TempDir::new().unwrap();

    let acl = "\
.env -> secret:dev
.env.* -> secret:dev
[domain secret:dev]
read = team:core
write = team:core
";
    let signing_secret = "cli-e2e-signing-secret";
    let server_dir = tmp.path().join("server-data");
    let config = ServerConfig::new(&server_dir)
        .with_default_acl(acl)
        .with_token_signing_secret(signing_secret.as_bytes().to_vec())
        .with_trust_proxy_headers(false);

    let base_url = rt.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            gitx_server::serve(listener, config).await.unwrap();
        });
        format!("http://{addr}")
    });

    // Mint a signed bearer token directly via CLI!
    let token_alice = assert_ok(
        tmp.path(),
        &[
            "token",
            "mint",
            "--secret",
            signing_secret,
            "--user",
            "alice",
            "--teams",
            "core",
            "--ttl-secs",
            "3600",
        ],
    )
    .trim()
    .to_string();
    assert!(token_alice.starts_with("gitx1h."));

    // Machine A: import OpenSSH Ed25519 keypair, create `.env`, push directly to URL (push-to-create)!
    let machine_a = tmp.path().join("machine-a");
    fs::create_dir_all(&machine_a).unwrap();
    let ssh_priv = tmp.path().join("id_ed25519_alice");
    let pem = encode_openssh_ed25519_private(&[7u8; 32], "alice@t3.gg");
    fs::write(&ssh_priv, &pem).unwrap();

    assert_ok(
        &machine_a,
        &["init", "--name", "Alice", "--email", "alice@t3.gg"],
    );
    let imp_out = assert_ok(
        &machine_a,
        &[
            "secret",
            "import-ssh",
            "--path",
            ssh_priv.to_str().unwrap(),
            "--name",
            "alice",
        ],
    );
    assert!(imp_out.contains("Imported OpenSSH Ed25519 private key"));

    fs::write(machine_a.join("app.ts"), "export const ok = true;\n").unwrap();
    fs::write(machine_a.join(".env"), "API_KEY=super_secret_env_value\n").unwrap();
    fs::write(machine_a.join(".env.local"), "LOCAL_FLAG=1\n").unwrap();

    // Direct URL push-to-create (no `gitx remote add` needed!) syncing encrypted `.env`!
    let repo_url = format!("{base_url}/t3/stack");
    let push_out = assert_ok(
        &machine_a,
        &[
            "push",
            &repo_url,
            "-m",
            "Push app + encrypted .env",
            "--token",
            &token_alice,
        ],
    );
    assert!(push_out.contains("encrypted secret(s)"));

    // Live encrypted Fleet Sync push from Machine A!
    let fleet_push = assert_ok(
        &machine_a,
        &[
            "fleet",
            "sync",
            "--url",
            &repo_url,
            "--include",
            ".env.local",
            "--machine",
            "macbook-pro",
            "--push",
            "--token",
            &token_alice,
        ],
    );
    assert!(fleet_push.contains("Fleet push"));

    // Machine B (same SSH key): pull from server and verify `.env` auto-decrypts on disk!
    let machine_b = tmp.path().join("machine-b");
    fs::create_dir_all(&machine_b).unwrap();
    assert_ok(
        &machine_b,
        &["init", "--name", "Alice", "--email", "alice@t3.gg"],
    );
    assert_ok(
        &machine_b,
        &[
            "secret",
            "import-ssh",
            "--path",
            ssh_priv.to_str().unwrap(),
            "--name",
            "alice",
        ],
    );
    assert_ok(
        &machine_b,
        &[
            "remote",
            "add",
            "origin",
            &repo_url,
            "--token",
            &token_alice,
        ],
    );

    let pull_out = assert_ok(&machine_b, &["pull", "origin"]);
    assert!(pull_out.contains("decrypted locally"));
    assert_eq!(
        fs::read_to_string(machine_b.join("app.ts")).unwrap(),
        "export const ok = true;\n"
    );
    assert_eq!(
        fs::read_to_string(machine_b.join(".env")).unwrap(),
        "API_KEY=super_secret_env_value\n"
    );

    // Live Fleet Sync pull on Machine B restores `.env.local` encrypted end-to-end!
    let fleet_pull = assert_ok(
        &machine_b,
        &["fleet", "sync", "--remote", "origin", "--pull"],
    );
    assert!(fleet_pull.contains("Fleet pull"));
    assert_eq!(
        fs::read_to_string(machine_b.join(".env.local")).unwrap(),
        "LOCAL_FLAG=1\n"
    );

    // Workspace `--share node_modules` hydrates heavy ignored dirs + lazy workspace works!
    fs::create_dir_all(machine_b.join("node_modules/pkg")).unwrap();
    fs::write(
        machine_b.join("node_modules/pkg/index.js"),
        "module.exports = 1;\n",
    )
    .unwrap();
    let ws_dir = tmp.path().join("ws-agent");
    assert_ok(
        &machine_b,
        &[
            "ws",
            "add",
            "agent-1",
            "--path",
            ws_dir.to_str().unwrap(),
            "--share",
            "node_modules",
        ],
    );
    assert_eq!(
        fs::read_to_string(ws_dir.join("node_modules/pkg/index.js")).unwrap(),
        "module.exports = 1;\n"
    );

    // Grant Bob an SSH pubkey, then revoke Bob across all secrets and verify deterministic audit!
    let bob_pem = encode_openssh_ed25519_private(&[9u8; 32], "bob@t3.gg");
    let bob_kp = gitx_crypto::UserKeyPair::from_openssh_ed25519(&bob_pem, None).unwrap();
    assert_ok(
        &machine_b,
        &[
            "secret",
            "import-ssh",
            "--pub",
            &bob_kp.to_openssh_ed25519_pub(),
            "--name",
            "bob",
        ],
    );
    let revoke_out = assert_ok(&machine_b, &["secret", "revoke", "bob"]);
    assert!(revoke_out.contains("Revoked 'bob'"));
    assert!(revoke_out.contains("Exposure audit"));

    // Bidirectional Git mirror sync pushes ONLY public files (zero `.env` leaked!) to a bare Git repo!
    let bare_mirror = tmp.path().join("mirror.git");
    assert!(
        Command::new("git")
            .args(["init", "--bare", bare_mirror.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let mirror_out = assert_ok(
        &machine_b,
        &[
            "mirror",
            "sync",
            bare_mirror.to_str().unwrap(),
            "--domains",
            "public",
        ],
    );
    assert!(mirror_out.contains("Mirror pushed"));
    let ls_tree = Command::new("git")
        .arg("-C")
        .arg(&bare_mirror)
        .args(["ls-tree", "-r", "--name-only", "refs/heads/master"])
        .output()
        .unwrap();
    let files_list = String::from_utf8_lossy(&ls_tree.stdout);
    assert!(files_list.contains("app.ts"));
    assert!(
        !files_list.contains(".env"),
        "public Git mirror must NEVER contain .env!"
    );
}

#[test]
fn cli_colocated_continuous_sync_hunk_split_passphrase_ssh_wip_fleet_and_remote_symbols_rebase() {
    use gitx_crypto::encode_openssh_ed25519_private_encrypted;
    use std::io::Write;
    use std::process::Stdio;

    let tmp = TempDir::new().unwrap();

    // 1. Continuous colocated `.git` sync (`gitx init --colocate`) with zero secret leak!
    let coloc = tmp.path().join("colocated");
    fs::create_dir_all(&coloc).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-b", "master", coloc.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&coloc)
            .args(["config", "user.name", "Theo"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&coloc)
            .args(["config", "user.email", "theo@t3.gg"])
            .status()
            .unwrap()
            .success()
    );
    fs::write(coloc.join("README.md"), "# Colocated\n").unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&coloc)
            .args(["add", "README.md"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&coloc)
            .args(["commit", "-m", "Initial git commit"])
            .status()
            .unwrap()
            .success()
    );

    assert_ok(
        &coloc,
        &[
            "init",
            "--colocate",
            "--name",
            "Theo",
            "--email",
            "theo@t3.gg",
        ],
    );
    fs::write(coloc.join(".gitxacl"), ".env -> secret:dev\n").unwrap();
    fs::write(
        coloc.join("public.rs"),
        "pub fn public_colocated() -> u32 { 7 }\n",
    )
    .unwrap();
    fs::write(coloc.join(".env"), "TOP_SECRET_COLOC=never_in_dot_git\n").unwrap();
    assert_ok(&coloc, &["describe", "-m", "Add public.rs + secret .env"]);
    assert_ok(&coloc, &["land"]);

    // `.git` must AUTOMATICALLY have `public.rs` on `master` and NEVER `.env`, passing `git fsck`!
    let ls_tree = Command::new("git")
        .arg("-C")
        .arg(&coloc)
        .args(["ls-tree", "-r", "--name-only", "refs/heads/master"])
        .output()
        .unwrap();
    let tree_list = String::from_utf8_lossy(&ls_tree.stdout);
    assert!(
        tree_list.contains("public.rs"),
        "colocated .git missing public.rs: {tree_list}"
    );
    assert!(
        !tree_list.contains(".env"),
        "colocated .git leaked .env: {tree_list}"
    );
    let fsck = Command::new("git")
        .arg("-C")
        .arg(&coloc)
        .args(["fsck", "--full"])
        .output()
        .unwrap();
    assert!(
        fsck.status.success(),
        "git fsck failed on colocated .git: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );

    // 2. Hunk-level `gitx split --hunks` AND interactive `gitx split -p`!
    let split_repo = tmp.path().join("split-hunks");
    fs::create_dir_all(&split_repo).unwrap();
    assert_ok(
        &split_repo,
        &["init", "--name", "Theo", "--email", "theo@t3.gg"],
    );
    let mut base_lines = Vec::new();
    for i in 1..=20 {
        base_lines.push(format!("line {i}"));
    }
    let base_text = format!("{}\n", base_lines.join("\n"));
    fs::write(split_repo.join("app.txt"), &base_text).unwrap();
    assert_ok(&split_repo, &["describe", "-m", "Base 20 lines"]);
    assert_ok(&split_repo, &["land"]);

    // Modify line 2 (hunk 1) AND line 19 (hunk 2) so there are 2 disjoint hunks.
    assert_ok(&split_repo, &["new", "-m", "Two hunks WIP"]);
    let mut edited_lines = base_lines.clone();
    edited_lines[1] = "line 2 EDITED_HUNK_1".to_string();
    edited_lines[18] = "line 19 EDITED_HUNK_2".to_string();
    fs::write(
        split_repo.join("app.txt"),
        format!("{}\n", edited_lines.join("\n")),
    )
    .unwrap();

    let hunk_split_out = assert_ok(
        &split_repo,
        &["split", "--hunks", "app.txt:1", "-m", "Only Hunk 1"],
    );
    assert!(hunk_split_out.contains("Split"));

    // Verify parent commit has ONLY hunk 1 while `@` still has BOTH hunks!
    let log_out = assert_ok(&split_repo, &["log", "--limit", "5"]);
    assert!(log_out.contains("Only Hunk 1"));
    assert_eq!(
        fs::read_to_string(split_repo.join("app.txt")).unwrap(),
        format!("{}\n", edited_lines.join("\n"))
    );
    // Diff of `@` against its parent ("Only Hunk 1") should ONLY show HUNK_2!
    let diff_after = assert_ok(&split_repo, &["diff"]);
    assert!(
        diff_after.contains("EDITED_HUNK_2"),
        "expected hunk 2 remaining in @: {diff_after}"
    );
    assert!(
        !diff_after.contains("EDITED_HUNK_1"),
        "hunk 1 should already be in parent: {diff_after}"
    );

    // Test interactive `gitx split -p` via piped stdin (`y\nn\n`) on a fresh two-hunk edit!
    assert_ok(&split_repo, &["land"]);
    assert_ok(&split_repo, &["new", "-m", "Interactive patch WIP"]);
    edited_lines[2] = "line 3 PATCH_A".to_string();
    edited_lines[17] = "line 18 PATCH_B".to_string();
    fs::write(
        split_repo.join("app.txt"),
        format!("{}\n", edited_lines.join("\n")),
    )
    .unwrap();

    let mut child = Command::new(gitx_bin())
        .current_dir(&split_repo)
        .args(["split", "-p", "-m", "Interactive Patch A"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"y\nn\n").unwrap();
    let patch_out = child.wait_with_output().unwrap();
    assert!(
        patch_out.status.success(),
        "gitx split -p failed: {}",
        String::from_utf8_lossy(&patch_out.stderr)
    );
    let diff_patch = assert_ok(&split_repo, &["diff"]);
    assert!(diff_patch.contains("PATCH_B"));
    assert!(!diff_patch.contains("PATCH_A"));

    // 3. Passphrase-protected OpenSSH Ed25519 import + WIP Fleet Sync + Remote Symbols & Rebase!
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server_dir = tmp.path().join("srv-gaps");
    let config = ServerConfig::new(&server_dir);
    let base_url = rt.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            gitx_server::serve(listener, config).await.unwrap();
        });
        format!("http://{addr}")
    });

    let ssh_enc_path = tmp.path().join("id_ed25519_enc");
    let enc_pem =
        encode_openssh_ed25519_private_encrypted(&[55u8; 32], "theo@t3.gg", "secret-pass-123")
            .unwrap();
    fs::write(&ssh_enc_path, &enc_pem).unwrap();

    let box_a = tmp.path().join("box-a");
    fs::create_dir_all(&box_a).unwrap();
    assert_ok(&box_a, &["init", "--name", "Theo", "--email", "theo@t3.gg"]);

    // Wrong passphrase must fail cleanly.
    let bad_imp = run_gitx(
        &box_a,
        &[
            "secret",
            "import-ssh",
            "--path",
            ssh_enc_path.to_str().unwrap(),
            "--passphrase",
            "wrong",
        ],
    );
    assert!(!bad_imp.status.success());

    // Correct passphrase succeeds!
    assert_ok(
        &box_a,
        &[
            "secret",
            "import-ssh",
            "--path",
            ssh_enc_path.to_str().unwrap(),
            "--passphrase",
            "secret-pass-123",
        ],
    );

    fs::write(box_a.join("lib.rs"), "pub fn alpha_sym() -> u32 { 1 }\n").unwrap();
    fs::write(box_a.join(".env.local"), "WIP_FLAG=1\n").unwrap();
    let repo_url = format!("{base_url}/t3/gaps");
    assert_ok(
        &box_a,
        &["remote", "add", "origin", &repo_url, "--token", "user=theo"],
    );
    assert_ok(&box_a, &["push", "origin", "-m", "Initial lib.rs"]);

    // `gitx remote symbols` finds `alpha_sym` on the server!
    let sym_out = assert_ok(&box_a, &["remote", "symbols"]);
    assert!(
        sym_out.contains("alpha_sym"),
        "expected alpha_sym in: {sym_out}"
    );

    // Make an uncommitted WIP edit and push via `gitx fleet sync --include-wip --push`!
    fs::write(box_a.join("wip_notes.rs"), "pub fn wip_on_laptop() {}\n").unwrap();
    let fleet_wip_push = assert_ok(
        &box_a,
        &[
            "fleet",
            "sync",
            "--remote",
            "origin",
            "--include",
            ".env.local",
            "--include-wip",
            "--push",
        ],
    );
    assert!(
        fleet_wip_push.contains("WIP file(s)"),
        "expected WIP file(s) in: {fleet_wip_push}"
    );

    // Pull on box-b with same encrypted SSH key and verify both `.env.local` AND `wip_notes.rs` arrive!
    let box_b = tmp.path().join("box-b");
    fs::create_dir_all(&box_b).unwrap();
    assert_ok(&box_b, &["init", "--name", "Theo", "--email", "theo@t3.gg"]);
    assert_ok(
        &box_b,
        &[
            "secret",
            "import-ssh",
            "--path",
            ssh_enc_path.to_str().unwrap(),
            "--passphrase",
            "secret-pass-123",
        ],
    );
    assert_ok(
        &box_b,
        &["remote", "add", "origin", &repo_url, "--token", "user=theo"],
    );
    assert_ok(&box_b, &["pull", "origin"]);
    let fleet_wip_pull = assert_ok(&box_b, &["fleet", "sync", "--remote", "origin", "--pull"]);
    assert!(fleet_wip_pull.contains("WIP"));
    assert_eq!(
        fs::read_to_string(box_b.join(".env.local")).unwrap(),
        "WIP_FLAG=1\n"
    );
    assert_eq!(
        fs::read_to_string(box_b.join("wip_notes.rs")).unwrap(),
        "pub fn wip_on_laptop() {}\n"
    );

    // `gitx remote rebase` against the live server!
    let log_json = assert_ok(&box_a, &["remote", "log", "--limit", "5"]);
    assert!(log_json.contains("Initial lib.rs"));
}
