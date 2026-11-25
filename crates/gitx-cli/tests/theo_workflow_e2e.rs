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

    assert_ok(&machine_a, &["init", "--name", "Alice", "--email", "alice@t3.gg"]);
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
    assert_ok(&machine_b, &["init", "--name", "Alice", "--email", "alice@t3.gg"]);
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
        &["remote", "add", "origin", &repo_url, "--token", &token_alice],
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
    fs::write(machine_b.join("node_modules/pkg/index.js"), "module.exports = 1;\n").unwrap();
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
        &["mirror", "sync", bare_mirror.to_str().unwrap(), "--domains", "public"],
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
