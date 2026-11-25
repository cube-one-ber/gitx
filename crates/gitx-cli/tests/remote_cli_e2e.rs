use gitx_server::{ServerConfig, serve};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn gitx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_gitx")
}

fn run_gitx(dir: &Path, args: &[&str]) -> Output {
    Command::new(gitx_bin())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run gitx {args:?}: {e}"))
}

fn gitx_ok(dir: &Path, args: &[&str]) -> String {
    let out = run_gitx(dir, args);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "gitx {:?} failed (status={:?})\nstdout:\n{}\nstderr:\n{}",
        args,
        out.status,
        stdout,
        stderr
    );
    stdout
}

fn extract_field<'a>(output: &'a str, prefix: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix).map(str::trim))
        .unwrap_or_else(|| panic!("expected field '{prefix}' in output:\n{output}"))
}

struct LiveServer {
    addr: SocketAddr,
    _data_dir: TempDir,
    shutdown_tx: Option<oneshot::Sender<()>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl LiveServer {
    fn start(default_acl: Option<&str>) -> Self {
        let data_dir = TempDir::new().expect("server data temp dir");
        let mut config = ServerConfig::new(data_dir.path());
        if let Some(acl) = default_acl {
            config = config.with_default_acl(acl);
        }

        let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let thread_handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("build server tokio runtime");

            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind 127.0.0.1:0");
                let addr = listener.local_addr().expect("local addr");
                let _ = addr_tx.send(addr);

                tokio::select! {
                    _ = serve(listener, config) => {}
                    _ = shutdown_rx => {}
                }
            });
        });

        let addr = addr_rx.recv().expect("receive bound server addr");
        Self {
            addr,
            _data_dir: data_dir,
            shutdown_tx: Some(shutdown_tx),
            thread_handle: Some(thread_handle),
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn repo_url(&self, owner: &str, repo: &str) -> String {
        format!("http://{}/{owner}/{repo}", self.addr)
    }
}

impl Drop for LiveServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn e2e_remote_config_add_list_show_rm() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    gitx_ok(
        root,
        &["init", "--name", "Alice", "--email", "alice@acme.dev"],
    );

    // Empty list initially
    let empty_list = gitx_ok(root, &["remote", "list"]);
    assert!(
        empty_list.contains("No remotes configured"),
        "got:\n{empty_list}"
    );

    // Auto-parse owner & repo from URL
    let add1 = gitx_ok(
        root,
        &[
            "remote",
            "add",
            "origin",
            "http://127.0.0.1:7878/acme/demo",
            "--token",
            "user=alice;teams=core",
        ],
    );
    assert!(add1.contains("Added remote 'origin'"), "got:\n{add1}");
    assert!(
        add1.contains("http://127.0.0.1:7878/acme/demo"),
        "got:\n{add1}"
    );
    assert!(root.join(".gitx/remotes.toml").is_file());

    // Explicit --owner and --repo flags
    let add2 = gitx_ok(
        root,
        &[
            "remote",
            "add",
            "upstream",
            "http://127.0.0.1:7878",
            "--owner",
            "org",
            "--repo",
            "upstream-repo",
        ],
    );
    assert!(
        add2.contains("http://127.0.0.1:7878/org/upstream-repo"),
        "got:\n{add2}"
    );

    // Duplicate remote add must fail cleanly
    let dup = run_gitx(
        root,
        &[
            "remote",
            "add",
            "origin",
            "http://127.0.0.1:7878/acme/other",
        ],
    );
    assert!(!dup.status.success());

    // List both remotes
    let list_out = gitx_ok(root, &["remote", "list"]);
    assert!(
        list_out.contains("origin\thttp://127.0.0.1:7878/acme/demo"),
        "got:\n{list_out}"
    );
    assert!(list_out.contains("[token]"), "got:\n{list_out}");
    assert!(
        list_out.contains("upstream\thttp://127.0.0.1:7878/org/upstream-repo"),
        "got:\n{list_out}"
    );

    // Show details for origin
    let show_out = gitx_ok(root, &["remote", "show", "origin"]);
    assert!(show_out.contains("Remote: origin"), "got:\n{show_out}");
    assert!(show_out.contains("Owner:  acme"), "got:\n{show_out}");
    assert!(show_out.contains("Repo:   demo"), "got:\n{show_out}");
    assert!(show_out.contains("user=alice"), "got:\n{show_out}");
    assert!(show_out.contains("teams=core"), "got:\n{show_out}");

    // Remove upstream and confirm it's gone
    let rm_out = gitx_ok(root, &["remote", "rm", "upstream"]);
    assert!(
        rm_out.contains("Removed remote 'upstream'"),
        "got:\n{rm_out}"
    );

    let list_after = gitx_ok(root, &["remote", "list"]);
    assert!(list_after.contains("origin"));
    assert!(!list_after.contains("upstream"));

    let show_missing = run_gitx(root, &["remote", "show", "upstream"]);
    assert!(!show_missing.status.success());
}

#[test]
fn e2e_push_to_create_and_pull_roundtrip_with_history_and_deletions() {
    let srv = LiveServer::start(None);
    let repo_a = TempDir::new().unwrap();
    let repo_b = TempDir::new().unwrap();

    // Initialize Repo A and configure remote (repo does NOT exist on server yet -> push-to-create)
    gitx_ok(
        repo_a.path(),
        &["init", "--name", "Alice", "--email", "alice@acme.dev"],
    );
    let url = srv.repo_url("acme", "alpha");
    gitx_ok(
        repo_a.path(),
        &["remote", "add", "origin", &url, "--token", "alice"],
    );

    // Commit 1: push-to-create
    fs::create_dir_all(repo_a.path().join("src")).unwrap();
    fs::create_dir_all(repo_a.path().join("docs")).unwrap();
    fs::write(
        repo_a.path().join("src/lib.rs"),
        "pub fn greet() -> &'static str {\n    \"hello\"\n}\n",
    )
    .unwrap();
    fs::write(repo_a.path().join("docs/guide.md"), "# Guide v1\n").unwrap();
    gitx_ok(repo_a.path(), &["describe", "-m", "Initial public library"]);

    let push1 = gitx_ok(repo_a.path(), &["push"]);
    assert!(
        push1.contains("Pushed to 'origin' (acme/alpha -> master)"),
        "got:\n{push1}"
    );
    let c1_id = extract_field(&push1, "changeset:").to_string();
    assert!(!c1_id.is_empty());

    // Pushing again with no changes reports up-to-date
    let noop_push = gitx_ok(repo_a.path(), &["push"]);
    assert!(
        noop_push.contains("Already up to date"),
        "got:\n{noop_push}"
    );

    // Verify `remote show` recorded the remote head
    let show_out = gitx_ok(repo_a.path(), &["remote", "show", "origin"]);
    assert!(show_out.contains(&c1_id[..12]), "got:\n{show_out}");

    // Commit 2: modify src/lib.rs, delete docs/guide.md, add src/extra.rs
    fs::write(
        repo_a.path().join("src/lib.rs"),
        "pub fn greet() -> &'static str {\n    \"hello\"\n}\n\npub fn farewell() -> &'static str {\n    \"bye\"\n}\n",
    )
    .unwrap();
    fs::remove_file(repo_a.path().join("docs/guide.md")).unwrap();
    fs::write(
        repo_a.path().join("src/extra.rs"),
        "pub const VERSION: u32 = 2;\n",
    )
    .unwrap();

    let push2 = gitx_ok(
        repo_a.path(),
        &[
            "push",
            "origin",
            "--target",
            "master",
            "-m",
            "Add farewell and drop old guide",
        ],
    );
    assert!(
        push2.contains("-1 deleted"),
        "expected deletion count in:\n{push2}"
    );

    // Initialize fresh Repo B and pull from the server
    gitx_ok(
        repo_b.path(),
        &["init", "--name", "Bob", "--email", "bob@acme.dev"],
    );
    gitx_ok(repo_b.path(), &["remote", "add", "origin", &url]);

    let pull_out = gitx_ok(repo_b.path(), &["pull"]);
    assert!(
        pull_out.contains("Pulled from 'origin' (acme/alpha @ master)"),
        "got:\n{pull_out}"
    );
    assert!(pull_out.contains("2 imported"), "got:\n{pull_out}");

    // Verify file contents and deletion materialized in Repo B
    let pulled_lib = fs::read_to_string(repo_b.path().join("src/lib.rs")).unwrap();
    assert!(pulled_lib.contains("pub fn greet()"), "got:\n{pulled_lib}");
    assert!(
        pulled_lib.contains("pub fn farewell()"),
        "got:\n{pulled_lib}"
    );
    assert_eq!(
        fs::read_to_string(repo_b.path().join("src/extra.rs")).unwrap(),
        "pub const VERSION: u32 = 2;\n"
    );
    assert!(
        !repo_b.path().join("docs/guide.md").exists(),
        "deleted file docs/guide.md must not exist in Repo B"
    );

    // Verify full commit history was stored in Repo B's LocalStore
    let log_b = gitx_ok(repo_b.path(), &["log"]);
    assert!(
        log_b.contains("Initial public library"),
        "expected commit 1 message in Repo B log:\n{log_b}"
    );
    assert!(
        log_b.contains("Add farewell and drop old guide"),
        "expected commit 2 message in Repo B log:\n{log_b}"
    );

    // Verify working copy in Repo B is clean after pull
    let status_b = gitx_ok(repo_b.path(), &["status"]);
    assert!(status_b.contains("(no changes)"), "got:\n{status_b}");
}

#[test]
fn e2e_zero_clone_remote_rpc_grep_diff_blame_log_stats() {
    let srv = LiveServer::start(None);
    let repo_a = TempDir::new().unwrap();
    let scratch_no_repo = TempDir::new().unwrap();
    let url = srv.repo_url("acme", "rpc-demo");

    // Push two commits from Repo A
    gitx_ok(
        repo_a.path(),
        &["init", "--name", "Alice", "--email", "alice@acme.dev"],
    );
    gitx_ok(
        repo_a.path(),
        &["remote", "add", "origin", &url, "--token", "alice"],
    );
    fs::create_dir_all(repo_a.path().join("src")).unwrap();
    fs::write(
        repo_a.path().join("src/lib.rs"),
        "pub fn alpha() -> &'static str {\n    \"alpha_marker\"\n}\n",
    )
    .unwrap();
    let push1 = gitx_ok(repo_a.path(), &["push", "-m", "Add alpha function"]);
    let c1 = extract_field(&push1, "changeset:").to_string();

    fs::write(
        repo_a.path().join("src/lib.rs"),
        "pub fn alpha() -> &'static str {\n    \"alpha_marker\"\n}\n\npub fn beta() -> &'static str {\n    \"beta_marker\"\n}\n",
    )
    .unwrap();
    let push2 = gitx_ok(repo_a.path(), &["push", "-m", "Add beta function"]);
    let c2 = extract_field(&push2, "changeset:").to_string();

    // Run ALL zero-clone remote RPC commands from an EMPTY directory with NO `.gitx`!
    assert!(!scratch_no_repo.path().join(".gitx").exists());

    let log_out = gitx_ok(scratch_no_repo.path(), &["remote", "log", "--url", &url]);
    assert!(log_out.contains("Add beta function"), "got:\n{log_out}");
    assert!(log_out.contains("Add alpha function"), "got:\n{log_out}");

    let grep_out = gitx_ok(
        scratch_no_repo.path(),
        &["remote", "grep", "beta_marker", "--url", &url],
    );
    assert!(
        grep_out.contains("[public] src/lib.rs:6:"),
        "expected grep match on line 6, got:\n{grep_out}"
    );

    let diff_out = gitx_ok(
        scratch_no_repo.path(),
        &["remote", "diff", &c1, &c2, "--url", &url],
    );
    assert!(diff_out.contains("+pub fn beta()"), "got:\n{diff_out}");
    assert!(
        diff_out.contains("+\"beta_marker\"".trim_start_matches('+'))
            || diff_out.contains("beta_marker"),
        "got:\n{diff_out}"
    );

    let blame_out = gitx_ok(
        scratch_no_repo.path(),
        &["remote", "blame", "src/lib.rs", "--url", &url, "--rev", &c2],
    );
    assert!(
        blame_out.contains(&c1[..12]),
        "expected c1 attribution in blame:\n{blame_out}"
    );
    assert!(
        blame_out.contains(&c2[..12]),
        "expected c2 attribution in blame:\n{blame_out}"
    );
    assert!(blame_out.contains("pub fn alpha()"), "got:\n{blame_out}");
    assert!(blame_out.contains("pub fn beta()"), "got:\n{blame_out}");

    // Query /derived/stats — trigram & path_history should reflect cached indices from grep & blame
    let stats_out = gitx_ok(scratch_no_repo.path(), &["remote", "stats", "--url", &url]);
    assert!(
        stats_out.contains("Derived data stats for acme/rpc-demo"),
        "got:\n{stats_out}"
    );
    assert!(stats_out.contains("trigram:"), "got:\n{stats_out}");
    assert!(
        stats_out.contains("trees=1"),
        "expected trigram indexed tree in:\n{stats_out}"
    );
    assert!(stats_out.contains("path_history:"), "got:\n{stats_out}");
    assert!(
        stats_out.contains("entries=1"),
        "expected path_history entry in:\n{stats_out}"
    );

    // Confirm zero local .gitx directory was created in scratch_no_repo
    assert!(!scratch_no_repo.path().join(".gitx").exists());

    // Also verify configured-remote form inside Repo A (without --url)
    let repo_grep = gitx_ok(
        repo_a.path(),
        &["remote", "grep", "alpha_marker", "--remote", "origin"],
    );
    assert!(repo_grep.contains("src/lib.rs:2:"), "got:\n{repo_grep}");
}

#[test]
fn e2e_remote_merge_queue_enqueue_list_drain() {
    let srv = LiveServer::start(None);
    let url = srv.repo_url("acme", "swarm");

    let seed = TempDir::new().unwrap();
    let agent1 = TempDir::new().unwrap();
    let agent2 = TempDir::new().unwrap();
    let verifier = TempDir::new().unwrap();

    // 1. Seed initial commit on server
    gitx_ok(
        seed.path(),
        &["init", "--name", "Seed", "--email", "seed@acme.dev"],
    );
    gitx_ok(
        seed.path(),
        &[
            "remote",
            "add",
            "origin",
            &srv.base_url(),
            "--owner",
            "acme",
            "--repo",
            "swarm",
            "--token",
            "seed",
        ],
    );
    fs::create_dir_all(seed.path().join("src")).unwrap();
    let base_lib = "pub fn base_fn() -> i32 {\n    1\n}\n";
    fs::write(seed.path().join("src/lib.rs"), base_lib).unwrap();
    gitx_ok(seed.path(), &["push", "-m", "Seed base_fn"]);

    // 2. Both Agent 1 and Agent 2 pull the exact same base commit
    for (dir, name) in [(agent1.path(), "Agent1"), (agent2.path(), "Agent2")] {
        gitx_ok(dir, &["init", "--name", name, "--email", "agent@acme.dev"]);
        gitx_ok(dir, &["remote", "add", "origin", &url]);
        gitx_ok(dir, &["pull"]);
    }

    // 3. Agent 1 adds agents/alpha.rs and appends alpha_fn() to src/lib.rs, then enqueues
    fs::create_dir_all(agent1.path().join("agents")).unwrap();
    fs::write(
        agent1.path().join("agents/alpha.rs"),
        "pub fn alpha_only() -> i32 { 10 }\n",
    )
    .unwrap();
    fs::write(
        agent1.path().join("src/lib.rs"),
        format!("{base_lib}\npub fn alpha_fn() -> i32 {{\n    10\n}}\n"),
    )
    .unwrap();
    let enq1 = gitx_ok(
        agent1.path(),
        &[
            "queue",
            "enqueue",
            "--remote",
            "origin",
            "--target",
            "master",
            "-m",
            "Agent 1 alpha feature",
            "--token",
            "agent-1",
        ],
    );
    assert!(enq1.contains("queue_depth:  1"), "got:\n{enq1}");

    // 4. Agent 2 adds agents/beta.rs and appends beta_fn() to src/lib.rs, then enqueues
    fs::create_dir_all(agent2.path().join("agents")).unwrap();
    fs::write(
        agent2.path().join("agents/beta.rs"),
        "pub fn beta_only() -> i32 { 20 }\n",
    )
    .unwrap();
    fs::write(
        agent2.path().join("src/lib.rs"),
        format!("{base_lib}\npub fn beta_fn() -> i32 {{\n    20\n}}\n"),
    )
    .unwrap();
    let enq2 = gitx_ok(
        agent2.path(),
        &[
            "queue",
            "enqueue",
            "--remote",
            "origin",
            "--target",
            "master",
            "-m",
            "Agent 2 beta feature",
            "--token",
            "agent-2",
        ],
    );
    assert!(enq2.contains("queue_depth:  2"), "got:\n{enq2}");

    // 5. Inspect queue list before draining
    let list_before = gitx_ok(
        agent1.path(),
        &[
            "queue",
            "list",
            "--remote",
            "origin",
            "--token",
            "merge-bot",
        ],
    );
    assert!(list_before.contains("pending: 2"), "got:\n{list_before}");
    assert!(list_before.contains("agent-1"), "got:\n{list_before}");
    assert!(list_before.contains("agent-2"), "got:\n{list_before}");

    // 6. Drain the batched merge queue atomically
    let drain_out = gitx_ok(
        agent1.path(),
        &[
            "queue",
            "drain",
            "--remote",
            "origin",
            "--target",
            "master",
            "--token",
            "merge-bot",
        ],
    );
    assert!(drain_out.contains("land_seq:   1"), "got:\n{drain_out}");
    assert!(drain_out.contains("landed:     2"), "got:\n{drain_out}");
    assert!(drain_out.contains("conflicted: 0"), "got:\n{drain_out}");
    assert!(drain_out.contains("rejected:   0"), "got:\n{drain_out}");

    // 7. Queue list after drain shows 0 pending and landed(seq=1)
    let list_after = gitx_ok(
        agent1.path(),
        &[
            "queue",
            "list",
            "--remote",
            "origin",
            "--token",
            "merge-bot",
        ],
    );
    assert!(list_after.contains("pending: 0"), "got:\n{list_after}");
    assert!(list_after.contains("landed(seq=1)"), "got:\n{list_after}");

    // 8. Pull into Verifier repo and confirm BOTH agents' files AND semantic AST merge landed cleanly!
    gitx_ok(
        verifier.path(),
        &["init", "--name", "Verifier", "--email", "v@acme.dev"],
    );
    gitx_ok(verifier.path(), &["remote", "add", "origin", &url]);
    gitx_ok(verifier.path(), &["pull"]);

    assert!(verifier.path().join("agents/alpha.rs").is_file());
    assert!(verifier.path().join("agents/beta.rs").is_file());
    let merged_lib = fs::read_to_string(verifier.path().join("src/lib.rs")).unwrap();
    assert!(
        !merged_lib.contains("<<<<<<<"),
        "unexpected conflict markers:\n{merged_lib}"
    );
    assert!(
        merged_lib.contains("pub fn base_fn()"),
        "got:\n{merged_lib}"
    );
    assert!(
        merged_lib.contains("pub fn alpha_fn()"),
        "got:\n{merged_lib}"
    );
    assert!(
        merged_lib.contains("pub fn beta_fn()"),
        "got:\n{merged_lib}"
    );
}

#[test]
fn e2e_token_acl_domain_isolation() {
    let acl = "packages/private/** -> team:core\n";
    let srv = LiveServer::start(Some(acl));
    let url = srv.repo_url("t3", "monorepo");

    let repo_core = TempDir::new().unwrap();
    let repo_outsider = TempDir::new().unwrap();
    let repo_authorized = TempDir::new().unwrap();

    // 1. Core engineer pushes public file + private team:core file with authorized token
    gitx_ok(
        repo_core.path(),
        &["init", "--name", "Theo", "--email", "theo@t3.gg"],
    );
    gitx_ok(
        repo_core.path(),
        &[
            "remote",
            "add",
            "origin",
            &url,
            "--token",
            "user=theo;teams=core,security",
        ],
    );
    fs::write(repo_core.path().join(".gitxacl"), acl).unwrap();
    fs::create_dir_all(repo_core.path().join("src")).unwrap();
    fs::write(
        repo_core.path().join("src/public.rs"),
        "pub const GREETING: &str = \"PUBLIC_HELLO_WORLD\";\n",
    )
    .unwrap();
    gitx_ok(repo_core.path(), &["push", "-m", "Add public greeting"]);

    fs::create_dir_all(repo_core.path().join("packages/private")).unwrap();
    fs::write(
        repo_core.path().join("packages/private/vault.rs"),
        "pub const SECRET_ALGO: &str = \"CORE_SECRET_FORMULA_999\";\n",
    )
    .unwrap();
    let priv_push = gitx_ok(
        repo_core.path(),
        &["push", "-m", "Add private core algorithm"],
    );
    assert!(
        priv_push.contains("team:core"),
        "expected team:core domain in:\n{priv_push}"
    );

    // 2. Unauthorized user pulls -> ONLY sees public file, ZERO private file or private commit history!
    gitx_ok(
        repo_outsider.path(),
        &["init", "--name", "Eve", "--email", "eve@external.dev"],
    );
    gitx_ok(
        repo_outsider.path(),
        &["remote", "add", "origin", &url, "--token", "user=eve"],
    );
    gitx_ok(repo_outsider.path(), &["pull"]);

    assert!(repo_outsider.path().join("src/public.rs").is_file());
    assert!(
        !repo_outsider
            .path()
            .join("packages/private/vault.rs")
            .exists(),
        "unauthorized token must NOT pull team:core private file!"
    );
    let outsider_log = gitx_ok(repo_outsider.path(), &["log"]);
    assert!(
        outsider_log.contains("Add public greeting"),
        "got:\n{outsider_log}"
    );
    assert!(
        !outsider_log.contains("Add private core algorithm"),
        "unauthorized token must NOT receive private commit message:\n{outsider_log}"
    );

    // 3. Unauthorized user cannot grep or blame private content (neither with outsider token nor anonymous)
    let unauth_grep = gitx_ok(
        repo_outsider.path(),
        &[
            "remote",
            "grep",
            "CORE_SECRET_FORMULA_999",
            "--remote",
            "origin",
        ],
    );
    assert!(
        unauth_grep.contains("(no matches"),
        "unauthorized grep leaked private content:\n{unauth_grep}"
    );

    let anon_grep = gitx_ok(
        repo_outsider.path(),
        &["remote", "grep", "CORE_SECRET_FORMULA_999", "--url", &url],
    );
    assert!(
        anon_grep.contains("(no matches"),
        "anonymous grep leaked private content:\n{anon_grep}"
    );

    let unauth_blame = run_gitx(
        repo_outsider.path(),
        &[
            "remote",
            "blame",
            "packages/private/vault.rs",
            "--remote",
            "origin",
        ],
    );
    assert!(
        !unauth_blame.status.success(),
        "unauthorized blame on private file must fail"
    );

    // 4. Unauthorized push to team:core path must be rejected (HTTP 403)
    fs::create_dir_all(repo_outsider.path().join("packages/private")).unwrap();
    fs::write(
        repo_outsider.path().join("packages/private/intrusion.rs"),
        "pub fn hijack() {}\n",
    )
    .unwrap();
    let unauth_push = run_gitx(repo_outsider.path(), &["push", "-m", "Unauthorized write"]);
    assert!(
        !unauth_push.status.success(),
        "unauthorized push to team:core must fail"
    );
    let unauth_stderr = String::from_utf8_lossy(&unauth_push.stderr);
    assert!(
        unauth_stderr.contains("403") || unauth_stderr.contains("forbidden"),
        "expected 403 forbidden error, got:\n{unauth_stderr}"
    );

    // 5. Authorized core team member pulls AND greps private content cleanly!
    gitx_ok(
        repo_authorized.path(),
        &["init", "--name", "CoreDev", "--email", "core@t3.gg"],
    );
    gitx_ok(
        repo_authorized.path(),
        &[
            "remote",
            "add",
            "origin",
            &url,
            "--token",
            "user=core-dev;teams=core",
        ],
    );
    gitx_ok(repo_authorized.path(), &["pull"]);

    assert!(repo_authorized.path().join("src/public.rs").is_file());
    let private_content =
        fs::read_to_string(repo_authorized.path().join("packages/private/vault.rs")).unwrap();
    assert!(
        private_content.contains("CORE_SECRET_FORMULA_999"),
        "got:\n{private_content}"
    );
    let auth_log = gitx_ok(repo_authorized.path(), &["log"]);
    assert!(
        auth_log.contains("Add private core algorithm"),
        "got:\n{auth_log}"
    );

    let auth_grep = gitx_ok(
        repo_authorized.path(),
        &[
            "remote",
            "grep",
            "CORE_SECRET_FORMULA_999",
            "--remote",
            "origin",
        ],
    );
    assert!(
        auth_grep.contains("[team:core] packages/private/vault.rs:1:"),
        "expected authorized grep match, got:\n{auth_grep}"
    );
}
