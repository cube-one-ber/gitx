use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

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

fn run_git_ok(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run git {args:?}: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "git {:?} failed (status={:?})\nstdout:\n{}\nstderr:\n{}",
        args,
        out.status,
        stdout,
        stderr
    );
    stdout
}

#[test]
fn e2e_full_local_workflow() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    // 1. init
    let init_out = gitx_ok(
        root,
        &["init", "--name", "Alice", "--email", "alice@example.com"],
    );
    assert!(init_out.contains("Initialized gitx repository"));
    assert!(root.join(".gitx/store").is_dir());
    assert!(root.join(".gitx/pool").is_dir());
    assert!(root.join(".gitx/keys/local.json").is_file());
    assert!(root.join(".gitx/config.json").is_file());
    assert!(root.join(".gitx/context.db").is_file());
    assert!(root.join(".gitxacl").is_file());

    // 2. edit file + status
    fs::write(root.join("hello.txt"), "hello v1\nline two\n").unwrap();
    let status_out = gitx_ok(root, &["status"]);
    assert!(status_out.contains("hello.txt"));
    assert!(status_out.contains("A [public] hello.txt"));

    // 3. describe
    let desc_out = gitx_ok(root, &["describe", "-m", "Add greeting file"]);
    assert!(desc_out.contains("Add greeting file"));

    // 4. amend working copy & inspect interdiff (v1 -> v2)
    fs::write(root.join("hello.txt"), "hello v2\nline two\n").unwrap();
    let interdiff_out = gitx_ok(root, &["diff", "--interdiff"]);
    assert!(
        interdiff_out.contains("-hello v1") && interdiff_out.contains("+hello v2"),
        "expected v1->v2 interdiff, got:\n{interdiff_out}"
    );

    // 5. new child ChangeSet on top with agent metadata
    let new_out = gitx_ok(
        root,
        &["new", "-m", "Add second file", "--agent", "claude:sonnet"],
    );
    assert!(new_out.contains("Working copy now at"));
    fs::write(root.join("second.txt"), "second content\n").unwrap();

    // 6. land onto master
    let land_out = gitx_ok(root, &["land"]);
    assert!(land_out.contains("land_seq: 1"), "got:\n{land_out}");

    // 7. log shows our history and agent committer
    let log_out = gitx_ok(root, &["log", "--limit", "10"]);
    assert!(log_out.contains("Add second file"), "log:\n{log_out}");
    assert!(log_out.contains("Add greeting file"), "log:\n{log_out}");
    assert!(log_out.contains("agent=claude:sonnet"), "log:\n{log_out}");
    assert!(log_out.contains("[master]"), "log:\n{log_out}");

    // 8. op log records operations
    let oplog_out = gitx_ok(root, &["op", "log", "--limit", "10"]);
    assert!(oplog_out.contains("Land"), "oplog:\n{oplog_out}");

    // 9. revert land_seq 1 -> restores initial state (removes hello.txt and second.txt)
    let revert_out = gitx_ok(root, &["revert", "1"]);
    assert!(revert_out.contains("Reverted land_seq 1"), "got:\n{revert_out}");
    assert!(
        !root.join("hello.txt").exists(),
        "hello.txt should be removed after revert"
    );
    assert!(
        !root.join("second.txt").exists(),
        "second.txt should be removed after revert"
    );

    // 10. undo restores the landed state cleanly
    let undo_out = gitx_ok(root, &["undo"]);
    assert!(undo_out.contains("Undid"), "got:\n{undo_out}");
    assert_eq!(
        fs::read_to_string(root.join("hello.txt")).unwrap(),
        "hello v2\nline two\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("second.txt")).unwrap(),
        "second content\n"
    );
}

#[test]
fn e2e_lock_free_multi_workspace() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    gitx_ok(root, &["init", "--name", "Bob", "--email", "bob@example.com"]);
    fs::write(root.join("README.md"), "# GitX Multi-Workspace\n").unwrap();
    gitx_ok(root, &["describe", "-m", "Add README"]);
    gitx_ok(root, &["land"]);

    let ws1_dir = dir.path().join("ws-agent-1");
    let ws2_dir = dir.path().join("ws-agent-2");

    // Simultaneously create two CoW workspaces + one in-memory workspace off `master` with zero branch locks!
    let add1 = gitx_ok(
        root,
        &["ws", "add", "agent-1", "--path", ws1_dir.to_str().unwrap()],
    );
    assert!(add1.contains("agent-1"));
    assert_eq!(
        fs::read_to_string(ws1_dir.join("README.md")).unwrap(),
        "# GitX Multi-Workspace\n"
    );

    let add2 = gitx_ok(
        root,
        &["ws", "add", "agent-2", "--path", ws2_dir.to_str().unwrap()],
    );
    assert!(add2.contains("agent-2"));
    assert_eq!(
        fs::read_to_string(ws2_dir.join("README.md")).unwrap(),
        "# GitX Multi-Workspace\n"
    );

    let add_mem = gitx_ok(root, &["ws", "add", "agent-mem", "--mem"]);
    assert!(add_mem.contains("Memory"));

    let list_out = gitx_ok(root, &["ws", "list"]);
    assert!(list_out.contains("default"));
    assert!(list_out.contains("agent-1"));
    assert!(list_out.contains("agent-2"));
    assert!(list_out.contains("agent-mem"));

    // Editing in agent-1 does not affect agent-2 or default
    fs::write(ws1_dir.join("README.md"), "# Agent 1 Edit\n").unwrap();
    assert_eq!(
        fs::read_to_string(ws2_dir.join("README.md")).unwrap(),
        "# GitX Multi-Workspace\n"
    );

    let rm_out = gitx_ok(root, &["ws", "rm", "agent-mem"]);
    assert!(rm_out.contains("Removed workspace 'agent-mem'"));
}

#[test]
fn e2e_native_secrets_and_acl_git_export() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    gitx_ok(root, &["init", "--name", "Sec", "--email", "sec@example.com"]);

    fs::write(root.join("app.rs"), "pub fn main() { println!(\"ok\"); }\n").unwrap();
    let secret_payload = "DATABASE_URL=postgres://user:supersecret@db:5432/prod\nAPI_KEY=sk-live-secret-999999999\n";
    fs::write(root.join(".env"), secret_payload).unwrap();

    // Encrypt native secret into secret:dev
    let set_out = gitx_ok(root, &["secret", "set", ".env", "--domain", "secret:dev"]);
    assert!(set_out.contains("Stored encrypted secret '.env'"));

    // Decrypt back verbatim
    let get_out = gitx_ok(root, &["secret", "get", ".env", "--domain", "secret:dev"]);
    assert_eq!(get_out, secret_payload);

    // Keygen + grant + rotate (dropping peer key)
    let peer_pub = gitx_ok(root, &["secret", "keygen", "ci-runner"]);
    let grant_out = gitx_ok(root, &["secret", "grant", "ci-runner", peer_pub.trim()]);
    assert!(grant_out.contains("Granted secret recipient 'ci-runner'"));

    let rot_out = gitx_ok(
        root,
        &[
            "secret",
            "rotate",
            ".env",
            "--domain",
            "secret:dev",
            "--drop",
            "ci-runner",
        ],
    );
    assert!(rot_out.contains("epoch 2"), "got:\n{rot_out}");
    assert_eq!(
        gitx_ok(root, &["secret", "get", ".env", "--domain", "secret:dev"]),
        secret_payload
    );

    // Land public + secret changesets
    gitx_ok(root, &["describe", "-m", "Add app and native env secret"]);
    gitx_ok(root, &["land"]);

    // Export ONLY `public` domain to a Git repository
    let export_dir = TempDir::new().unwrap();
    let export_out = gitx_ok(
        root,
        &[
            "git-export",
            export_dir.path().to_str().unwrap(),
            "--domains",
            "public",
        ],
    );
    assert!(export_out.contains("Exported Git repository"));

    // Verify with real `git fsck --full --strict`
    run_git_ok(export_dir.path(), &["fsck", "--full", "--strict"]);

    // Verify `app.rs` is exported and ZERO `.env` file leaked!
    let tree_files = run_git_ok(export_dir.path(), &["ls-tree", "-r", "--name-only", "HEAD"]);
    assert!(tree_files.contains("app.rs"), "tree:\n{tree_files}");
    assert!(
        !tree_files.lines().any(|l| l == ".env"),
        ".env leaked into public Git export! tree:\n{tree_files}"
    );
}

#[test]
fn e2e_durable_context_relocation_and_checkpoint_undo() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    gitx_ok(root, &["init", "--name", "Dev", "--email", "dev@example.com"]);

    let initial_code = "\
fn alpha() {
    let a = 1;
    let b = 2;
    println!(\"{}\", a + b);
}

fn beta() {
    let x = 10;
    let y = 20;
    println!(\"{}\", x + y);
}
";
    fs::write(root.join("lib.rs"), initial_code).unwrap();
    gitx_ok(root, &["describe", "-m", "Initial lib.rs"]);
    gitx_ok(root, &["land"]);

    // Add durable context anchored to `beta()` (lines 7-11)
    let ctx_out = gitx_ok(
        root,
        &[
            "context",
            "add",
            "--prompt",
            "Keep beta pure for zero-allocation math",
            "--path",
            "lib.rs",
            "--lines",
            "7-11",
            "--model",
            "gemini-2.5",
            "--harness",
            "antigravity",
            "--visibility",
            "team:core",
        ],
    );
    assert!(ctx_out.contains("Added context"));

    // Shift file lines down by inserting 5 header comment lines at top of `lib.rs`
    let shifted_code = format!(
        "// header 1\n// header 2\n// header 3\n// header 4\n// header 5\n{initial_code}"
    );
    fs::write(root.join("lib.rs"), &shifted_code).unwrap();

    // `why` with only `public` must NOT leak `team:core` record
    let why_pub = gitx_ok(root, &["why", "lib.rs:14", "--domains", "public"]);
    assert!(why_pub.contains("No context records found"), "got:\n{why_pub}");

    // `why` with `public,team:core` relocates anchor cleanly to shifted line 14!
    let why_team = gitx_ok(root, &["why", "lib.rs:14", "--domains", "public,team:core"]);
    assert!(
        why_team.contains("Keep beta pure for zero-allocation math"),
        "expected relocated context match, got:\n{why_team}"
    );

    // Now test agent checkpoint save -> agent edit -> human edit -> checkpoint undo!
    // Start a clean ChangeSet with base `lib.rs`
    gitx_ok(root, &["new", "-m", "Agent session"]);
    fs::write(root.join("lib.rs"), initial_code).unwrap();
    gitx_ok(root, &["checkpoint", "save", "-m", "before agent edit", "--session", "sess-1"]);

    // Agent modifies `alpha()` (top of file) and saves checkpoint
    let after_agent = initial_code.replace("let a = 1;", "let a = 999; // agent edit");
    fs::write(root.join("lib.rs"), &after_agent).unwrap();
    let cp_save_out = gitx_ok(
        root,
        &["checkpoint", "save", "-m", "agent tuned alpha", "--session", "sess-1"],
    );
    let agent_cp_id = cp_save_out
        .split_whitespace()
        .nth(2)
        .expect("checkpoint id in output")
        .to_string();

    let cp_list = gitx_ok(root, &["checkpoint", "list"]);
    assert!(cp_list.contains(&agent_cp_id));

    // Human subsequently edits `beta()` (bottom of file)
    let after_human = after_agent.replace("let y = 20;", "let y = 42; // human edit");
    fs::write(root.join("lib.rs"), &after_human).unwrap();

    // Undo ONLY the agent checkpoint while preserving the human edit!
    let undo_cp_out = gitx_ok(root, &["checkpoint", "undo", &agent_cp_id]);
    assert!(undo_cp_out.contains("Undid checkpoint"), "got:\n{undo_cp_out}");

    let final_code = fs::read_to_string(root.join("lib.rs")).unwrap();
    assert!(
        final_code.contains("let a = 1;"),
        "agent edit should have been undone! file:\n{final_code}"
    );
    assert!(
        !final_code.contains("let a = 999;"),
        "agent edit still present! file:\n{final_code}"
    );
    assert!(
        final_code.contains("let y = 42; // human edit"),
        "human edit must be preserved! file:\n{final_code}"
    );
}

#[test]
fn e2e_fleet_overlay_export_and_apply() {
    let machine_a = TempDir::new().unwrap();
    let machine_b = TempDir::new().unwrap();
    let bundle_dir = TempDir::new().unwrap();
    let bundle_path = bundle_dir.path().join("overlay.json");

    fs::write(machine_a.path().join(".env"), "TOKEN=abc123\n").unwrap();
    fs::write(machine_a.path().join(".env.local"), "DEBUG=1\n").unwrap();
    fs::create_dir_all(machine_a.path().join("node_modules/pkg")).unwrap();
    fs::write(machine_a.path().join("node_modules/pkg/.env"), "SHOULD_NOT_EXPORT=1\n").unwrap();

    let exp_out = gitx_ok(
        machine_a.path(),
        &[
            "fleet",
            "export",
            bundle_path.to_str().unwrap(),
            "--include",
            ".env,.env.local",
        ],
    );
    assert!(exp_out.contains("2 file(s)"), "got:\n{exp_out}");

    let app_out = gitx_ok(
        machine_b.path(),
        &["fleet", "apply", bundle_path.to_str().unwrap()],
    );
    assert!(app_out.contains("2 file(s) restored"), "got:\n{app_out}");
    assert_eq!(
        fs::read_to_string(machine_b.path().join(".env")).unwrap(),
        "TOKEN=abc123\n"
    );
    assert_eq!(
        fs::read_to_string(machine_b.path().join(".env.local")).unwrap(),
        "DEBUG=1\n"
    );
    assert!(!machine_b.path().join("node_modules").exists());
}

#[test]
fn e2e_colocate_embargo_and_stack() {
    // Test colocated import from a real Git repo
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    run_git_ok(root, &["init", "-b", "master"]);
    run_git_ok(root, &["config", "user.name", "Git Author"]);
    run_git_ok(root, &["config", "user.email", "git@example.com"]);
    fs::write(root.join("main.txt"), "from git\n").unwrap();
    run_git_ok(root, &["add", "main.txt"]);
    run_git_ok(root, &["commit", "-m", "Initial git commit"]);

    let init_out = gitx_ok(root, &["init", "--colocate"]);
    assert!(init_out.contains("imported 1 commit(s) from Git"), "got:\n{init_out}");

    // Stack workflow
    fs::write(root.join("feature.txt"), "part 1\n").unwrap();
    gitx_ok(root, &["describe", "-m", "Feature part 1"]);
    gitx_ok(root, &["new", "-m", "Feature part 2"]);
    fs::write(root.join("feature2.txt"), "part 2\n").unwrap();
    let st_create = gitx_ok(root, &["stack", "create", "my-stack"]);
    assert!(st_create.contains("my-stack"));
    let st_list = gitx_ok(root, &["stack", "list"]);
    assert!(st_list.contains("my-stack"));
    let st_sync = gitx_ok(root, &["stack", "sync"]);
    assert!(st_sync.contains("Stack sync complete"));

    // Embargo create + publish
    let emb_create = gitx_ok(
        root,
        &[
            "embargo",
            "create",
            "cve-2026-0001",
            "--allow",
            "security",
            "-m",
            "Fix critical auth bug",
        ],
    );
    assert!(emb_create.contains("embargo:cve-2026-0001"));

    let emb_pub = gitx_ok(root, &["embargo", "publish", "cve-2026-0001"]);
    assert!(emb_pub.contains("is now public"));
}
