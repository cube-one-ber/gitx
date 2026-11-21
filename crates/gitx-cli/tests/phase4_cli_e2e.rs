use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
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

fn run_gitx_with_stdin(dir: &Path, args: &[&str], stdin_payload: &str) -> Output {
    let mut child = Command::new(gitx_bin())
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn gitx {args:?}: {e}"));

    {
        let stdin = child.stdin.as_mut().expect("piped stdin");
        stdin
            .write_all(stdin_payload.as_bytes())
            .expect("write stdin payload");
    }

    child.wait_with_output().expect("wait for gitx")
}

#[test]
fn e2e_mcp_in_memory_stdio() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    let requests = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e-test","version":"0.1.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gitx_write_file","arguments":{"path":"src/hello.rs","content":"pub fn greet() -> &'static str {\n    \"hello from mcp\"\n}\n"}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gitx_commit","arguments":{"message":"Add greet helper","prompt":"Implement greet helper via MCP"}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"gitx_read_file","arguments":{"path":"src/hello.rs"}}}"#,
    ]
    .join("\n")
        + "\n";

    let out = run_gitx_with_stdin(root, &["mcp", "--in-memory"], &requests);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "gitx mcp --in-memory failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Zero disk artifacts should be created in --in-memory mode.
    assert!(
        !root.join(".gitx").exists(),
        "in-memory MCP server must not create .gitx on disk"
    );

    let responses: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("invalid JSON line '{l}': {e}")))
        .collect();
    assert_eq!(
        responses.len(),
        5,
        "expected 5 JSON-RPC responses (notification produces none), got:\n{stdout}"
    );

    // 1. initialize
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[0]["result"]["serverInfo"]["name"], "gitx-mcp");
    assert_eq!(responses[0]["result"]["protocolVersion"], "2024-11-05");

    // 2. tools/list
    assert_eq!(responses[1]["id"], 2);
    let tools = responses[1]["result"]["tools"]
        .as_array()
        .expect("tools array");
    let tool_names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(tool_names.contains(&"gitx_write_file"));
    assert!(tool_names.contains(&"gitx_commit"));
    assert!(tool_names.contains(&"gitx_land"));

    // 3. gitx_write_file
    assert_eq!(responses[2]["id"], 3);
    assert_eq!(responses[2]["result"]["isError"], false);
    let write_payload: Value = serde_json::from_str(
        responses[2]["result"]["content"][0]["text"]
            .as_str()
            .expect("write_file text"),
    )
    .unwrap();
    assert_eq!(write_payload["path"], "src/hello.rs");
    assert!(write_payload["bytes_written"].as_u64().unwrap() > 0);

    // 4. gitx_commit
    assert_eq!(responses[3]["id"], 4);
    assert_eq!(responses[3]["result"]["isError"], false);
    let commit_payload: Value = serde_json::from_str(
        responses[3]["result"]["content"][0]["text"]
            .as_str()
            .expect("commit text"),
    )
    .unwrap();
    assert!(
        commit_payload["changeset_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "expected changeset_id in {commit_payload}"
    );
    assert!(
        commit_payload["context_record_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "expected durable context_record_id in {commit_payload}"
    );

    // 5. gitx_read_file
    assert_eq!(responses[4]["id"], 5);
    assert_eq!(responses[4]["result"]["isError"], false);
    let read_payload: Value = serde_json::from_str(
        responses[4]["result"]["content"][0]["text"]
            .as_str()
            .expect("read_file text"),
    )
    .unwrap();
    assert!(
        read_payload["content"]
            .as_str()
            .unwrap()
            .contains("hello from mcp")
    );
}

#[test]
fn e2e_mcp_local_repo_stdio() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    gitx_ok(root, &["init", "--name", "McpDev", "--email", "mcp@example.com"]);
    fs::write(root.join("README.md"), "# Local Repo\n").unwrap();
    gitx_ok(root, &["describe", "-m", "Add README"]);
    gitx_ok(root, &["land"]);

    let requests = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gitx_read_file","arguments":{"path":"README.md"}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gitx_write_file","arguments":{"path":"agent_note.txt","content":"persisted via mcp\n"}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gitx_commit","arguments":{"message":"Add agent note"}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"gitx_land","arguments":{"target":"master"}}}"#,
    ]
    .join("\n")
        + "\n";

    let out = run_gitx_with_stdin(root, &["mcp"], &requests);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "gitx mcp (local) failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let responses: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 5);

    let read_payload: Value =
        serde_json::from_str(responses[1]["result"]["content"][0]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(read_payload["content"], "# Local Repo\n");

    assert_eq!(responses[4]["result"]["isError"], false);
    let land_payload: Value =
        serde_json::from_str(responses[4]["result"]["content"][0]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(land_payload["land_seq"], 2);
}

#[test]
fn e2e_lazy_workspace_o1_mount() {
    let repo_dir = TempDir::new().unwrap();
    let root = repo_dir.path();
    let overlay_parent = TempDir::new().unwrap();
    let overlay_dir = overlay_parent.path().join("lazy-agent-overlay");

    gitx_ok(root, &["init", "--name", "LazyDev", "--email", "lazy@example.com"]);
    fs::create_dir_all(root.join("src")).unwrap();
    for i in 0..8 {
        fs::write(
            root.join(format!("src/mod_{i}.rs")),
            format!("pub fn fn_{i}() -> usize {{ {i} }}\n"),
        )
        .unwrap();
    }
    gitx_ok(root, &["describe", "-m", "Populate base modules"]);
    gitx_ok(root, &["land"]);

    let add_out = gitx_ok(
        root,
        &[
            "ws",
            "add",
            "lazy-agent",
            "--lazy",
            "--path",
            overlay_dir.to_str().unwrap(),
        ],
    );
    assert!(add_out.contains("lazy-agent"), "got:\n{add_out}");
    assert!(add_out.contains("LazyMount"), "got:\n{add_out}");
    assert!(add_out.contains("overlay_dirty: 0"), "got:\n{add_out}");

    // Overlay directory exists, yet ZERO base files were written to disk at mount!
    assert!(overlay_dir.is_dir(), "overlay dir should exist");
    let entry_count = fs::read_dir(&overlay_dir).unwrap().count();
    assert_eq!(
        entry_count, 0,
        "lazy workspace mount must write 0 base files to overlay dir, found {entry_count}"
    );

    let list_out = gitx_ok(root, &["ws", "list"]);
    assert!(
        list_out.contains("lazy-agent [LazyMount]"),
        "expected LazyMount workspace in ws list, got:\n{list_out}"
    );
}

#[test]
fn e2e_fleet_encrypted_overlay_export_and_apply() {
    let machine_a = TempDir::new().unwrap();
    let machine_b = TempDir::new().unwrap();
    let machine_c = TempDir::new().unwrap();
    let bundle_dir = TempDir::new().unwrap();
    let bundle_path = bundle_dir.path().join("fleet.enc.json");

    gitx_ok(
        machine_a.path(),
        &["init", "--name", "MachineA", "--email", "a@example.com"],
    );
    gitx_ok(
        machine_b.path(),
        &["init", "--name", "MachineB", "--email", "b@example.com"],
    );
    gitx_ok(
        machine_c.path(),
        &["init", "--name", "MachineC", "--email", "c@example.com"],
    );

    // Grant Machine B's local public key bundle as a recipient in Machine A's keyring.
    let b_keyring: Value = serde_json::from_str(
        &fs::read_to_string(machine_b.path().join(".gitx/keys/local.json")).unwrap(),
    )
    .unwrap();
    let b_pub_json = serde_json::to_string(&b_keyring["recipients"]["local"]).unwrap();
    let grant_out = gitx_ok(
        machine_a.path(),
        &["secret", "grant", "machine-b", &b_pub_json],
    );
    assert!(grant_out.contains("Granted secret recipient 'machine-b'"));

    // Write sensitive local overlay files on Machine A.
    let secret_env = "DATABASE_URL=postgres://admin:super_secret_pw_98765@db.prod/app\nAPI_TOKEN=sk_live_encrypted_fleet_token_42\n";
    let local_env = "DEBUG_TRACE=true\n";
    fs::write(machine_a.path().join(".env"), secret_env).unwrap();
    fs::write(machine_a.path().join(".env.local"), local_env).unwrap();

    // Export end-to-end encrypted fleet overlay bundle.
    let exp_out = gitx_ok(
        machine_a.path(),
        &[
            "fleet",
            "export",
            bundle_path.to_str().unwrap(),
            "--encrypted",
            "--machine",
            "laptop-a",
        ],
    );
    assert!(exp_out.contains("encrypted fleet overlay"), "got:\n{exp_out}");
    assert!(exp_out.contains("2 file(s)"), "got:\n{exp_out}");
    assert!(exp_out.contains("laptop-a"), "got:\n{exp_out}");

    // Prove ZERO plaintext secret appears anywhere in the exported bundle file!
    let raw_bundle = fs::read_to_string(&bundle_path).unwrap();
    assert!(
        !raw_bundle.contains("super_secret_pw_98765"),
        "plaintext password leaked into encrypted bundle!"
    );
    assert!(
        !raw_bundle.contains("sk_live_encrypted_fleet_token_42"),
        "plaintext API token leaked into encrypted bundle!"
    );
    assert!(
        !raw_bundle.contains("DATABASE_URL"),
        "plaintext env var key leaked into encrypted bundle!"
    );
    assert!(
        !raw_bundle.contains("DEBUG_TRACE"),
        "plaintext .env.local leaked into encrypted bundle!"
    );
    assert!(raw_bundle.contains("\"envelope\""));

    // Applying without --encrypted must fail cleanly and advise --encrypted.
    let wrong_mode = run_gitx(
        machine_b.path(),
        &["fleet", "apply", bundle_path.to_str().unwrap()],
    );
    assert!(!wrong_mode.status.success());
    let wrong_err = String::from_utf8_lossy(&wrong_mode.stderr);
    assert!(
        wrong_err.contains("--encrypted"),
        "expected hint about --encrypted, got:\n{wrong_err}"
    );

    // Authorized Machine B decrypts and restores overlay files verbatim!
    let app_out = gitx_ok(
        machine_b.path(),
        &[
            "fleet",
            "apply",
            bundle_path.to_str().unwrap(),
            "--encrypted",
        ],
    );
    assert!(app_out.contains("2 file(s) restored"), "got:\n{app_out}");
    assert_eq!(
        fs::read_to_string(machine_b.path().join(".env")).unwrap(),
        secret_env
    );
    assert_eq!(
        fs::read_to_string(machine_b.path().join(".env.local")).unwrap(),
        local_env
    );

    // Unauthorized Machine C cannot decrypt the bundle.
    let unauth = run_gitx(
        machine_c.path(),
        &[
            "fleet",
            "apply",
            bundle_path.to_str().unwrap(),
            "--encrypted",
        ],
    );
    assert!(
        !unauth.status.success(),
        "unauthorized machine must fail to decrypt encrypted fleet bundle"
    );
    assert!(!machine_c.path().join(".env").exists());
}

#[test]
fn e2e_symbols_rust_and_typescript() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("src")).unwrap();

    let rust_src = "\
pub struct Engine {
    pub workers: usize,
}

impl Engine {
    pub fn start(&self) -> usize {
        self.workers
    }
}

pub fn compute_sum(a: i32, b: i32) -> i32 {
    a + b
}
";
    fs::write(root.join("src/lib.rs"), rust_src).unwrap();

    // Human-readable output
    let text_out = gitx_ok(root, &["symbols", "src/lib.rs"]);
    assert!(text_out.contains("struct") && text_out.contains("Engine"), "got:\n{text_out}");
    assert!(text_out.contains("impl") && text_out.contains("Engine"), "got:\n{text_out}");
    assert!(text_out.contains("method") && text_out.contains("start"), "got:\n{text_out}");
    assert!(text_out.contains("fn") && text_out.contains("compute_sum"), "got:\n{text_out}");
    assert!(text_out.contains("L1-L3"), "got:\n{text_out}");

    // JSON output
    let json_out = gitx_ok(root, &["symbols", "src/lib.rs", "--json"]);
    let syms: Vec<Value> = serde_json::from_str(&json_out).expect("valid JSON array");
    assert_eq!(syms.len(), 4, "got:\n{json_out}");
    assert_eq!(syms[0]["kind"], "struct");
    assert_eq!(syms[0]["name"], "Engine");
    assert_eq!(syms[0]["line_start"], 1);
    assert_eq!(syms[0]["line_end"], 3);
    assert_eq!(syms[2]["kind"], "method");
    assert_eq!(syms[2]["name"], "start");
    assert_eq!(syms[3]["kind"], "fn");
    assert_eq!(syms[3]["name"], "compute_sum");

    // TypeScript support
    let ts_src = "\
export interface User {
    id: string;
}

export class UserService {
    find(id: string): User {
        return { id };
    }
}

export function bootstrap(): void {}
";
    fs::write(root.join("src/app.ts"), ts_src).unwrap();
    let ts_json = gitx_ok(root, &["symbols", "src/app.ts", "--json"]);
    let ts_syms: Vec<Value> = serde_json::from_str(&ts_json).expect("valid TS JSON");
    let ts_pairs: Vec<(&str, &str)> = ts_syms
        .iter()
        .map(|s| (s["kind"].as_str().unwrap(), s["name"].as_str().unwrap()))
        .collect();
    assert!(ts_pairs.contains(&("interface", "User")), "got:\n{ts_json}");
    assert!(ts_pairs.contains(&("class", "UserService")), "got:\n{ts_json}");
    assert!(ts_pairs.contains(&("method", "find")), "got:\n{ts_json}");
    assert!(ts_pairs.contains(&("function", "bootstrap")), "got:\n{ts_json}");
}

#[test]
fn e2e_parallel_workspaces_ast_semantic_merge_land() {
    let base_temp = TempDir::new().unwrap();
    let main_repo = base_temp.path().join("repo");
    let ws1_dir = base_temp.path().join("ws-agent-alpha");
    let ws2_dir = base_temp.path().join("ws-agent-beta");
    fs::create_dir_all(&main_repo).unwrap();

    // 1. Initialize repo with base src/lib.rs and land onto master.
    gitx_ok(
        &main_repo,
        &["init", "--name", "MergeLead", "--email", "lead@example.com"],
    );
    fs::create_dir_all(main_repo.join("src")).unwrap();
    let base_lib = "\
pub fn base_fn() -> i32 {
    1
}
";
    fs::write(main_repo.join("src/lib.rs"), base_lib).unwrap();
    gitx_ok(&main_repo, &["describe", "-m", "Add base_fn"]);
    let land0 = gitx_ok(&main_repo, &["land"]);
    assert!(land0.contains("land_seq: 1"), "got:\n{land0}");

    // 2. Spawn two lock-free parallel CoW workspaces off the exact same master commit.
    gitx_ok(
        &main_repo,
        &["ws", "add", "ws-alpha", "--path", ws1_dir.to_str().unwrap()],
    );
    gitx_ok(
        &main_repo,
        &["ws", "add", "ws-beta", "--path", ws2_dir.to_str().unwrap()],
    );

    // 3. Both workspaces concurrently append different Rust functions at the exact same EOF slot.
    let ws1_lib = format!(
        "{base_lib}\npub fn alpha_feature() -> i32 {{\n    10\n}}\n"
    );
    let ws2_lib = format!(
        "{base_lib}\npub fn beta_feature() -> i32 {{\n    20\n}}\n"
    );
    fs::write(ws1_dir.join("src/lib.rs"), ws1_lib).unwrap();
    fs::write(ws2_dir.join("src/lib.rs"), ws2_lib).unwrap();

    // 4. Workspace 1 lands onto master (fast-forward).
    gitx_ok(&ws1_dir, &["describe", "-m", "Add alpha_feature"]);
    let land1 = gitx_ok(&ws1_dir, &["land"]);
    assert!(land1.contains("land_seq: 2"), "got:\n{land1}");

    // 5. Workspace 2 lands onto master — Tree-sitter AST semantic merge resolves cleanly!
    gitx_ok(&ws2_dir, &["describe", "-m", "Add beta_feature"]);
    let land2 = gitx_ok(&ws2_dir, &["land"]);
    assert!(land2.contains("land_seq: 3"), "got:\n{land2}");

    // 6. Verify merged src/lib.rs has ALL THREE functions and zero conflict markers.
    let merged_src = fs::read_to_string(ws2_dir.join("src/lib.rs")).unwrap();
    assert!(
        !merged_src.contains("<<<<<<<"),
        "AST merge should produce zero conflict markers:\n{merged_src}"
    );
    assert!(merged_src.contains("pub fn base_fn()"), "got:\n{merged_src}");
    assert!(
        merged_src.contains("pub fn alpha_feature()"),
        "got:\n{merged_src}"
    );
    assert!(
        merged_src.contains("pub fn beta_feature()"),
        "got:\n{merged_src}"
    );

    // 7. Confirm via `gitx symbols src/lib.rs --json` that all 3 Rust functions parse cleanly.
    let syms_json = gitx_ok(&ws2_dir, &["symbols", "src/lib.rs", "--json"]);
    let syms: Vec<Value> = serde_json::from_str(&syms_json).unwrap();
    let fn_names: Vec<&str> = syms
        .iter()
        .filter(|s| s["kind"] == "fn")
        .filter_map(|s| s["name"].as_str())
        .collect();
    assert!(fn_names.contains(&"base_fn"), "got:\n{syms_json}");
    assert!(fn_names.contains(&"alpha_feature"), "got:\n{syms_json}");
    assert!(fn_names.contains(&"beta_feature"), "got:\n{syms_json}");
}

#[test]
fn e2e_ws_mount_and_unmount_loopback() {
    use std::io::{BufRead, BufReader};
    use std::net::SocketAddr;

    let repo_dir = TempDir::new().unwrap();
    let root = repo_dir.path();
    let overlay_parent = TempDir::new().unwrap();
    let overlay_dir = overlay_parent.path().join("lazy-mount-overlay");
    let mount_dir = overlay_parent.path().join("vfs-mnt");

    gitx_ok(root, &["init", "--name", "MountDev", "--email", "mount@example.com"]);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/hello.rs"), "pub fn hi() -> &'static str { \"hi\" }\n").unwrap();
    gitx_ok(root, &["describe", "-m", "Seed mount repo"]);
    gitx_ok(root, &["land"]);

    gitx_ok(
        root,
        &[
            "ws",
            "add",
            "vfs-agent",
            "--lazy",
            "--path",
            overlay_dir.to_str().unwrap(),
        ],
    );

    // Spawn `gitx ws mount vfs-agent <mount_dir> --backend loopback`.
    let mut child = Command::new(gitx_bin())
        .current_dir(root)
        .args([
            "ws",
            "mount",
            "vfs-agent",
            mount_dir.to_str().unwrap(),
            "--backend",
            "loopback",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gitx ws mount");

    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut first_line = String::new();
    reader
        .read_line(&mut first_line)
        .expect("read mount status line");
    assert!(
        first_line.contains("Mounted workspace 'vfs-agent'")
            && first_line.contains("backend: loopback"),
        "unexpected mount output: {first_line}"
    );

    // Parse `addr: 127.0.0.1:<port>` and verify live RPC reads/writes over TCP loopback!
    let addr_str = first_line
        .split("addr: ")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .expect("extract addr from mount line");
    let addr: SocketAddr = addr_str.parse().expect("valid loopback SocketAddr");

    let mut client = gitx_vfs::LoopbackVfsClient::connect(addr).expect("connect loopback vfs");
    let src_dir = client
        .lookup(gitx_vfs::ROOT_INO, "src")
        .expect("lookup src");
    let hello = client
        .lookup(src_dir.ino, "hello.rs")
        .expect("lookup hello.rs");
    let bytes = client.read(hello.ino, 0, 1024).expect("read hello.rs");
    assert_eq!(bytes, b"pub fn hi() -> &'static str { \"hi\" }\n");
    drop(client);

    // Unmount via `gitx ws unmount <mount_dir>` and confirm clean exit.
    let unmount_out = gitx_ok(root, &["ws", "unmount", mount_dir.to_str().unwrap()]);
    assert!(
        unmount_out.contains("Unmounted workspace 'vfs-agent'"),
        "unexpected unmount output:\n{unmount_out}"
    );

    let status = child.wait().expect("wait for mount process exit");
    assert!(
        status.success(),
        "mount process should exit cleanly on unmount, got {status:?}"
    );
}
