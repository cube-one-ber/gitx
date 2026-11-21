use gitx_context::ContextKind;
use gitx_core::{Actor, GitxError, Identity};
use gitx_crypto::{Principal, SecretKind};
use gitx_sdk::{AgentIdentity, AgentRepo, CommitContext, MCP_PROTOCOL_VERSION, McpServer};
use serde_json::{Value, json};
use std::io::Cursor;

fn dev_author() -> Identity {
    Identity {
        name: "Alice Developer".to_string(),
        email: "alice@example.com".to_string(),
        key_fingerprint: None,
    }
}

fn dev_principal() -> Principal {
    Principal::user("alice").with_team("core")
}

#[test]
fn four_parallel_agents_semantic_merge_why_and_checkpoint_undo() {
    let mut repo = AgentRepo::in_memory(dev_author(), dev_principal()).expect("in-memory repo");

    // Seed master with a shared package.json and a source file.
    let base_pkg = json!({
        "name": "gitx-demo",
        "version": "1.0.0",
        "dependencies": {
            "core-lib": "^1.0.0"
        }
    });
    let base_pkg_str = format!("{}\n", serde_json::to_string_pretty(&base_pkg).unwrap());
    let warnings = repo
        .write_file("default", "package.json", base_pkg_str.as_bytes())
        .unwrap();
    assert!(warnings.is_empty());

    let base_src = "pub fn alpha() -> i32 {\n    1\n}\n\npub fn beta() -> i32 {\n    2\n}\n";
    repo.write_file("default", "src/core.rs", base_src.as_bytes())
        .unwrap();

    let seed_agent = AgentIdentity::new("seed", "human-setup", "sess-0");
    repo.commit("default", "Seed base project files", seed_agent, None)
        .unwrap();
    let seed_land = repo.land("default", "master").unwrap();
    assert_eq!(seed_land.land_record.land_seq, 1);
    assert!(!seed_land.auto_merged);

    // Fork 4 parallel in-memory workspaces off `master`.
    let agent_specs = [
        ("agent-1", "src/auth.rs", "auth-pkg", "^2.0.0", "Add OAuth2 login middleware"),
        ("agent-2", "src/billing.rs", "stripe-sdk", "^3.1.0", "Implement invoice billing service"),
        ("agent-3", "src/metrics.rs", "otel-core", "^0.24.0", "Add OpenTelemetry metrics exporter"),
        ("agent-4", "src/search.rs", "tantivy-js", "^1.4.0", "Build full-text search index"),
    ];

    for (ws_name, _, _, _, _) in &agent_specs {
        repo.create_workspace(ws_name, "master").unwrap();
    }

    let workspaces = repo.list_workspaces().unwrap();
    assert_eq!(workspaces.len(), 5); // default + 4 agents

    // All 4 agents concurrently edit disjoint source files AND add distinct keys to shared package.json.
    for (idx, (ws_name, file_path, dep_name, dep_ver, prompt_text)) in agent_specs.iter().enumerate() {
        let code = format!(
            "pub fn feature_{idx}() -> &'static str {{\n    \"{dep_name}\"\n}}\n"
        );
        let w1 = repo.write_file(ws_name, file_path, code.as_bytes()).unwrap();
        assert!(w1.is_empty());

        let mut pkg: Value =
            serde_json::from_str(&repo.read_file_string(ws_name, "package.json").unwrap()).unwrap();
        pkg["dependencies"][*dep_name] = Value::String((*dep_ver).to_string());
        let updated_pkg = format!("{}\n", serde_json::to_string_pretty(&pkg).unwrap());
        repo.write_file(ws_name, "package.json", updated_pkg.as_bytes())
            .unwrap();

        // Verify diff and grep work in-memory before commit.
        let diff_text = repo.diff(ws_name).unwrap();
        assert!(diff_text.contains(dep_name));
        assert!(diff_text.contains(file_path));

        let grep_hits = repo.grep(ws_name, dep_name).unwrap();
        assert!(grep_hits.len() >= 2); // package.json + feature file

        let agent = AgentIdentity::new(
            "antigravity",
            format!("claude-agent-{idx}"),
            format!("session-{idx}"),
        );
        let commit_out = repo
            .commit(
                ws_name,
                format!("Implement {dep_name}"),
                agent,
                Some(CommitContext::prompt(*prompt_text)),
            )
            .unwrap();

        // Verify Actor::Agent provenance and durable ContextRecord.
        match &commit_out.changeset.committer {
            Actor::Agent {
                harness,
                model,
                session_id,
                initiated_by,
            } => {
                assert_eq!(harness, "antigravity");
                assert_eq!(model, &format!("claude-agent-{idx}"));
                assert_eq!(session_id, &format!("session-{idx}"));
                assert_eq!(initiated_by, &dev_author());
            }
            other => panic!("expected Actor::Agent, got {other:?}"),
        }
        assert!(commit_out.context_record.is_some());
    }

    // Land all 4 parallel agent workspaces sequentially onto `master`.
    let mut prev_seq = seed_land.land_record.land_seq;
    for (idx, (ws_name, _, _, _, _)) in agent_specs.iter().enumerate() {
        let land_out = repo.land(ws_name, "master").unwrap();
        assert_eq!(land_out.land_record.land_seq, prev_seq + 1);
        prev_seq = land_out.land_record.land_seq;
        assert!(land_out.conflict_paths.is_empty());
        // First agent fast-forwards; remaining 3 require 3-way semantic auto-merge.
        assert_eq!(land_out.auto_merged, idx > 0);
    }

    // Verify all 4 disjoint files and all 4 package.json dependencies are present on `master`.
    let master_files = repo.list_files_at("master").unwrap();
    for (_, file_path, _, _, _) in &agent_specs {
        assert!(
            master_files.contains(&(*file_path).to_string()),
            "missing {file_path} in master: {master_files:?}"
        );
    }

    let final_pkg_bytes = repo.read_file_at("master", "package.json").unwrap();
    let final_pkg_str = String::from_utf8(final_pkg_bytes).unwrap();
    let final_pkg: Value = serde_json::from_str(&final_pkg_str).unwrap();
    assert_eq!(final_pkg["dependencies"]["core-lib"], "^1.0.0");
    assert_eq!(final_pkg["dependencies"]["auth-pkg"], "^2.0.0");
    assert_eq!(final_pkg["dependencies"]["stripe-sdk"], "^3.1.0");
    assert_eq!(final_pkg["dependencies"]["otel-core"], "^0.24.0");
    assert_eq!(final_pkg["dependencies"]["tantivy-js"], "^1.4.0");

    // Verify `why` locates the originating agent prompt for each file AND for relocated lines in
    // the semantically merged `package.json`.
    for (_, file_path, dep_name, _, expected_prompt) in &agent_specs {
        let file_why = repo.why("master", file_path, 2).unwrap();
        assert!(
            file_why.iter().any(|m| matches!(
                &m.record.kind,
                ContextKind::Prompt { prompt, .. } if prompt == expected_prompt
            )),
            "expected prompt '{expected_prompt}' for {file_path}, got {file_why:?}"
        );

        let dep_line = final_pkg_str
            .lines()
            .position(|l| l.contains(dep_name))
            .expect("dep line in merged package.json") as u32
            + 1;
        let pkg_why = repo.why("master", "package.json", dep_line).unwrap();
        assert!(
            pkg_why.iter().any(|m| matches!(
                &m.record.kind,
                ContextKind::Prompt { prompt, .. } if prompt == expected_prompt
            )),
            "expected relocated prompt '{expected_prompt}' at package.json:{dep_line}, got {pkg_why:?}"
        );
    }

    // Verify surgical `undo_checkpoint` preserves concurrent non-overlapping human edits!
    repo.create_workspace("collab", "master").unwrap();
    let collab_agent = AgentIdentity::new("antigravity", "gpt-5", "collab-sess");

    let cp_before = repo
        .save_checkpoint("collab", collab_agent.clone(), "Baseline before agent refactor")
        .unwrap();

    // Agent modifies `alpha()` and adds a temporary helper file.
    let after_agent_src =
        "pub fn alpha() -> i32 {\n    999\n}\n\npub fn beta() -> i32 {\n    2\n}\n";
    repo.write_file("collab", "src/core.rs", after_agent_src.as_bytes())
        .unwrap();
    repo.write_file("collab", "src/agent_scratch.rs", b"// temporary\n")
        .unwrap();

    let cp_agent = repo
        .save_checkpoint("collab", collab_agent, "Agent rewrote alpha() to 999")
        .unwrap();
    assert_eq!(cp_agent.parent_checkpoint, Some(cp_before.id));

    // Human concurrently modifies `beta()` in the same file AND creates a human doc file.
    let after_human_src =
        "pub fn alpha() -> i32 {\n    999\n}\n\npub fn beta() -> i32 {\n    42\n}\n";
    repo.write_file("collab", "src/core.rs", after_human_src.as_bytes())
        .unwrap();
    repo.write_file("collab", "NOTES.md", b"# Human notes\n")
        .unwrap();

    // Surgically undo the agent checkpoint.
    let undo_out = repo.undo_checkpoint("collab", Some(cp_agent.id)).unwrap();
    assert!(undo_out.conflict_paths.is_empty());
    assert_eq!(undo_out.restored_to_checkpoint, Some(cp_before.id));

    // Agent's edit to `alpha()` is reverted back to `1`, agent scratch file is deleted,
    // while human's edit to `beta()` (`42`) and `NOTES.md` are BOTH preserved!
    let reverted_src = repo.read_file_string("collab", "src/core.rs").unwrap();
    assert!(reverted_src.contains("pub fn alpha() -> i32 {\n    1\n}"));
    assert!(reverted_src.contains("pub fn beta() -> i32 {\n    42\n}"));
    assert!(repo.read_file("collab", "src/agent_scratch.rs").is_err());
    assert_eq!(
        repo.read_file_string("collab", "NOTES.md").unwrap(),
        "# Human notes\n"
    );
}

#[test]
fn acl_enforcement_secret_scanner_and_open_local_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let fake_aws_key = format!("{}IOSFODNN7EXAMPLE", "AKIA");
    let config_with_secret = format!("AWS_ACCESS_KEY_ID={fake_aws_key}\n");

    // Open local repo and verify zero-trust secret warnings + ACL denial on secret:dev.
    {
        let mut repo =
            AgentRepo::open_local(dir.path(), dev_author(), dev_principal()).unwrap();

        // Writing to `.env` routes to `secret:dev`, which is deny-by-default unless granted.
        let err = repo
            .write_file("default", ".env", b"DB_PASS=supersecret123\n")
            .unwrap_err();
        assert!(matches!(err, GitxError::AccessDenied { .. }));

        // Writing a secret inside a public file succeeds in-memory but emits scanner warnings.
        let warnings = repo
            .write_file("default", "src/config.rs", config_with_secret.as_bytes())
            .unwrap();
        assert!(
            warnings.iter().any(|w| w.kind == SecretKind::AwsAccessKey),
            "expected AWS key warning, got {warnings:?}"
        );

        let scan_all = repo.scan_secrets("default", None).unwrap();
        assert!(!scan_all.is_empty());

        // Replace with clean content, commit, and land to disk-backed LocalStore.
        repo.write_file("default", "src/config.rs", b"pub const PORT: u16 = 8080;\n")
            .unwrap();
        let agent = AgentIdentity::new("cli", "gemini", "local-1");
        repo.commit(
            "default",
            "Add clean config",
            agent,
            Some(CommitContext::prompt("Set default HTTP port to 8080")),
        )
        .unwrap();
        let landed = repo.land("default", "master").unwrap();
        assert_eq!(landed.land_record.land_seq, 1);
    }

    // Reopen from disk and verify persisted changeset + context record survive restart.
    let reopened = AgentRepo::open_local(dir.path(), dev_author(), dev_principal()).unwrap();
    assert_eq!(
        reopened.read_file_string("default", "src/config.rs").unwrap(),
        "pub const PORT: u16 = 8080;\n"
    );
    let why_hits = reopened.why("master", "src/config.rs", 1).unwrap();
    assert_eq!(why_hits.len(), 1);
    assert!(matches!(
        &why_hits[0].record.kind,
        ContextKind::Prompt { prompt, .. } if prompt == "Set default HTTP port to 8080"
    ));
}

#[test]
fn full_mcp_json_rpc_stdio_session() {
    let repo = AgentRepo::in_memory(dev_author(), dev_principal()).unwrap();
    let mut server = McpServer::new(repo);

    let fake_gh_token = format!("{}_1234567890abcdef123456", "ghp");

    let requests = vec![
        // 1. initialize
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "0.1.0" }
            }
        }),
        // 2. notifications/initialized (no `id` => must produce NO response)
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
        // 3. tools/list
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }),
        // 4. gitx_create_workspace
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "gitx_create_workspace",
                "arguments": { "name": "mcp-ws", "base_ref": "master" }
            }
        }),
        // 5. gitx_write_file
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "gitx_write_file",
                "arguments": {
                    "workspace": "mcp-ws",
                    "path": "src/lib.rs",
                    "content": "pub fn greet() -> &'static str {\n    \"hello\"\n}\n\npub fn keep() -> i32 {\n    1\n}\n"
                }
            }
        }),
        // 6. gitx_list_files
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "gitx_list_files",
                "arguments": { "workspace": "mcp-ws" }
            }
        }),
        // 7. gitx_read_file
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "gitx_read_file",
                "arguments": { "workspace": "mcp-ws", "path": "src/lib.rs" }
            }
        }),
        // 8. gitx_grep
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "gitx_grep",
                "arguments": { "workspace": "mcp-ws", "query": "hello" }
            }
        }),
        // 9. gitx_diff
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "gitx_diff",
                "arguments": { "workspace": "mcp-ws" }
            }
        }),
        // 10. gitx_commit with prompt provenance
        json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "gitx_commit",
                "arguments": {
                    "workspace": "mcp-ws",
                    "message": "Add greet and keep helpers",
                    "prompt": "Create greet() returning hello",
                    "harness": "mcp-test",
                    "model": "gemini-pro",
                    "session_id": "mcp-1"
                }
            }
        }),
        // 11. gitx_land
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "gitx_land",
                "arguments": { "workspace": "mcp-ws", "target": "master" }
            }
        }),
        // 12. gitx_why
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "gitx_why",
                "arguments": { "workspace": "master", "path": "src/lib.rs", "line": 2 }
            }
        }),
        // 13. gitx_checkpoint_save (baseline) + agent edit + checkpoint_save + human edit + undo
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "gitx_write_file",
                "arguments": {
                    "workspace": "mcp-ws",
                    "path": "src/lib.rs",
                    "content": "pub fn greet() -> &'static str {\n    \"agent-changed\"\n}\n\npub fn keep() -> i32 {\n    1\n}\n"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "gitx_checkpoint_save",
                "arguments": {
                    "workspace": "mcp-ws",
                    "prompt_summary": "Agent modified greet()"
                }
            }
        }),
        // Human edits keep() concurrently
        json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {
                "name": "gitx_write_file",
                "arguments": {
                    "workspace": "mcp-ws",
                    "path": "src/lib.rs",
                    "content": "pub fn greet() -> &'static str {\n    \"agent-changed\"\n}\n\npub fn keep() -> i32 {\n    99\n}\n"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {
                "name": "gitx_checkpoint_undo",
                "arguments": { "workspace": "mcp-ws" }
            }
        }),
        // 14. gitx_secret_scan
        json!({
            "jsonrpc": "2.0",
            "id": 16,
            "method": "tools/call",
            "params": {
                "name": "gitx_secret_scan",
                "arguments": {
                    "path": "src/token.rs",
                    "content": format!("const TOKEN: &str = \"{fake_gh_token}\";\n")
                }
            }
        }),
        // 15. gitx_delete_file
        json!({
            "jsonrpc": "2.0",
            "id": 17,
            "method": "tools/call",
            "params": {
                "name": "gitx_write_file",
                "arguments": {
                    "workspace": "mcp-ws",
                    "path": "tmp.txt",
                    "content": "delete me\n"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 18,
            "method": "tools/call",
            "params": {
                "name": "gitx_delete_file",
                "arguments": { "workspace": "mcp-ws", "path": "tmp.txt" }
            }
        }),
    ];

    let mut input = String::new();
    for req in &requests {
        input.push_str(&req.to_string());
        input.push('\n');
    }

    let mut output_bytes = Vec::new();
    server
        .run_stdio(Cursor::new(input.into_bytes()), &mut output_bytes)
        .unwrap();
    assert!(server.is_initialized());

    let output_str = String::from_utf8(output_bytes).unwrap();
    let responses: Vec<Value> = output_str
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSON-RPC response"))
        .collect();

    // 19 requests minus 1 notification = 18 responses
    assert_eq!(responses.len(), 18);

    // Helper to parse tool call JSON text payload by request id.
    let by_id = |target_id: i64| -> &Value {
        responses
            .iter()
            .find(|r| r["id"] == json!(target_id))
            .unwrap_or_else(|| panic!("missing response for id {target_id}"))
    };
    let tool_json = |target_id: i64| -> Value {
        let resp = by_id(target_id);
        assert_eq!(resp["result"]["isError"], json!(false), "resp: {resp}");
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        serde_json::from_str(text).expect("tool JSON text")
    };

    // Check initialize
    let init = by_id(1);
    assert_eq!(init["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
    assert_eq!(init["result"]["serverInfo"]["name"], "gitx-mcp");

    // Check tools/list exposes all 13 required tools
    let tools = by_id(2)["result"]["tools"].as_array().unwrap();
    let tool_names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for expected in [
        "gitx_list_files",
        "gitx_read_file",
        "gitx_write_file",
        "gitx_delete_file",
        "gitx_diff",
        "gitx_grep",
        "gitx_create_workspace",
        "gitx_commit",
        "gitx_land",
        "gitx_checkpoint_save",
        "gitx_checkpoint_undo",
        "gitx_why",
        "gitx_secret_scan",
    ] {
        assert!(
            tool_names.contains(&expected),
            "missing tool '{expected}' in {tool_names:?}"
        );
    }

    // Check file operations
    assert_eq!(tool_json(5)["files"], json!(["src/lib.rs"]));
    assert!(tool_json(6)["content"].as_str().unwrap().contains("hello"));
    assert_eq!(tool_json(7)["matches"].as_array().unwrap().len(), 1);
    assert!(tool_json(8)["diff"].as_str().unwrap().contains("+pub fn greet()"));

    // Check commit, land, why
    assert!(tool_json(9)["context_record_id"].is_string());
    assert_eq!(tool_json(10)["land_seq"], json!(1));
    let why_matches = tool_json(11)["matches"].as_array().unwrap().clone();
    assert_eq!(why_matches.len(), 1);

    // Check checkpoint undo preserved human edit (`99`) while reverting agent edit (`"hello"`)
    let undo_payload = tool_json(15);
    assert_eq!(undo_payload["conflict_paths"], json!([]));
    let final_src = server
        .repo()
        .read_file_string("mcp-ws", "src/lib.rs")
        .unwrap();
    assert!(final_src.contains("\"hello\""), "agent edit should be undone: {final_src}");
    assert!(final_src.contains("99"), "human edit should be preserved: {final_src}");

    // Check secret scan
    let scan_payload = tool_json(16);
    assert_eq!(scan_payload["has_secrets"], json!(true));
    assert_eq!(scan_payload["findings"].as_array().unwrap().len(), 1);

    // Check delete_file
    assert_eq!(tool_json(18)["deleted"], json!(true));
    assert!(server.repo().read_file("mcp-ws", "tmp.txt").is_err());

    // Verify parse error & unknown method error handling
    let parse_err: Value =
        serde_json::from_str(&server.handle_json_line("{not-json").unwrap()).unwrap();
    assert_eq!(parse_err["error"]["code"], json!(-32700));

    let method_err: Value = serde_json::from_str(
        &server
            .handle_json_line(r#"{"jsonrpc":"2.0","id":99,"method":"nonexistent/method"}"#)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(method_err["error"]["code"], json!(-32601));
}
