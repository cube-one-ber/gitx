use gitx_server::{
    BlameResponse, CommitResponse, ConflictResolverFn, DerivedStats, DrainResponse,
    EnqueueResponse, GrepResponse, QueueListResponse, QueueStatus, RevertResponse, ServerConfig,
    TreeResponse, serve,
};
use reqwest::Client;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

struct TestServer {
    addr: SocketAddr,
    _tmp: TempDir,
    handle: JoinHandle<()>,
}

impl TestServer {
    async fn start(default_acl: Option<&str>, resolver: Option<ConflictResolverFn>) -> Self {
        let tmp = TempDir::new().expect("temp dir");
        let mut config = ServerConfig::new(tmp.path());
        if let Some(acl) = default_acl {
            config = config.with_default_acl(acl);
        }
        if let Some(r) = resolver {
            config = config.with_conflict_resolver(r);
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let _ = serve(listener, config).await;
        });
        Self {
            addr,
            _tmp: tmp,
            handle,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_16_agents_batched_merge_queue_and_monotonic_land_seq() {
    let srv = TestServer::start(None, None).await;
    let client = Client::new();

    // Seed initial master commit with base package.json
    let base: CommitResponse = client
        .post(srv.url("/v1/repos/acme/swarm/commit"))
        .header("X-Gitx-User", "bootstrap")
        .json(&json!({
            "files": {
                "package.json": "{\n  \"name\": \"agent-swarm\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"core\": \"1.0.0\"\n  }\n}\n",
                "README.md": "# Agent Swarm Repo\n"
            },
            "message": "Initial base commit",
            "author_name": "Bootstrap",
            "author_email": "bootstrap@acme.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Launch 16 concurrent Tokio agent tasks:
    // each commits a unique file + unique package.json dependency key based on `base`,
    // then enqueues its ChangeSet onto `master`.
    let mut set = JoinSet::new();
    for idx in 0..16usize {
        let client = client.clone();
        let commit_url = srv.url("/v1/repos/acme/swarm/commit");
        let enqueue_url = srv.url("/v1/repos/acme/swarm/queue/enqueue");
        let base_id = base.changeset_id.clone();

        set.spawn(async move {
            let agent_name = format!("agent-{idx:02}");
            let file_path = format!("agents/agent_{idx:02}.rs");
            let file_body = format!("pub fn agent_{idx:02}() -> usize {{ {idx} }}\n");
            let pkg_json = format!(
                "{{\n  \"name\": \"agent-swarm\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {{\n    \"core\": \"1.0.0\",\n    \"pkg-agent-{idx:02}\": \"1.0.{idx}\"\n  }}\n}}\n"
            );

            let cs: CommitResponse = client
                .post(&commit_url)
                .header("X-Gitx-User", &agent_name)
                .json(&json!({
                    "files": {
                        file_path: file_body,
                        "package.json": pkg_json
                    },
                    "parent": base_id,
                    "update_target": false,
                    "message": format!("Agent {idx:02} feature"),
                    "author_name": format!("Agent {idx:02}"),
                    "author_email": format!("agent{idx:02}@acme.dev"),
                    "actor_agent": {
                        "harness": "gitx-swarm",
                        "model": "test-agent",
                        "session_id": format!("sess-{idx:02}")
                    }
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            let enq: EnqueueResponse = client
                .post(&enqueue_url)
                .header("X-Gitx-User", &agent_name)
                .json(&json!({
                    "changeset_id": cs.changeset_id,
                    "target": "master"
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            assert_eq!(enq.entry.status, QueueStatus::Pending);
            cs.changeset_id
        });
    }

    let mut committed_ids = Vec::new();
    while let Some(res) = set.join_next().await {
        committed_ids.push(res.expect("agent task panicked"));
    }
    assert_eq!(committed_ids.len(), 16);

    // Inspect pending queue before draining
    let before_queue: QueueListResponse = client
        .get(srv.url("/v1/repos/acme/swarm/queue?target=master"))
        .header("X-Gitx-User", "merge-bot")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(before_queue.target, "master");
    assert_eq!(before_queue.pending_count, 16);
    assert_eq!(before_queue.entries.len(), 16);

    // Drain the entire 16-agent batch atomically in a SINGLE record_land transaction!
    let drain: DrainResponse = client
        .post(srv.url("/v1/repos/acme/swarm/queue/drain"))
        .header("X-Gitx-User", "merge-bot")
        .json(&json!({ "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(drain.land_seq, Some(1));
    assert_eq!(drain.previous_head.as_deref(), Some(base.changeset_id.as_str()));
    assert!(drain.new_head.is_some());
    assert_eq!(drain.landed.len(), 16);
    assert!(drain.conflicted.is_empty());
    assert!(drain.rejected.is_empty());
    for entry in &drain.landed {
        assert_eq!(entry.status, QueueStatus::Landed { land_seq: 1 });
    }

    // Verify all 16 unique files + all 16 unique package.json keys are intact on master!
    let tree: TreeResponse = client
        .get(srv.url("/v1/repos/acme/swarm/tree"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let pkg_entry = tree
        .files
        .iter()
        .find(|f| f.path == "package.json")
        .expect("package.json present");
    let pkg: Value = serde_json::from_str(pkg_entry.content.as_deref().unwrap()).unwrap();
    assert_eq!(pkg["dependencies"]["core"], "1.0.0");

    for idx in 0..16usize {
        let expected_path = format!("agents/agent_{idx:02}.rs");
        let file = tree
            .files
            .iter()
            .find(|f| f.path == expected_path)
            .unwrap_or_else(|| panic!("missing {expected_path} after batch drain"));
        assert!(
            file.content
                .as_deref()
                .unwrap()
                .contains(&format!("pub fn agent_{idx:02}()"))
        );

        let dep_key = format!("pkg-agent-{idx:02}");
        assert_eq!(
            pkg["dependencies"][&dep_key],
            format!("1.0.{idx}"),
            "missing merged package.json key {dep_key}"
        );
    }

    // Enqueue a follow-up batch to verify strictly monotonic land_seq (1 -> 2)
    let c17: CommitResponse = client
        .post(srv.url("/v1/repos/acme/swarm/commit"))
        .header("X-Gitx-User", "agent-16")
        .json(&json!({
            "files": {
                "agents/agent_16.rs": "pub fn agent_16() -> usize { 16 }\n"
            },
            "parent": drain.new_head.as_deref().unwrap(),
            "update_target": false,
            "message": "Agent 16 follow-up"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    client
        .post(srv.url("/v1/repos/acme/swarm/queue/enqueue"))
        .header("X-Gitx-User", "agent-16")
        .json(&json!({ "changeset_id": c17.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let drain2: DrainResponse = client
        .post(srv.url("/v1/repos/acme/swarm/queue/drain"))
        .header("X-Gitx-User", "merge-bot")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(drain2.land_seq, Some(2));
    assert_eq!(drain2.landed.len(), 1);

    // Queue should now have 0 pending entries and 17 landed entries total
    let after_queue: QueueListResponse = client
        .get(srv.url("/v1/repos/acme/swarm/queue?target=master"))
        .header("X-Gitx-User", "merge-bot")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(after_queue.pending_count, 0);
    assert_eq!(after_queue.entries.len(), 17);

    // O(1) atomic revert of land_seq 2 restores the exact 16-agent batch head
    let rev: RevertResponse = client
        .post(srv.url("/v1/repos/acme/swarm/revert/2"))
        .header("X-Gitx-User", "merge-bot")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rev.revert_land_seq, 3);
    assert_eq!(rev.restored_head, drain.new_head.unwrap());
}

#[tokio::test]
async fn queue_drain_conflict_resolver_hook_and_skip_unresolvable_conflicts() {
    let client = Client::new();

    // -----------------------------------------------------------------------
    // Part A: Without a conflict resolver, unresolvable conflicts are skipped
    // without aborting clean entries in the same batch.
    // -----------------------------------------------------------------------
    let srv_no_hook = TestServer::start(None, None).await;

    let base_a: CommitResponse = client
        .post(srv_no_hook.url("/v1/repos/org/conflicts/commit"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "files": {
                "config.txt": "header\nmode=default\nfooter\n"
            },
            "message": "Base config"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let cs_a: CommitResponse = client
        .post(srv_no_hook.url("/v1/repos/org/conflicts/commit"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "files": {
                "config.txt": "header\nmode=alpha\nfooter\n"
            },
            "parent": base_a.changeset_id,
            "update_target": false,
            "message": "Set mode=alpha"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Deliberate same-line conflict with cs_a
    let cs_b: CommitResponse = client
        .post(srv_no_hook.url("/v1/repos/org/conflicts/commit"))
        .header("X-Gitx-User", "bob")
        .json(&json!({
            "files": {
                "config.txt": "header\nmode=beta\nfooter\n"
            },
            "parent": base_a.changeset_id,
            "update_target": false,
            "message": "Set mode=beta (conflicts with alpha)"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Clean unrelated change after the conflicted one
    let cs_c: CommitResponse = client
        .post(srv_no_hook.url("/v1/repos/org/conflicts/commit"))
        .header("X-Gitx-User", "carol")
        .json(&json!({
            "files": {
                "clean.rs": "pub const CLEAN: bool = true;\n"
            },
            "parent": base_a.changeset_id,
            "update_target": false,
            "message": "Add clean.rs"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    for (user, id) in [
        ("alice", &cs_a.changeset_id),
        ("bob", &cs_b.changeset_id),
        ("carol", &cs_c.changeset_id),
    ] {
        client
            .post(srv_no_hook.url("/v1/repos/org/conflicts/queue/enqueue"))
            .header("X-Gitx-User", user)
            .json(&json!({ "changeset_id": id, "target": "master" }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }

    let drain_a: DrainResponse = client
        .post(srv_no_hook.url("/v1/repos/org/conflicts/queue/drain"))
        .header("X-Gitx-User", "merge-bot")
        .json(&json!({ "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(drain_a.land_seq, Some(1));
    assert_eq!(drain_a.landed.len(), 2);
    assert_eq!(drain_a.conflicted.len(), 1);
    assert_eq!(drain_a.conflicted[0].changeset_id, cs_b.changeset_id);
    assert_eq!(
        drain_a.conflicted[0].status,
        QueueStatus::Conflicted {
            conflict_paths: vec!["config.txt".to_string()]
        }
    );

    let tree_a: TreeResponse = client
        .get(srv_no_hook.url("/v1/repos/org/conflicts/tree"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let cfg_a = tree_a
        .files
        .iter()
        .find(|f| f.path == "config.txt")
        .unwrap()
        .content
        .as_deref()
        .unwrap();
    assert_eq!(cfg_a, "header\nmode=alpha\nfooter\n");
    assert!(tree_a.files.iter().any(|f| f.path == "clean.rs"));

    // -----------------------------------------------------------------------
    // Part B: With ConflictResolverFn configured, the same-line conflict is
    // resolved automatically during /queue/drain and both entries land cleanly!
    // -----------------------------------------------------------------------
    let resolver: ConflictResolverFn = Arc::new(|path, _base, ours, theirs| {
        if path != "config.txt" {
            return None;
        }
        let ours_str = std::str::from_utf8(ours).ok()?;
        let theirs_str = std::str::from_utf8(theirs).ok()?;
        let ours_mode = ours_str
            .lines()
            .find_map(|l| l.strip_prefix("mode="))
            .unwrap_or("unknown");
        let theirs_mode = theirs_str
            .lines()
            .find_map(|l| l.strip_prefix("mode="))
            .unwrap_or("unknown");
        Some(format!("header\nmode={ours_mode}+{theirs_mode}\nfooter\n").into_bytes())
    });

    let srv_hook = TestServer::start(None, Some(resolver)).await;

    let base_b: CommitResponse = client
        .post(srv_hook.url("/v1/repos/org/resolved/commit"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "files": {
                "config.txt": "header\nmode=default\nfooter\n"
            },
            "message": "Base config"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let hook_a: CommitResponse = client
        .post(srv_hook.url("/v1/repos/org/resolved/commit"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "files": {
                "config.txt": "header\nmode=alpha\nfooter\n"
            },
            "parent": base_b.changeset_id,
            "update_target": false,
            "message": "Alpha mode"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let hook_b: CommitResponse = client
        .post(srv_hook.url("/v1/repos/org/resolved/commit"))
        .header("X-Gitx-User", "bob")
        .json(&json!({
            "files": {
                "config.txt": "header\nmode=beta\nfooter\n"
            },
            "parent": base_b.changeset_id,
            "update_target": false,
            "message": "Beta mode (same-line conflict)"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    for (user, id) in [
        ("alice", &hook_a.changeset_id),
        ("bob", &hook_b.changeset_id),
    ] {
        client
            .post(srv_hook.url("/v1/repos/org/resolved/queue/enqueue"))
            .header("X-Gitx-User", user)
            .json(&json!({ "changeset_id": id, "target": "master" }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }

    let drain_b: DrainResponse = client
        .post(srv_hook.url("/v1/repos/org/resolved/queue/drain"))
        .header("X-Gitx-User", "merge-bot")
        .json(&json!({ "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(drain_b.land_seq, Some(1));
    assert_eq!(drain_b.landed.len(), 2);
    assert!(drain_b.conflicted.is_empty());
    assert!(drain_b.rejected.is_empty());
    assert_eq!(drain_b.resolved_conflicts, vec!["config.txt"]);

    let tree_b: TreeResponse = client
        .get(srv_hook.url("/v1/repos/org/resolved/tree"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let cfg_b = tree_b
        .files
        .iter()
        .find(|f| f.path == "config.txt")
        .unwrap()
        .content
        .as_deref()
        .unwrap();
    assert_eq!(cfg_b, "header\nmode=alpha+beta\nfooter\n");
}

#[tokio::test]
async fn derived_trigram_cache_hits_blame_history_and_acl_isolation() {
    let acl = "packages/private/** -> team:core\n";
    let srv = TestServer::start(Some(acl), None).await;
    let client = Client::new();

    // 1. Public commit 1
    let c1: CommitResponse = client
        .post(srv.url("/v1/repos/t3/search/commit"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": {
                "src/lib.rs": "pub fn public_alpha() -> &'static str {\n    \"PUBLIC_DERIVED_TOKEN\"\n}\n",
                "README.md": "# Derived Data Demo\n"
            },
            "message": "Initial public library",
            "author_name": "Theo",
            "author_email": "theo@t3.gg"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // 2. Private team:core commit (must be strictly partitioned in TrigramIndex)
    client
        .post(srv.url("/v1/repos/t3/search/commit"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": {
                "packages/private/vault.rs": "pub const VAULT_SECRET: &str = \"TEAM_CORE_INDEXED_SECRET_42\";\n"
            },
            "message": "Add private core vault",
            "author_name": "Theo",
            "author_email": "theo@t3.gg"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // 3. Public commit 2 modifying src/lib.rs (for PathHistoryIndex / blame test)
    let c3: CommitResponse = client
        .post(srv.url("/v1/repos/t3/search/commit"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "files": {
                "src/lib.rs": "pub fn public_alpha() -> &'static str {\n    \"PUBLIC_DERIVED_TOKEN\"\n}\n\npub fn public_beta() -> usize {\n    42\n}\n"
            },
            "message": "Add public_beta",
            "author_name": "Alice",
            "author_email": "alice@t3.gg"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Cold grep by authorized `team:core` user -> populates TrigramIndex for both public & team:core
    let g1: GrepResponse = client
        .get(srv.url("/v1/repos/t3/search/grep?q=TEAM_CORE_INDEXED_SECRET_42"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(g1.matches.len(), 1);
    assert_eq!(g1.matches[0].path, "packages/private/vault.rs");
    assert_eq!(g1.matches[0].domain, "team:core");

    let stats_cold: DerivedStats = client
        .get(srv.url("/v1/repos/t3/search/derived/stats"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats_cold.trigram_indexed_trees, 2);
    assert_eq!(stats_cold.trigram_cache_misses, 2);
    assert_eq!(stats_cold.trigram_cache_hits, 0);
    assert!(stats_cold.trigram_domains.contains(&"public".to_string()));
    assert!(stats_cold.trigram_domains.contains(&"team:core".to_string()));
    assert!(stats_cold.trigram_total_postings > 0);

    // Warm grep by authorized `team:core` user -> cache HIT on both trees!
    let g2: GrepResponse = client
        .get(srv.url("/v1/repos/t3/search/grep?q=TEAM_CORE_INDEXED_SECRET_42"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(g2.matches.len(), 1);

    let stats_warm: DerivedStats = client
        .get(srv.url("/v1/repos/t3/search/derived/stats"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats_warm.trigram_cache_misses, 2);
    assert_eq!(stats_warm.trigram_cache_hits, 2);

    // STRICT ACL ISOLATION:
    // Anonymous /grep for the ALREADY-INDEXED team:core string MUST return ZERO matches!
    let anon_secret_grep: GrepResponse = client
        .get(srv.url("/v1/repos/t3/search/grep?q=TEAM_CORE_INDEXED_SECRET_42"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        anon_secret_grep.matches.is_empty(),
        "anonymous /grep leaked indexed team:core content: {:?}",
        anon_secret_grep.matches
    );

    // Anonymous /grep for public token succeeds and hits the public trigram cache!
    let anon_pub_grep: GrepResponse = client
        .get(srv.url("/v1/repos/t3/search/grep?q=PUBLIC_DERIVED_TOKEN"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(anon_pub_grep.matches.len(), 1);
    assert_eq!(anon_pub_grep.matches[0].path, "src/lib.rs");

    // Anonymous /derived/stats MUST ONLY expose `public` domain metadata (never `team:core`)!
    let anon_stats: DerivedStats = client
        .get(srv.url("/v1/repos/t3/search/derived/stats"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(anon_stats.trigram_domains, vec!["public"]);
    assert_eq!(anon_stats.trigram_indexed_trees, 1);
    assert!(anon_stats.trigram_cache_hits >= 2);

    // PathHistoryIndex & CommitGraphIndex acceleration on /blame
    let blame1: BlameResponse = client
        .get(srv.url("/v1/repos/t3/search/blame?path=src/lib.rs"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(blame1.lines.len(), 7);
    assert_eq!(blame1.lines[0].author_name, "Theo");
    assert_eq!(blame1.lines[0].changeset_id, c1.changeset_id);
    assert_eq!(blame1.lines[4].author_name, "Alice");
    assert_eq!(blame1.lines[4].changeset_id, c3.changeset_id);

    // Repeat blame -> PathHistoryIndex cache hit!
    let blame2: BlameResponse = client
        .get(srv.url("/v1/repos/t3/search/blame?path=src/lib.rs"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(blame2.lines.len(), 7);

    let stats_after_blame: DerivedStats = client
        .get(srv.url("/v1/repos/t3/search/derived/stats"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats_after_blame.path_history_entries, 1);
    assert_eq!(stats_after_blame.path_history_cache_misses, 1);
    assert_eq!(stats_after_blame.path_history_cache_hits, 1);
    assert!(stats_after_blame.commit_graph_nodes >= 2);
}
