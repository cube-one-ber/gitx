use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use gitx_server::{
    BlameResponse, CommitResponse, CreateRepoResponse, DiffResponse, GrepResponse, HealthResponse,
    LandResponse, ListReposResponse, LogResponse, PublishEmbargoResponse, RevertResponse,
    ServerConfig, TreeResponse, WhyResponse, serve,
};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::task::JoinHandle;

struct TestServer {
    addr: SocketAddr,
    _tmp: TempDir,
    handle: JoinHandle<()>,
}

impl TestServer {
    async fn start(default_acl: Option<&str>) -> Self {
        let tmp = TempDir::new().expect("temp dir");
        let mut config = ServerConfig::new(tmp.path());
        if let Some(acl) = default_acl {
            config = config.with_default_acl(acl);
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

#[tokio::test]
async fn push_to_create_and_zero_clone_operations() {
    let srv = TestServer::start(None).await;
    let client = Client::new();

    // 1. Health check
    let health: HealthResponse = client
        .get(srv.url("/health"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health.status, "ok");

    // 2. Push-to-create: commit directly to a brand-new repo without calling create_repo first!
    let c1: CommitResponse = client
        .post(srv.url("/v1/repos/acme/alpha/commit"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "files": {
                "src/lib.rs": "pub fn greet() -> &'static str {\n    \"hello\"\n}\n",
                "assets/note.txt": format!("base64:{}", BASE64_STANDARD.encode("encoded-payload\n"))
            },
            "message": "Initial zero-clone commit",
            "author_name": "Alice",
            "author_email": "alice@acme.dev",
            "actor_agent": {
                "harness": "claude-code",
                "model": "claude-opus",
                "session_id": "sess-001"
            },
            "context_prompt": "Create the greeting helper for the public SDK"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!c1.changeset_id.is_empty());
    assert_eq!(c1.domains_written, vec!["public"]);

    // Verify repo listing includes push-to-created repo
    let repos: ListReposResponse = client
        .get(srv.url("/v1/repos"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(repos.repos.len(), 1);
    assert_eq!(repos.repos[0].full_name, "acme/alpha");

    let scoped_repos: ListReposResponse = client
        .get(srv.url("/v1/repos/acme/alpha/repos"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(scoped_repos.repos.len(), 1);

    // 3. Second commit modifying src/lib.rs
    let c2: CommitResponse = client
        .post(srv.url("/v1/repos/acme/alpha/commit"))
        .header("X-Gitx-User", "bob")
        .json(&json!({
            "files": {
                "src/lib.rs": "pub fn greet() -> &'static str {\n    \"hello\"\n}\n\npub fn farewell() -> &'static str {\n    \"bye\"\n}\n"
            },
            "message": "Add farewell helper",
            "author_name": "Bob",
            "author_email": "bob@acme.dev",
            "context_prompt": "Add matching farewell helper alongside greet"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // 4. Tree check (base64 file decoded cleanly)
    let tree: TreeResponse = client
        .get(srv.url("/v1/repos/acme/alpha/tree"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let note = tree
        .files
        .iter()
        .find(|f| f.path == "assets/note.txt")
        .expect("note.txt in tree");
    assert_eq!(note.content.as_deref(), Some("encoded-payload\n"));

    // 5. Diff between c1 and c2
    let diff: DiffResponse = client
        .get(srv.url(&format!(
            "/v1/repos/acme/alpha/diff?from={}&to={}",
            c1.changeset_id, c2.changeset_id
        )))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(diff.files.len(), 1);
    assert_eq!(diff.files[0].path, "src/lib.rs");
    assert_eq!(diff.files[0].status, "modified");
    assert!(diff.unified_diff.contains("+pub fn farewell()"));

    // 6. Grep
    let grep_res: GrepResponse = client
        .get(srv.url("/v1/repos/acme/alpha/grep?q=farewell"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(grep_res.matches.len(), 1);
    assert_eq!(grep_res.matches[0].path, "src/lib.rs");
    assert_eq!(grep_res.matches[0].line_number, 5);

    // 7. Blame (lines 1-3 -> Alice/c1, lines 5-7 -> Bob/c2)
    let blame_res: BlameResponse = client
        .get(srv.url("/v1/repos/acme/alpha/blame?path=src/lib.rs"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(blame_res.lines.len(), 7);
    assert_eq!(blame_res.lines[0].author_name, "Alice");
    assert_eq!(blame_res.lines[0].changeset_id, c1.changeset_id);
    assert_eq!(blame_res.lines[4].author_name, "Bob");
    assert_eq!(blame_res.lines[4].changeset_id, c2.changeset_id);

    // 8. Log
    let log_res: LogResponse = client
        .get(srv.url("/v1/repos/acme/alpha/log?limit=10"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(log_res.commits.len(), 2);
    assert_eq!(log_res.commits[0].changeset_id, c2.changeset_id);
    assert_eq!(log_res.commits[1].changeset_id, c1.changeset_id);

    // 9. Why (durable context query)
    let why_res: WhyResponse = client
        .get(srv.url("/v1/repos/acme/alpha/why?path=src/lib.rs&line=2"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!why_res.matches.is_empty());
    let prompts: Vec<String> = why_res
        .matches
        .iter()
        .filter_map(|m| match &m.record.kind {
            gitx_context::ContextKind::Prompt { prompt, .. } => Some(prompt.clone()),
            _ => None,
        })
        .collect();
    assert!(
        prompts
            .iter()
            .any(|p| p.contains("Create the greeting helper")),
        "expected initial prompt in why matches, got {prompts:?}"
    );
}

#[tokio::test]
async fn strict_acl_isolation_and_embargo_publish() {
    let acl = "packages/private/** -> team:core\n";
    let srv = TestServer::start(Some(acl)).await;
    let client = Client::new();

    // 1. Public commit
    let c_pub: CommitResponse = client
        .post(srv.url("/v1/repos/t3/mono/commit"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .json(&json!({
            "files": {
                "src/main.rs": "fn main() {\n    println!(\"PUBLIC_MARKER_OK\");\n}\n"
            },
            "message": "Public entrypoint",
            "author_name": "Theo",
            "author_email": "theo@t3.gg",
            "context_prompt": "PUBLIC_WHY_CONTEXT bootstrap app"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(c_pub.domains_written, vec!["public"]);

    // 2. Private team:core commit
    let c_priv: CommitResponse = client
        .post(srv.url("/v1/repos/t3/mono/commit"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .json(&json!({
            "files": {
                "packages/private/secret.rs": "pub const INTERNAL_ALGO: &str = \"TOP_SECRET_CORE_TOKEN\";\n"
            },
            "message": "Add private core algorithm",
            "author_name": "Theo",
            "author_email": "theo@t3.gg",
            "context_prompt": "PRIVATE_WHY_CONTEXT internal billing formula"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(c_priv.domains_written, vec!["team:core"]);

    // 3. Embargoed CVE security fix commit
    let c_emb: CommitResponse = client
        .post(srv.url("/v1/repos/t3/mono/commit"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .json(&json!({
            "files": {
                "src/security_fix.rs": "pub fn patch_cve() -> &'static str {\n    \"EMBARGO_CVE_2026_99_FIX\"\n}\n"
            },
            "message": "Embargoed fix for CVE-2026-99",
            "author_name": "Theo",
            "author_email": "theo@t3.gg",
            "embargo_advisory": "cve-2026-99",
            "embargo_allowed_teams": ["security"],
            "context_prompt": "EMBARGO_WHY_CONTEXT fix auth bypass before disclosure"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(c_emb.domains_written, vec!["embargo:cve-2026-99"]);

    // ---- ANONYMOUS REQUESTS: must see ZERO private or embargo data ----
    let anon_tree: TreeResponse = client
        .get(srv.url("/v1/repos/t3/mono/tree"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let anon_paths: Vec<&str> = anon_tree.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(anon_paths, vec!["src/main.rs"]);

    // Anonymous grep for private token and embargo token -> ZERO matches
    for needle in ["TOP_SECRET_CORE_TOKEN", "EMBARGO_CVE_2026_99_FIX"] {
        let g: GrepResponse = client
            .get(srv.url(&format!("/v1/repos/t3/mono/grep?q={needle}")))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            g.matches.is_empty(),
            "anonymous grep leaked {needle}: {:?}",
            g.matches
        );
    }

    // Anonymous diff from public commit to master/embargo -> ZERO private/embargo diffs
    let anon_diff: DiffResponse = client
        .get(srv.url(&format!(
            "/v1/repos/t3/mono/diff?from={}&to={}",
            c_pub.changeset_id, c_emb.changeset_id
        )))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(anon_diff.files.is_empty());
    assert!(anon_diff.unified_diff.is_empty());

    // Anonymous log -> ONLY public commit, zero private/embargo commit messages
    let anon_log: LogResponse = client
        .get(srv.url("/v1/repos/t3/mono/log"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(anon_log.commits.len(), 1);
    assert_eq!(anon_log.commits[0].changeset_id, c_pub.changeset_id);
    assert!(!anon_log.commits[0].message.contains("CVE"));

    // Anonymous why on private and embargo paths -> ZERO matches
    for path in ["packages/private/secret.rs", "src/security_fix.rs"] {
        let w: WhyResponse = client
            .get(srv.url(&format!("/v1/repos/t3/mono/why?path={path}&line=1")))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(w.matches.is_empty(), "anonymous why leaked {path}");
    }

    // Anonymous blame on private path -> 404 (not leaked)
    let anon_blame = client
        .get(srv.url("/v1/repos/t3/mono/blame?path=packages/private/secret.rs"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon_blame.status(), StatusCode::NOT_FOUND);

    // Anonymous attempt to publish embargo -> 403 Forbidden
    let anon_pub = client
        .post(srv.url("/v1/repos/t3/mono/embargo/cve-2026-99/publish"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon_pub.status(), StatusCode::FORBIDDEN);

    // ---- AUTHORIZED REQUESTS (theo in core,security): sees public + team:core + embargo ----
    let theo_tree: TreeResponse = client
        .get(srv.url("/v1/repos/t3/mono/tree"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let theo_paths: Vec<&str> = theo_tree.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        theo_paths,
        vec![
            "packages/private/secret.rs",
            "src/main.rs",
            "src/security_fix.rs"
        ]
    );

    let theo_grep_priv: GrepResponse = client
        .get(srv.url("/v1/repos/t3/mono/grep?q=TOP_SECRET_CORE_TOKEN"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(theo_grep_priv.matches.len(), 1);

    let theo_grep_emb: GrepResponse = client
        .get(srv.url("/v1/repos/t3/mono/grep?q=EMBARGO_CVE_2026_99_FIX"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(theo_grep_emb.matches.len(), 1);

    let theo_diff: DiffResponse = client
        .get(srv.url(&format!(
            "/v1/repos/t3/mono/diff?from={}&to={}",
            c_pub.changeset_id, c_emb.changeset_id
        )))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(theo_diff.files.len(), 2);
    assert!(theo_diff.unified_diff.contains("TOP_SECRET_CORE_TOKEN"));
    assert!(theo_diff.unified_diff.contains("EMBARGO_CVE_2026_99_FIX"));

    let theo_log: LogResponse = client
        .get(srv.url("/v1/repos/t3/mono/log"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(theo_log.commits.len(), 3);

    let theo_why_priv: WhyResponse = client
        .get(srv.url("/v1/repos/t3/mono/why?path=packages/private/secret.rs&line=1"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(theo_why_priv.matches.len(), 1);

    let theo_why_emb: WhyResponse = client
        .get(srv.url("/v1/repos/t3/mono/why?path=src/security_fix.rs&line=1"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(theo_why_emb.matches.len(), 1);

    // ---- PUBLISH EMBARGO: now anonymous sees src/security_fix.rs, still ZERO team:core ----
    let pub_res: PublishEmbargoResponse = client
        .post(srv.url("/v1/repos/t3/mono/embargo/cve-2026-99/publish"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pub_res.advisory, "cve-2026-99");
    assert_eq!(pub_res.promoted_paths, vec!["src/security_fix.rs"]);

    let anon_tree_after: TreeResponse = client
        .get(srv.url("/v1/repos/t3/mono/tree"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let anon_paths_after: Vec<&str> = anon_tree_after
        .files
        .iter()
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(anon_paths_after, vec!["src/main.rs", "src/security_fix.rs"]);
}

#[tokio::test]
async fn secret_scanner_rejects_unlabelled_secrets_in_public() {
    let srv = TestServer::start(None).await;
    let client = Client::new();

    // Unlabelled AWS key into public -> 400 Bad Request with redacted findings
    let resp = client
        .post(srv.url("/v1/repos/sec/app/commit"))
        .header("X-Gitx-User", "dev")
        .json(&json!({
            "files": {
                "src/config.rs": "pub const AWS_KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";\n"
            },
            "message": "Accidental AWS key leak",
            "author_name": "Dev",
            "author_email": "dev@sec.io"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "secret_detected");
    assert!(!body["findings"].as_array().unwrap().is_empty());
    // Ensure raw secret value is NOT echoed in error payload
    assert!(!body.to_string().contains("AKIAIOSFODNN7EXAMPLE"));

    // Unlabelled sk-... API key forced into public -> 400 Bad Request
    let resp2 = client
        .post(srv.url("/v1/repos/sec/app/commit"))
        .header("X-Gitx-User", "dev")
        .json(&json!({
            "files": {
                "src/ai.rs": "const OPENAI: &str = \"sk-proj1234567890abcdef\";\n"
            },
            "message": "Accidental API key leak",
            "author_name": "Dev",
            "author_email": "dev@sec.io",
            "visibility_domain": "public"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);

    // Same file routed explicitly to secret:prod -> succeeds!
    let ok_secret: CommitResponse = client
        .post(srv.url("/v1/repos/sec/app/commit"))
        .header("X-Gitx-User", "dev")
        .json(&json!({
            "files": {
                "secrets/prod.env": "API_KEY=sk-proj1234567890abcdef\n"
            },
            "message": "Store prod key in secret domain",
            "author_name": "Dev",
            "author_email": "dev@sec.io",
            "visibility_domain": "secret:prod"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ok_secret.domains_written, vec!["secret:prod"]);

    // Anonymous cannot see secret:prod
    let anon_tree: TreeResponse = client
        .get(srv.url("/v1/repos/sec/app/tree"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(anon_tree.files.is_empty());
}

#[tokio::test]
async fn transactional_land_semantic_automerge_and_atomic_revert() {
    let srv = TestServer::start(None).await;
    let client = Client::new();

    // Explicit idempotent repo creation
    let created: CreateRepoResponse = client
        .post(srv.url("/v1/repos/org/merge-demo"))
        .header("X-Gitx-User", "alice")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created.repo.full_name, "org/merge-demo");

    // Base commit on master with JSON and TOML files
    let base: CommitResponse = client
        .post(srv.url("/v1/repos/org/merge-demo/commit"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "files": {
                "config.json": "{\n  \"alpha\": 1,\n  \"beta\": 2\n}\n",
                "settings.toml": "[service]\nport = 8080\nhost = \"127.0.0.1\"\n"
            },
            "message": "Base config",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Concurrent change A (based on `base`, staged without moving master)
    let change_a: CommitResponse = client
        .post(srv.url("/v1/repos/org/merge-demo/commit"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "files": {
                "config.json": "{\n  \"alpha\": 10,\n  \"beta\": 2\n}\n",
                "settings.toml": "[service]\nport = 9090\nhost = \"127.0.0.1\"\n"
            },
            "parent": base.changeset_id,
            "update_target": false,
            "message": "Update alpha and port",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Concurrent change B (also based on `base`, modifying disjoint keys in same JSON & TOML files!)
    let change_b: CommitResponse = client
        .post(srv.url("/v1/repos/org/merge-demo/commit"))
        .header("X-Gitx-User", "bob")
        .json(&json!({
            "files": {
                "config.json": "{\n  \"alpha\": 1,\n  \"beta\": 20,\n  \"gamma\": true\n}\n",
                "settings.toml": "[service]\nport = 8080\nhost = \"0.0.0.0\"\n"
            },
            "parent": base.changeset_id,
            "update_target": false,
            "message": "Update beta/gamma and host",
            "author_name": "Bob",
            "author_email": "bob@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Land change A (fast-forward)
    let land1: LandResponse = client
        .post(srv.url("/v1/repos/org/merge-demo/land"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "changeset_id": change_a.changeset_id,
            "target": "master",
            "expected_head": base.changeset_id
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(land1.land_seq, 1);
    assert_eq!(land1.new_head, change_a.changeset_id);
    assert!(land1.conflicts.is_empty());

    // Stale expected_head fails with 409 Conflict (optimistic CAS)
    let stale = client
        .post(srv.url("/v1/repos/org/merge-demo/land"))
        .header("X-Gitx-User", "bob")
        .json(&json!({
            "changeset_id": change_b.changeset_id,
            "target": "master",
            "expected_head": base.changeset_id
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);

    // Land change B against moved master -> automatic 3-way semantic JSON + TOML merge!
    let land2: LandResponse = client
        .post(srv.url("/v1/repos/org/merge-demo/land"))
        .header("X-Gitx-User", "bob")
        .json(&json!({
            "changeset_id": change_b.changeset_id,
            "target": "master",
            "expected_head": land1.new_head
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(land2.land_seq, 2);
    assert!(land2.conflicts.is_empty());
    assert_ne!(land2.new_head, change_b.changeset_id);

    // Inspect merged tree: BOTH alpha=10 and beta=20/gamma=true, BOTH port=9090 and host="0.0.0.0"!
    let merged_tree: TreeResponse = client
        .get(srv.url("/v1/repos/org/merge-demo/tree"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let json_content = merged_tree
        .files
        .iter()
        .find(|f| f.path == "config.json")
        .unwrap()
        .content
        .as_ref()
        .unwrap();
    let parsed_json: Value = serde_json::from_str(json_content).unwrap();
    assert_eq!(parsed_json["alpha"], 10);
    assert_eq!(parsed_json["beta"], 20);
    assert_eq!(parsed_json["gamma"], true);

    let toml_content = merged_tree
        .files
        .iter()
        .find(|f| f.path == "settings.toml")
        .unwrap()
        .content
        .as_ref()
        .unwrap();
    assert!(toml_content.contains("port = 9090"));
    assert!(toml_content.contains("host = \"0.0.0.0\""));

    // O(1) Atomic Revert of land_seq 2 -> restores master to land1.new_head (change_a)!
    let revert: RevertResponse = client
        .post(srv.url("/v1/repos/org/merge-demo/revert/2"))
        .header("X-Gitx-User", "alice")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(revert.reverted_land_seq, 2);
    assert_eq!(revert.revert_land_seq, 3);
    assert_eq!(revert.restored_head, land1.new_head);

    let reverted_tree: TreeResponse = client
        .get(srv.url("/v1/repos/org/merge-demo/tree"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let rev_json: Value = serde_json::from_str(
        reverted_tree
            .files
            .iter()
            .find(|f| f.path == "config.json")
            .unwrap()
            .content
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rev_json["alpha"], 10);
    assert_eq!(rev_json["beta"], 2);
    assert!(rev_json.get("gamma").is_none());

    // Double revert returns 409 Conflict
    let double_revert = client
        .post(srv.url("/v1/repos/org/merge-demo/revert/2"))
        .header("X-Gitx-User", "alice")
        .send()
        .await
        .unwrap();
    assert_eq!(double_revert.status(), StatusCode::CONFLICT);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_smart_http_clone_enforces_acl_and_passes_fsck() {
    let acl = "packages/private/** -> team:core\n";
    let srv = TestServer::start(Some(acl)).await;
    let client = Client::new();

    // 1. Public commit
    client
        .post(srv.url("/v1/repos/t3/demo/commit"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .json(&json!({
            "files": {
                "src/main.rs": "fn main() { println!(\"hello public git\"); }\n",
                "README.md": "# Demo Repo\n"
            },
            "message": "Initial public commit",
            "author_name": "Theo",
            "author_email": "theo@t3.gg"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // 2. Private team:core commit + .env secret (auto-routed to secret:dev)
    client
        .post(srv.url("/v1/repos/t3/demo/commit"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .json(&json!({
            "files": {
                "packages/private/secret.rs": "pub fn internal_only() {}\n",
                ".env": "DATABASE_URL=postgres://secret:pass@localhost/db\n"
            },
            "message": "Private core module and dev env",
            "author_name": "Theo",
            "author_email": "theo@t3.gg"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // 3. Embargoed CVE commit
    client
        .post(srv.url("/v1/repos/t3/demo/commit"))
        .header("X-Gitx-User", "theo")
        .header("X-Gitx-Teams", "core,security")
        .json(&json!({
            "files": {
                "src/cve_patch.rs": "pub fn zero_day_fix() {}\n"
            },
            "message": "Embargoed zero-day fix",
            "author_name": "Theo",
            "author_email": "theo@t3.gg",
            "embargo_advisory": "cve-2026-99",
            "embargo_allowed_teams": ["security"]
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // ---- Anonymous `git clone http://127.0.0.1:<port>/t3/demo.git` ----
    let clone_tmp = TempDir::new().unwrap();
    let anon_clone_dir = clone_tmp.path().join("anon-demo");
    let clone_url = srv.url("/t3/demo.git");

    let clone_out = Command::new("git")
        .args(["clone", &clone_url])
        .arg(&anon_clone_dir)
        .output()
        .await
        .expect("spawn git clone");
    assert!(
        clone_out.status.success(),
        "anonymous git clone failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&clone_out.stdout),
        String::from_utf8_lossy(&clone_out.stderr)
    );

    // Verify `git fsck --full --strict` passes cleanly
    let fsck_out = Command::new("git")
        .args(["fsck", "--full", "--strict"])
        .current_dir(&anon_clone_dir)
        .output()
        .await
        .expect("spawn git fsck");
    assert!(
        fsck_out.status.success(),
        "git fsck failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&fsck_out.stdout),
        String::from_utf8_lossy(&fsck_out.stderr)
    );

    // Public files exist; private, secret, and embargoed files are COMPLETELY ABSENT
    assert!(anon_clone_dir.join("src/main.rs").is_file());
    assert!(anon_clone_dir.join("README.md").is_file());
    assert!(!anon_clone_dir.join("packages/private/secret.rs").exists());
    assert!(!anon_clone_dir.join(".env").exists());
    assert!(!anon_clone_dir.join("src/cve_patch.rs").exists());

    // Git log in anonymous clone contains ONLY the 1 public commit (no private/embargo history)
    let log_out = Command::new("git")
        .args(["log", "--all", "--format=%s"])
        .current_dir(&anon_clone_dir)
        .output()
        .await
        .expect("spawn git log");
    assert!(log_out.status.success());
    let log_str = String::from_utf8_lossy(&log_out.stdout);
    let subjects: Vec<&str> = log_str.lines().collect();
    assert_eq!(subjects, vec!["Initial public commit"]);

    // ---- Authorized `git clone` for theo (team:core + team:security) ----
    let auth_clone_dir = clone_tmp.path().join("theo-demo");
    let auth_clone_out = Command::new("git")
        .args([
            "-c",
            "http.extraHeader=X-Gitx-User: theo",
            "-c",
            "http.extraHeader=X-Gitx-Teams: core,security",
            "clone",
            &clone_url,
        ])
        .arg(&auth_clone_dir)
        .output()
        .await
        .expect("spawn authenticated git clone");
    assert!(
        auth_clone_out.status.success(),
        "authenticated git clone failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&auth_clone_out.stdout),
        String::from_utf8_lossy(&auth_clone_out.stderr)
    );

    let auth_fsck = Command::new("git")
        .args(["fsck", "--full", "--strict"])
        .current_dir(&auth_clone_dir)
        .output()
        .await
        .expect("spawn git fsck");
    assert!(auth_fsck.status.success());

    // Theo receives public + team:core + embargo fix, and still never `.env` (secret:dev requires explicit read grant)
    assert!(auth_clone_dir.join("src/main.rs").is_file());
    assert!(auth_clone_dir.join("packages/private/secret.rs").is_file());
    assert!(auth_clone_dir.join("src/cve_patch.rs").is_file());
    assert!(!auth_clone_dir.join(".env").exists());
}

#[tokio::test]
async fn security_acl_self_auth_bearer_tokens_embargo_and_queue_isolation() {
    use gitx_crypto::Principal;

    // 1. Bearer token server disables X-Gitx-* proxy header trust by default
    let tmp_tok = TempDir::new().expect("temp dir");
    let config_tok = ServerConfig::new(tmp_tok.path())
        .with_token(
            "alice-token-123",
            Principal::user("alice").with_team("core"),
        )
        .with_token(
            "admin-token-456",
            Principal::user("root").with_role("admin"),
        );
    let listener_tok = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_tok = listener_tok.local_addr().unwrap();
    let handle_tok = tokio::spawn(async move {
        let _ = serve(listener_tok, config_tok).await;
    });
    let tok_url = |p: &str| format!("http://{addr_tok}{p}");
    let client = Client::new();

    // Spoofing X-Gitx-Roles: admin without Bearer token is treated as anonymous and rejected on write
    let spoof_res = client
        .post(tok_url("/v1/repos/sec/tokrepo"))
        .header("X-Gitx-User", "attacker")
        .header("X-Gitx-Roles", "admin")
        .send()
        .await
        .unwrap();
    assert_eq!(spoof_res.status(), StatusCode::FORBIDDEN);

    // Invalid Bearer token returns 401 Unauthorized (including on GET /v1/repos)
    let bad_tok = client
        .post(tok_url("/v1/repos/sec/tokrepo"))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_tok.status(), StatusCode::UNAUTHORIZED);

    let bad_list = client
        .get(tok_url("/v1/repos"))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_list.status(), StatusCode::UNAUTHORIZED);

    // Valid Bearer token creates repo
    let ok_tok = client
        .post(tok_url("/v1/repos/sec/tokrepo"))
        .header("Authorization", "Bearer alice-token-123")
        .send()
        .await
        .unwrap();
    assert!(ok_tok.status().is_success());

    // Non-admin cannot self-authorize by submitting a permissive .gitxacl in POST /commit
    let self_auth = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "files": {
                ".gitxacl": "path ** -> public\ndomain public read=* write=*\n",
                "packages/private/loot.rs": "pub fn pwn() {}\n"
            },
            "message": "Attempt .gitxacl self-authorization",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(self_auth.status(), StatusCode::FORBIDDEN);

    // Non-admin cannot overwrite .gitxacl via create_repo on an existing repo
    let overwrite_acl = client
        .post(tok_url("/v1/repos/sec/tokrepo"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "acl": "path ** -> public\ndomain public read=* write=*\n"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(overwrite_acl.status(), StatusCode::FORBIDDEN);

    // Admin token CAN update .gitxacl
    let admin_acl = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer admin-token-456")
        .json(&json!({
            "files": {
                ".gitxacl": "path ** -> public\npath packages/private/** -> team:core\npath .env* -> secret:dev\ndomain public read=* write=authenticated\ndomain team:core read=team:core write=team:core\ndomain team:security read=team:security write=team:security\n",
                "README.md": "# Token Repo\n"
            },
            "message": "Admin initializes ACL",
            "author_name": "Root",
            "author_email": "root@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert!(admin_acl.status().is_success());

    // Non-admin cannot downgrade a team:core path using visibility_domain: "public"
    let downgrade_res = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "files": {
                "packages/private/core.rs": "pub fn secret_core() {}\n"
            },
            "visibility_domain": "public",
            "message": "Attempt path downgrade",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(downgrade_res.status(), StatusCode::FORBIDDEN);

    // Non-admin can drop a new secret into unconfigured secret:dev, but cannot overwrite or delete it
    let _first_secret: CommitResponse = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "files": {
                ".env": "SECRET=one\n"
            },
            "message": "Create initial secret",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let overwrite_secret = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "files": {
                ".env": "SECRET=hijacked\n"
            },
            "message": "Overwrite existing secret",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(overwrite_secret.status(), StatusCode::FORBIDDEN);

    // Non-admin cannot overwrite or shadow an existing secret in an unconfigured `secret:*` tree
    // by submitting that path under `visibility_domain: "public"`
    let custom_secret = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "files": { "notes.txt": "SECRET_DROPBOX_NOTE=1\n" },
            "visibility_domain": "secret:dropbox",
            "message": "Drop custom secret note",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert!(custom_secret.status().is_success());

    let shadow_secret_via_pub = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "files": { "notes.txt": "public shadow attempt\n" },
            "visibility_domain": "public",
            "message": "Shadow secret via public",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(shadow_secret_via_pub.status(), StatusCode::FORBIDDEN);

    // Non-admin cannot delete existing dropbox secret via delete_files + visibility_domain: "public"
    let delete_secret_via_pub = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "delete_files": [".env"],
            "visibility_domain": "public",
            "message": "Attempt secret delete bypass",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(delete_secret_via_pub.status(), StatusCode::FORBIDDEN);

    // Non-admin cannot delete a dropbox secret by reverting the land that added it
    // (even when the landed changeset's primary domain is `public` and readable by the caller).
    let staged_secret: CommitResponse = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "files": {
                "README.md": "# Token Repo with staged secret\n",
                ".env.staging": "SECRET=staged\n"
            },
            "update_target": false,
            "message": "Stage public doc and second secret",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let landed_secret: LandResponse = client
        .post(tok_url("/v1/repos/sec/tokrepo/land"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "changeset_id": staged_secret.changeset_id,
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
    let revert_secret_land = client
        .post(tok_url(&format!(
            "/v1/repos/sec/tokrepo/revert/{}",
            landed_secret.land_seq
        )))
        .header("Authorization", "Bearer alice-token-123")
        .send()
        .await
        .unwrap();
    assert_eq!(revert_secret_land.status(), StatusCode::FORBIDDEN);

    // Non-admin cannot overwrite an existing dropbox secret via embargo publish
    let emb_secret_overwrite = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "files": { ".env": "SECRET=embargo-hijack\n" },
            "embargo_advisory": "cve-2026-sec-overwrite",
            "embargo_allowed_teams": ["core"],
            "message": "Embargo containing .env",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert!(emb_secret_overwrite.status().is_success());

    let publish_secret_overwrite = client
        .post(tok_url(
            "/v1/repos/sec/tokrepo/embargo/cve-2026-sec-overwrite/publish",
        ))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({ "target": "master" }))
        .send()
        .await
        .unwrap();
    assert_eq!(publish_secret_overwrite.status(), StatusCode::FORBIDDEN);

    // Commit a team:core changeset, then verify anonymous cannot probe its hash or parent it
    let core_cs: CommitResponse = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "files": {
                "packages/private/core.rs": "pub fn core_only() {}\n"
            },
            "message": "Core commit",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let probe_hidden: TreeResponse = client
        .get(tok_url(&format!(
            "/v1/repos/sec/tokrepo/tree?rev={}",
            &core_cs.changeset_id[..12]
        )))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(probe_hidden.rev.is_none());
    assert!(probe_hidden.files.is_empty());

    // Empty embargo_allowed_teams is rejected for non-admin
    let empty_embargo = client
        .post(tok_url("/v1/repos/sec/tokrepo/commit"))
        .header("Authorization", "Bearer alice-token-123")
        .json(&json!({
            "files": {
                "src/fix.rs": "pub fn fix() {}\n"
            },
            "embargo_advisory": "cve-2026-empty",
            "embargo_allowed_teams": [],
            "message": "Empty embargo",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(empty_embargo.status(), StatusCode::FORBIDDEN);

    handle_tok.abort();

    // 2. Embargo publish ACL (read-only viewer denied, double-publish 409),
    //    non-tip revert_land 409, and queue/drain embargo isolation
    let srv = TestServer::start(Some(
        "path ** -> public\n\
         domain public read=* write=authenticated\n\
         domain team:security read=team:security,user:auditor write=team:security\n",
    ))
    .await;

    let base: CommitResponse = client
        .post(srv.url("/v1/repos/sec/embargo-demo/commit"))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .json(&json!({
            "files": { "src/app.rs": "fn main() {}\n" },
            "message": "Base",
            "author_name": "SecEng",
            "author_email": "sec@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Create staged public commit and staged embargo commit on the same base
    let pub_staged: CommitResponse = client
        .post(srv.url("/v1/repos/sec/embargo-demo/commit"))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .json(&json!({
            "files": { "src/docs.rs": "pub const DOC: &str = \"ok\";\n" },
            "parent": base.changeset_id,
            "update_target": false,
            "message": "Public doc",
            "author_name": "SecEng",
            "author_email": "sec@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let emb_staged: CommitResponse = client
        .post(srv.url("/v1/repos/sec/embargo-demo/commit"))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .json(&json!({
            "files": { "src/patch.rs": "pub fn zero_day() {}\n" },
            "parent": base.changeset_id,
            "update_target": false,
            "embargo_advisory": "cve-2026-42",
            "embargo_allowed_teams": ["security"],
            "message": "Embargoed fix",
            "author_name": "SecEng",
            "author_email": "sec@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Enqueue both and drain with max_batch_size=8: drain MUST NOT merge embargo into public batch!
    client
        .post(srv.url("/v1/repos/sec/embargo-demo/queue/enqueue"))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .json(&json!({ "changeset_id": pub_staged.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    client
        .post(srv.url("/v1/repos/sec/embargo-demo/queue/enqueue"))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .json(&json!({ "changeset_id": emb_staged.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let drain1: Value = client
        .post(srv.url("/v1/repos/sec/embargo-demo/queue/drain"))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .json(&json!({ "target": "master", "max_batch_size": 8 }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(drain1["landed"].as_array().unwrap().len(), 1);
    let land1_seq = drain1["land_seq"].as_u64().unwrap();

    // Second drain lands the embargoed entry separately
    let drain2: Value = client
        .post(srv.url("/v1/repos/sec/embargo-demo/queue/drain"))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .json(&json!({ "target": "master", "max_batch_size": 8 }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(drain2["landed"].as_array().unwrap().len(), 1);

    // Anonymous caller MUST NOT see src/patch.rs after both drains
    let anon_tree: TreeResponse = client
        .get(srv.url("/v1/repos/sec/embargo-demo/tree"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(anon_tree.files.iter().any(|f| f.path == "src/docs.rs"));
    assert!(!anon_tree.files.iter().any(|f| f.path == "src/patch.rs"));

    // Non-tip revert_land (reverting land1 while land2 is tip) must fail with 409 Conflict
    let non_tip_revert = client
        .post(srv.url(&format!("/v1/repos/sec/embargo-demo/revert/{land1_seq}")))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .send()
        .await
        .unwrap();
    assert_eq!(non_tip_revert.status(), StatusCode::CONFLICT);

    // Read-only viewer (`auditor`) cannot publish embargo
    let ro_publish = client
        .post(srv.url("/v1/repos/sec/embargo-demo/embargo/cve-2026-42/publish"))
        .header("X-Gitx-User", "auditor")
        .json(&json!({ "target": "master" }))
        .send()
        .await
        .unwrap();
    assert_eq!(ro_publish.status(), StatusCode::FORBIDDEN);

    // Authorized team:security writer publishes embargo once -> 200 OK
    let ok_publish = client
        .post(srv.url("/v1/repos/sec/embargo-demo/embargo/cve-2026-42/publish"))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .json(&json!({ "target": "master" }))
        .send()
        .await
        .unwrap();
    assert!(ok_publish.status().is_success());

    // Publishing the same embargo a second time returns 409 Conflict
    let dup_publish = client
        .post(srv.url("/v1/repos/sec/embargo-demo/embargo/cve-2026-42/publish"))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .json(&json!({ "target": "master" }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup_publish.status(), StatusCode::CONFLICT);

    // Non-admin embargo writer CAN revert their own active embargo tip land,
    // while an unauthorized user gets 403 Forbidden.
    let emb_rev_staged: CommitResponse = client
        .post(srv.url("/v1/repos/sec/embargo-demo/commit"))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .json(&json!({
            "files": { "src/revertable_cve.rs": "pub fn hotfix() {}\n" },
            "update_target": false,
            "embargo_advisory": "cve-2026-revert",
            "embargo_allowed_teams": ["security"],
            "message": "Revertable embargo fix",
            "author_name": "SecEng",
            "author_email": "sec@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let emb_landed: LandResponse = client
        .post(srv.url("/v1/repos/sec/embargo-demo/land"))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .json(&json!({ "changeset_id": emb_rev_staged.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Read-only viewer (`auditor`) cannot revert the active embargo land
    let unauth_emb_revert = client
        .post(srv.url(&format!(
            "/v1/repos/sec/embargo-demo/revert/{}",
            emb_landed.land_seq
        )))
        .header("X-Gitx-User", "auditor")
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_emb_revert.status(), StatusCode::FORBIDDEN);

    // Authorized non-admin `team:security` writer CAN revert the active embargo tip land
    let auth_emb_revert = client
        .post(srv.url(&format!(
            "/v1/repos/sec/embargo-demo/revert/{}",
            emb_landed.land_seq
        )))
        .header("X-Gitx-User", "seceng")
        .header("X-Gitx-Teams", "security")
        .send()
        .await
        .unwrap();
    assert!(
        auth_emb_revert.status().is_success(),
        "expected authorized non-admin embargo writer to revert own active embargo land, got {}",
        auth_emb_revert.status()
    );

    // Stacked-parent write-ACL bypass regression:
    // An authorized team:security writer stages B (touching both public + team:security so B is readable).
    // An unprivileged user `eve` (public-only) stacks public-only commit C on top of B,
    // then tries to land C via both POST /land and POST /queue/drain -> MUST be rejected!
    let srv_stack = TestServer::start(Some(
        "path ** -> public\n\
         path packages/private/** -> team:core\n\
         domain public read=* write=authenticated\n\
         domain team:core read=team:core write=team:core\n",
    ))
    .await;

    let base_a: CommitResponse = client
        .post(srv_stack.url("/v1/repos/sec/stack-acl/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": { "README.md": "# base A\n" },
            "message": "Commit A",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Staged unlanded commit B by team:core writer modifying both README.md (public) & packages/private/core.rs (team:core)
    let staged_b: CommitResponse = client
        .post(srv_stack.url("/v1/repos/sec/stack-acl/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": {
                "README.md": "# commit B\n",
                "packages/private/core.rs": "pub fn unlanded_core() {}\n"
            },
            "parent": base_a.changeset_id,
            "update_target": false,
            "message": "Staged B with team:core change",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Unprivileged `eve` (not in team:core) stacks public-only commit C on top of B
    let stacked_c: CommitResponse = client
        .post(srv_stack.url("/v1/repos/sec/stack-acl/commit"))
        .header("X-Gitx-User", "eve")
        .json(&json!({
            "files": { "README.md": "# commit C stacked on B\n" },
            "parent": staged_b.changeset_id,
            "update_target": false,
            "message": "Public-only C stacked on B",
            "author_name": "Eve",
            "author_email": "eve@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Attempting to land stacked C as `eve` via POST /land MUST fail with 403 Forbidden
    let land_bypass = client
        .post(srv_stack.url("/v1/repos/sec/stack-acl/land"))
        .header("X-Gitx-User", "eve")
        .json(&json!({ "changeset_id": stacked_c.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap();
    assert_eq!(land_bypass.status(), StatusCode::FORBIDDEN);

    // Attempting to land stacked C via merge queue MUST reject C without aborting a clean public entry
    let clean_pub: CommitResponse = client
        .post(srv_stack.url("/v1/repos/sec/stack-acl/commit"))
        .header("X-Gitx-User", "eve")
        .json(&json!({
            "files": { "PUBLIC.md": "# clean public\n" },
            "parent": base_a.changeset_id,
            "update_target": false,
            "message": "Clean public change",
            "author_name": "Eve",
            "author_email": "eve@org.dev"
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
        .post(srv_stack.url("/v1/repos/sec/stack-acl/queue/enqueue"))
        .header("X-Gitx-User", "eve")
        .json(&json!({ "changeset_id": stacked_c.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    client
        .post(srv_stack.url("/v1/repos/sec/stack-acl/queue/enqueue"))
        .header("X-Gitx-User", "eve")
        .json(&json!({ "changeset_id": clean_pub.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let drain_bypass: Value = client
        .post(srv_stack.url("/v1/repos/sec/stack-acl/queue/drain"))
        .header("X-Gitx-User", "eve")
        .json(&json!({ "target": "master", "max_batch_size": 8 }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(drain_bypass["rejected"].as_array().unwrap().len(), 1);
    assert_eq!(drain_bypass["landed"].as_array().unwrap().len(), 1);
    assert_eq!(
        drain_bypass["landed"][0]["changeset_id"].as_str(),
        Some(clean_pub.changeset_id.as_str())
    );

    // Verify packages/private/core.rs was NEVER landed onto master!
    let core_tree: TreeResponse = client
        .get(srv_stack.url("/v1/repos/sec/stack-acl/tree"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(core_tree.files.iter().any(|f| f.path == "PUBLIC.md"));
    assert!(
        !core_tree
            .files
            .iter()
            .any(|f| f.path == "packages/private/core.rs")
    );

    // Embargo advisory-ID hijacking & Git Smart HTTP isolation regression (Grok R7 blocker/should):
    // 1. Alice (team:security) commits an active embargo under advisory `cve-2026-0001`.
    // 2. Mallory (unprivileged) attempts to attach a decoy commit under the SAME advisory id
    //    with `embargo_allowed_teams: ["private:user:mallory"]` -> MUST fail with 403 Forbidden.
    // 3. Mallory clones via Git Smart HTTP -> ZERO embargoed blobs leaked.
    // 4. After Alice publishes `cve-2026-0001`, attaching another commit to it returns 409 Conflict.
    let srv_emb = TestServer::start(Some(
        "path ** -> public\n\
         domain public read=* write=authenticated\n\
         domain team:security read=team:security write=team:security\n",
    ))
    .await;

    client
        .post(srv_emb.url("/v1/repos/sec/embargo-http/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "security")
        .json(&json!({
            "files": { "README.md": "# Embargo Repo\n" },
            "message": "Initial public commit",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    client
        .post(srv_emb.url("/v1/repos/sec/embargo-http/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "security")
        .json(&json!({
            "files": { "src/zero_day.rs": "pub const ZERO_DAY_SECRET: &str = \"TOP_SECRET_PATCH\";\n" },
            "embargo_advisory": "cve-2026-0001",
            "embargo_allowed_teams": ["security"],
            "message": "Confidential CVE-2026-0001 fix",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Mallory tries to attach a decoy commit under the same advisory id on her own branch
    let decoy_res = client
        .post(srv_emb.url("/v1/repos/sec/embargo-http/commit"))
        .header("X-Gitx-User", "mallory")
        .json(&json!({
            "files": { "decoy.txt": "decoy\n" },
            "target": "mallory-branch",
            "embargo_advisory": "cve-2026-0001",
            "embargo_allowed_teams": ["private:user:mallory"],
            "message": "Decoy advisory hijack attempt",
            "author_name": "Mallory",
            "author_email": "mallory@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(decoy_res.status(), StatusCode::FORBIDDEN);

    // Mallory clones via Git Smart HTTP and receives ZERO embargoed blobs
    let mallory_tmp = TempDir::new().unwrap();
    let mallory_clone = mallory_tmp.path().join("mallory");
    let clone_out = Command::new("git")
        .args([
            "-c",
            "http.extraHeader=X-Gitx-User: mallory",
            "clone",
            &srv_emb.url("/sec/embargo-http.git"),
        ])
        .arg(&mallory_clone)
        .output()
        .await
        .expect("spawn git clone");
    assert!(clone_out.status.success());
    assert!(mallory_clone.join("README.md").is_file());
    assert!(!mallory_clone.join("src/zero_day.rs").exists());

    // Alice publishes cve-2026-0001; attempting to attach another commit to it afterwards returns 409
    client
        .post(srv_emb.url("/v1/repos/sec/embargo-http/embargo/cve-2026-0001/publish"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "security")
        .json(&json!({ "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let post_publish_commit = client
        .post(srv_emb.url("/v1/repos/sec/embargo-http/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "security")
        .json(&json!({
            "files": { "src/after.rs": "pub fn after() {}\n" },
            "embargo_advisory": "cve-2026-0001",
            "embargo_allowed_teams": ["security"],
            "message": "Post-publish embargo commit",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(post_publish_commit.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn round8_receive_pack_acl_non_primary_domain_outbox_acl_retry_and_auto_revert_error() {
    use axum::routing::post as axum_post;
    use gitx_core::ObjectHash;
    use gitx_server::{OutboxResponse, WebhookOutbox, outbox::replay_pending_events};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let client = Client::new();

    // 1. HTTP git-receive-pack rejects non-admin `.gitxacl` modification & protected-path push,
    //    and preserves non-primary domain files when pushing to `?domain=team:core`.
    let acl = "\
path ** -> public
path packages/private/** -> team:core
path .env* -> secret:dev
domain public read=* write=authenticated
domain team:core read=team:core write=team:core
";
    let srv = TestServer::start(Some(acl)).await;

    // Seed commit with BOTH public (`README.md`) and non-primary `team:core` (`packages/private/existing.rs`).
    // Primary domain is `public` because both `public` and `team:core` are touched.
    client
        .post(srv.url("/v1/repos/sec/gitpush/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": {
                "README.md": "# GitPush Repo\n",
                "packages/private/existing.rs": "pub fn keep_me() {}\n"
            },
            "message": "Initial mixed-domain commit",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Clone public view as non-admin `bob`
    let tmp = TempDir::new().unwrap();
    let bob_dir = tmp.path().join("bob-clone");
    let clone_out = Command::new("git")
        .args([
            "-c",
            "http.extraHeader=X-Gitx-User: bob",
            "clone",
            &srv.url("/sec/gitpush.git"),
        ])
        .arg(&bob_dir)
        .output()
        .await
        .unwrap();
    assert!(clone_out.status.success());
    for args in [
        vec!["config", "user.name", "Bob"],
        vec!["config", "user.email", "bob@org.dev"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&bob_dir)
                .args(&args)
                .status()
                .await
                .unwrap()
                .success()
        );
    }

    // 1a. Non-admin `bob` attempts to escalate privileges by pushing a malicious `.gitxacl` -> DENIED
    std::fs::write(
        bob_dir.join(".gitxacl"),
        "path ** -> public\ndomain public read=* write=*\n",
    )
    .unwrap();
    for args in [
        vec!["add", ".gitxacl"],
        vec!["commit", "-m", "Malicious ACL push"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&bob_dir)
                .args(&args)
                .status()
                .await
                .unwrap()
                .success()
        );
    }
    let acl_push = Command::new("git")
        .arg("-C")
        .arg(&bob_dir)
        .args([
            "-c",
            "http.extraHeader=X-Gitx-User: bob",
            "push",
            "origin",
            "HEAD:master",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        !acl_push.status.success(),
        "non-admin .gitxacl push over HTTP receive-pack must be denied"
    );

    // Reset bob's clone and attempt pushing a `team:core`-routed path into `public` -> DENIED
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&bob_dir)
            .args(["reset", "--hard", "HEAD~1"])
            .status()
            .await
            .unwrap()
            .success()
    );
    std::fs::create_dir_all(bob_dir.join("packages/private")).unwrap();
    std::fs::write(
        bob_dir.join("packages/private/sneaky.rs"),
        "pub fn sneak() {}\n",
    )
    .unwrap();
    for args in [
        vec!["add", "packages/private/sneaky.rs"],
        vec!["commit", "-m", "Protected path pushed to public"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&bob_dir)
                .args(&args)
                .status()
                .await
                .unwrap()
                .success()
        );
    }
    let path_acl_push = Command::new("git")
        .arg("-C")
        .arg(&bob_dir)
        .args([
            "-c",
            "http.extraHeader=X-Gitx-User: bob",
            "push",
            "origin",
            "HEAD:master",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        !path_acl_push.status.success(),
        "pushing team:core path into public domain must be denied"
    );

    // 1b. Non-primary domain receive-pack staging preserves existing `team:core` files!
    let core_dir = tmp.path().join("core-clone");
    let core_clone = Command::new("git")
        .args([
            "-c",
            "http.extraHeader=X-Gitx-User: alice",
            "-c",
            "http.extraHeader=X-Gitx-Teams: core",
            "clone",
            &srv.url("/sec/gitpush.git"),
        ])
        .arg(&core_dir)
        .output()
        .await
        .unwrap();
    assert!(core_clone.status.success());
    // Push a commit containing BOTH existing + new `team:core` file into `?domain=team:core`
    // using a clean staging repo exported strictly for `team:core` (proving `info/refs?service=git-receive-pack&domain=team:core`
    // advertised `master` rather than an empty history!).
    let info_refs_core = client
        .get(srv.url("/sec/gitpush.git/info/refs?service=git-receive-pack&domain=team:core"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        info_refs_core.contains("refs/heads/master"),
        "receive-pack info/refs for non-primary domain team:core must advertise master, got:\n{info_refs_core}"
    );

    // Pushing to an embargo domain via git-receive-pack must be rejected with 403
    let emb_refs = client
        .get(srv.url("/sec/gitpush.git/info/refs?service=git-receive-pack&domain=embargo:cve-1"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .send()
        .await
        .unwrap();
    assert_eq!(emb_refs.status(), StatusCode::FORBIDDEN);

    // Pushing a new branch name that collides with an existing active embargo bookmark must be DENIED
    let embargo_commit: CommitResponse = client
        .post(srv.url("/v1/repos/sec/gitpush/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": { "sec_fix.txt": "cve fix\n" },
            "target": "embargo/cve-1",
            "embargo_advisory": "cve-1",
            "embargo_allowed_teams": ["core"],
            "message": "Embargo branch commit",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        embargo_commit
            .domains_written
            .iter()
            .any(|d| d == "embargo:cve-1"),
        "expected embargo:cve-1 in domains_written, got {:?}",
        embargo_commit.domains_written
    );

    // Verify `embargo/cve-1` is NOT advertised in Bob's receive-pack `info/refs`,
    // proving the rejection below comes from `import_received_refs_with_policy`'s hidden-bookmark guard!
    let bob_recv_refs = client
        .get(srv.url("/sec/gitpush.git/info/refs?service=git-receive-pack"))
        .header("X-Gitx-User", "bob")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !bob_recv_refs.contains("refs/heads/embargo/cve-1"),
        "active embargo bookmark must not be advertised in receive-pack info/refs"
    );

    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&bob_dir)
            .args(["reset", "--hard", "HEAD~1"])
            .status()
            .await
            .unwrap()
            .success()
    );
    std::fs::write(bob_dir.join("hijack.txt"), "attempt\n").unwrap();
    for args in [
        vec!["add", "hijack.txt"],
        vec!["commit", "-m", "Hijack hidden embargo bookmark"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&bob_dir)
                .args(&args)
                .status()
                .await
                .unwrap()
                .success()
        );
    }
    let hijack_push = Command::new("git")
        .arg("-C")
        .arg(&bob_dir)
        .args([
            "-c",
            "http.extraHeader=X-Gitx-User: bob",
            "push",
            "origin",
            "HEAD:refs/heads/embargo/cve-1",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        !hijack_push.status.success(),
        "pushing a branch colliding with a hidden active embargo bookmark must be denied"
    );

    // Also verify pushing onto a branch whose tip is an active embargo over a public ancestor is DENIED!
    let pub_branch_commit: CommitResponse = client
        .post(srv.url("/v1/repos/sec/gitpush/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": { "base_emb.txt": "public base\n" },
            "target": "release-embargo",
            "message": "Public base for release-embargo",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let active_emb_tip: CommitResponse = client
        .post(srv.url("/v1/repos/sec/gitpush/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": { "patch_emb.txt": "cve patch\n" },
            "target": "release-embargo",
            "parent": pub_branch_commit.changeset_id,
            "embargo_advisory": "cve-2",
            "embargo_allowed_teams": ["core"],
            "message": "Active embargo tip over public ancestor",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        active_emb_tip
            .domains_written
            .iter()
            .any(|d| d == "embargo:cve-2"),
        "expected embargo:cve-2 in domains_written, got {:?}",
        active_emb_tip.domains_written
    );
    let emb_tip_push = Command::new("git")
        .arg("-C")
        .arg(&bob_dir)
        .args([
            "-c",
            "http.extraHeader=X-Gitx-User: bob",
            "push",
            "origin",
            "HEAD:refs/heads/release-embargo",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        !emb_tip_push.status.success(),
        "pushing onto a branch whose tip is an active embargo over a public ancestor must be denied"
    );

    // 2. Outbox fail-closed `previous_head` filtering + pagination past unreadable burst
    let pub1: CommitResponse = client
        .post(srv.url("/v1/repos/sec/gitpush/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": { "pub1.txt": "visible\n" },
            "update_target": false,
            "message": "Public staged 1",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let land_pub1: LandResponse = client
        .post(srv.url("/v1/repos/sec/gitpush/land"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({ "changeset_id": pub1.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Land a private `team:core` commit, then revert it back to public `pub1`!
    // The revert outbox event has `new_head = pub1` (public) and `previous_head = priv_cs` (private).
    let priv1: CommitResponse = client
        .post(srv.url("/v1/repos/sec/gitpush/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": { "packages/private/only_core.rs": "pub fn x() {}\n" },
            "update_target": false,
            "message": "Private core staged",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let land_priv1: LandResponse = client
        .post(srv.url("/v1/repos/sec/gitpush/land"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({ "changeset_id": priv1.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    client
        .post(srv.url(&format!(
            "/v1/repos/sec/gitpush/revert/{}",
            land_priv1.land_seq
        )))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Unprivileged `bob` requests `GET /outbox?limit=1`:
    // MUST NOT see the private land OR the revert event (whose `previous_head` is private!),
    // and MUST paginate past both unreadable events to still return `land_pub1`!
    let bob_outbox: OutboxResponse = client
        .get(srv.url("/v1/repos/sec/gitpush/outbox?limit=1"))
        .header("X-Gitx-User", "bob")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bob_outbox.events.len(), 1);
    assert_eq!(bob_outbox.events[0].land_seq, land_pub1.land_seq);
    assert_eq!(bob_outbox.events[0].event_type, "land");

    // 3. Per-destination webhook outbox deduplication & retry on startup replay
    let ok_hits = Arc::new(AtomicUsize::new(0));
    let flaky_hits = Arc::new(AtomicUsize::new(0));
    let ok_hits_srv = Arc::clone(&ok_hits);
    let flaky_hits_srv = Arc::clone(&flaky_hits);
    let wh_app = axum::Router::new()
        .route(
            "/ok",
            axum_post(move || {
                let c = Arc::clone(&ok_hits_srv);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::OK
                }
            }),
        )
        .route(
            "/flaky",
            axum_post(move || {
                let c = Arc::clone(&flaky_hits_srv);
                async move {
                    let n = c.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR
                    } else {
                        axum::http::StatusCode::OK
                    }
                }
            }),
        );
    let wh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wh_addr = wh_listener.local_addr().unwrap();
    let wh_handle = tokio::spawn(async move {
        let _ = axum::serve(wh_listener, wh_app).await;
    });

    let outbox = Arc::new(WebhookOutbox::in_memory().unwrap());
    let _ev = outbox
        .record_event(
            "land",
            "master",
            1,
            None,
            ObjectHash::of_bytes(b"head1"),
            &json!({"event": "land"}),
        )
        .unwrap();
    let urls = vec![
        format!("http://{wh_addr}/ok"),
        format!("http://{wh_addr}/flaky"),
    ];
    replay_pending_events(Arc::clone(&outbox), urls).await;
    assert_eq!(
        ok_hits.load(Ordering::SeqCst),
        1,
        "already-delivered webhook destination must not receive duplicate deliveries on retry"
    );
    assert_eq!(flaky_hits.load(Ordering::SeqCst), 2);
    let stored = outbox.list_events(10).unwrap();
    assert!(stored[0].delivered_at.is_some());
    wh_handle.abort();

    // 4. Failing `post_land_cmd` on initial land (no previous_head -> revert_land fails)
    //    must return 500 instead of falsely claiming `409 auto-reverted`!
    let tmp_hook = TempDir::new().unwrap();
    let hook_cfg = ServerConfig::new(tmp_hook.path()).with_post_land_cmd("exit 1");
    let hook_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = hook_listener.local_addr().unwrap();
    let hook_handle = tokio::spawn(async move {
        let _ = serve(hook_listener, hook_cfg).await;
    });
    let staged_init: CommitResponse = client
        .post(format!("http://{hook_addr}/v1/repos/sec/hookfail/commit"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "files": { "a.txt": "init\n" },
            "update_target": false,
            "message": "Initial staged",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let failed_auto_revert = client
        .post(format!("http://{hook_addr}/v1/repos/sec/hookfail/land"))
        .header("X-Gitx-User", "alice")
        .json(&json!({ "changeset_id": staged_init.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        failed_auto_revert.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    hook_handle.abort();
}

#[tokio::test]
async fn round9_create_repo_acl_survives_master_updates_outbox_reconciles_crash_and_multiref_push_atomic()
 {
    use axum::routing::post as axum_post;
    use gitx_server::{
        DrainResponse, OutboxResponse, WebhookOutbox, outbox::replay_pending_events,
    };
    use gitx_store::{LocalStore, ObjectStore};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::process::Command;

    // 1. Server with NO `default_acl`: per-repo `.gitxacl` configured via `POST /v1/repos/{o}/{n}`
    //    MUST survive unprivileged `land`, `queue/drain`, `revert`, and HTTP `git-receive-pack`!
    let srv = TestServer::start(None).await;
    let client = reqwest::Client::new();
    let per_repo_acl = "\
path ** -> public
path packages/private/** -> team:core
domain public read=* write=*
domain team:core read=team:core write=team:core
";

    client
        .post(srv.url("/v1/repos/sec/perrepo"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Roles", "admin")
        .json(&json!({ "acl": per_repo_acl }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Seed master with a public file and a private `team:core` file (WITHOUT committing `.gitxacl`)
    client
        .post(srv.url("/v1/repos/sec/perrepo/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": {
                "README.md": "public\n",
                "packages/private/secret.rs": "pub const K: &str = \"core\";\n"
            },
            "message": "Initial seed without committed .gitxacl",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Helper closure via async fn check: `bob` MUST stay forbidden from reading `packages/private/secret.rs`
    // (checked via active `/tree` and `/grep` HTTP routes) and forbidden from writing `packages/private/x.rs`.
    async fn assert_per_repo_acl_intact(client: &reqwest::Client, srv: &TestServer, step: &str) {
        let tree_resp: TreeResponse = client
            .get(srv.url("/v1/repos/sec/perrepo/tree"))
            .header("X-Gitx-User", "bob")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            !tree_resp
                .files
                .iter()
                .any(|f| f.path == "packages/private/secret.rs"),
            "per-repo .gitxacl wiped after {step}: bob saw packages/private/secret.rs in /tree!"
        );
        let grep_resp: GrepResponse = client
            .get(srv.url("/v1/repos/sec/perrepo/grep?q=core"))
            .header("X-Gitx-User", "bob")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            grep_resp.matches.is_empty(),
            "per-repo .gitxacl wiped after {step}: bob matched private content via /grep!"
        );
        let write_resp = client
            .post(srv.url("/v1/repos/sec/perrepo/commit"))
            .header("X-Gitx-User", "bob")
            .json(&json!({
                "files": { "packages/private/pwn.rs": "pwn\n" },
                "update_target": false,
                "message": "Bob probe",
                "author_name": "Bob",
                "author_email": "bob@org.dev"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            write_resp.status(),
            StatusCode::FORBIDDEN,
            "per-repo .gitxacl wiped after {step}: bob could write packages/private/pwn.rs!"
        );
    }

    assert_per_repo_acl_intact(&client, &srv, "create_repo + seed").await;

    // 1a. Unprivileged `POST /land` onto master
    let bob_staged1: CommitResponse = client
        .post(srv.url("/v1/repos/sec/perrepo/commit"))
        .header("X-Gitx-User", "bob")
        .json(&json!({
            "files": { "bob_land.txt": "landed\n" },
            "update_target": false,
            "message": "Bob staged land",
            "author_name": "Bob",
            "author_email": "bob@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let land1: LandResponse = client
        .post(srv.url("/v1/repos/sec/perrepo/land"))
        .header("X-Gitx-User", "bob")
        .json(&json!({ "changeset_id": bob_staged1.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_per_repo_acl_intact(&client, &srv, "POST /land").await;

    // 1b. Unprivileged `POST /queue/enqueue` + `POST /queue/drain` onto master
    let bob_staged2: CommitResponse = client
        .post(srv.url("/v1/repos/sec/perrepo/commit"))
        .header("X-Gitx-User", "bob")
        .json(&json!({
            "files": { "bob_queue.txt": "queued\n" },
            "update_target": false,
            "message": "Bob staged queue",
            "author_name": "Bob",
            "author_email": "bob@org.dev"
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
        .post(srv.url("/v1/repos/sec/perrepo/queue/enqueue"))
        .header("X-Gitx-User", "bob")
        .json(&json!({ "changeset_id": bob_staged2.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let drain_resp: DrainResponse = client
        .post(srv.url("/v1/repos/sec/perrepo/queue/drain"))
        .header("X-Gitx-User", "bob")
        .json(&json!({ "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let q_land_seq = drain_resp.land_seq.expect("queue drain landed");
    assert_per_repo_acl_intact(&client, &srv, "POST /queue/drain").await;

    // 1c. Unprivileged `POST /revert/{seq}` on master
    client
        .post(srv.url(&format!("/v1/repos/sec/perrepo/revert/{q_land_seq}")))
        .header("X-Gitx-User", "bob")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_per_repo_acl_intact(&client, &srv, "POST /revert").await;

    // 1d. Unprivileged HTTP `git-receive-pack` push onto master
    let tmp = TempDir::new().unwrap();
    let bob_clone = tmp.path().join("bob");
    assert!(
        Command::new("git")
            .args([
                "-c",
                "http.extraHeader=X-Gitx-User: bob",
                "clone",
                &srv.url("/sec/perrepo.git"),
            ])
            .arg(&bob_clone)
            .status()
            .await
            .unwrap()
            .success()
    );
    for args in [
        vec!["config", "user.name", "Bob"],
        vec!["config", "user.email", "bob@org.dev"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&bob_clone)
                .args(&args)
                .status()
                .await
                .unwrap()
                .success()
        );
    }
    std::fs::write(bob_clone.join("bob_git_push.txt"), "via git http\n").unwrap();
    for args in [
        vec!["add", "bob_git_push.txt"],
        vec!["commit", "-m", "Bob HTTP git push"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&bob_clone)
                .args(&args)
                .status()
                .await
                .unwrap()
                .success()
        );
    }
    let ok_push = Command::new("git")
        .arg("-C")
        .arg(&bob_clone)
        .args([
            "-c",
            "http.extraHeader=X-Gitx-User: bob",
            "push",
            "origin",
            "HEAD:master",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        ok_push.status.success(),
        "bob public HTTP push should succeed: {}",
        String::from_utf8_lossy(&ok_push.stderr)
    );
    assert_per_repo_acl_intact(&client, &srv, "HTTP git-receive-pack").await;

    // 2. Multi-ref HTTP `git-receive-pack` atomicity: pushing a valid `master` update AND an
    //    invalid `zz-bad` ref (containing a protected `packages/private/*` path) in a SINGLE push
    //    MUST fail and leave `master` completely unchanged!
    let repo_dir = srv._tmp.path().join("repos/sec/perrepo");
    let direct_store = LocalStore::open(&repo_dir).unwrap();
    let master_before = direct_store
        .get_bookmark("master")
        .unwrap()
        .expect("master bookmark must exist");

    std::fs::write(bob_clone.join("good_master.txt"), "valid master commit\n").unwrap();
    for args in [
        vec!["add", "good_master.txt"],
        vec!["commit", "-m", "Valid master update in multi-ref push"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&bob_clone)
                .args(&args)
                .status()
                .await
                .unwrap()
                .success()
        );
    }
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&bob_clone)
            .args(["checkout", "-b", "zz-bad"])
            .status()
            .await
            .unwrap()
            .success()
    );
    std::fs::create_dir_all(bob_clone.join("packages/private")).unwrap();
    std::fs::write(bob_clone.join("packages/private/evil.rs"), "evil\n").unwrap();
    for args in [
        vec!["add", "packages/private/evil.rs"],
        vec!["commit", "-m", "Disallowed path on second ref"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&bob_clone)
                .args(&args)
                .status()
                .await
                .unwrap()
                .success()
        );
    }
    let multiref_push = Command::new("git")
        .arg("-C")
        .arg(&bob_clone)
        .args([
            "-c",
            "http.extraHeader=X-Gitx-User: bob",
            "push",
            "origin",
            "master:refs/heads/master",
            "zz-bad:refs/heads/zz-bad",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        !multiref_push.status.success(),
        "multi-ref push with one invalid ref must be rejected"
    );
    assert_eq!(
        direct_store.get_bookmark("master").unwrap(),
        Some(master_before),
        "failed multi-ref push must NOT partially advance master"
    );
    assert_eq!(
        direct_store.get_bookmark("zz-bad").unwrap(),
        None,
        "failed multi-ref push must NOT create zz-bad"
    );

    // 3. Crash-window reconciliation between `store.record_land` and `outbox.record_event`:
    //    Write a land record directly to the repo's `LocalStore` (simulating a crash right after
    //    `record_land` before `outbox.record_event`), then verify `GET /outbox` AND webhook replay
    //    automatically reconcile and deliver it ONCE without duplication!
    let direct_land = direct_store
        .record_land("crash-branch", None, master_before, Vec::new())
        .unwrap();
    assert!(direct_land.land_seq > land1.land_seq);

    let outbox_resp: OutboxResponse = client
        .get(srv.url("/v1/repos/sec/perrepo/outbox?limit=50"))
        .header("X-Gitx-User", "bob")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        outbox_resp
            .events
            .iter()
            .any(|e| e.land_seq == direct_land.land_seq && e.event_type == "land"),
        "outbox must reconcile committed land_seq {} missed due to crash",
        direct_land.land_seq
    );

    // Also verify webhook replay delivers the reconciled event exactly once (idempotent reconcile + dedup)
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&hits);
    let wh_app = axum::Router::new().route(
        "/hook",
        axum_post(move || {
            let c = Arc::clone(&hits_srv);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::OK
            }
        }),
    );
    let wh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wh_addr = wh_listener.local_addr().unwrap();
    let wh_handle = tokio::spawn(async move {
        let _ = axum::serve(wh_listener, wh_app).await;
    });
    let isolated_outbox = Arc::new(WebhookOutbox::in_memory().unwrap());
    let recovered1 = isolated_outbox
        .reconcile_from_store(&direct_store, "sec/perrepo")
        .unwrap();
    assert!(recovered1 >= 1);
    let recovered2 = isolated_outbox
        .reconcile_from_store(&direct_store, "sec/perrepo")
        .unwrap();
    assert_eq!(recovered2, 0, "second reconcile pass must be a no-op");
    let expected_events = isolated_outbox.list_pending_events(100).unwrap().len();
    replay_pending_events(
        Arc::clone(&isolated_outbox),
        vec![format!("http://{wh_addr}/hook")],
    )
    .await;
    assert_eq!(hits.load(Ordering::SeqCst), expected_events);
    // Replaying a second time delivers zero duplicates
    replay_pending_events(
        Arc::clone(&isolated_outbox),
        vec![format!("http://{wh_addr}/hook")],
    )
    .await;
    assert_eq!(hits.load(Ordering::SeqCst), expected_events);
    wh_handle.abort();
}

#[tokio::test]
async fn round10_embargo_publish_records_outbox_and_dispatches_webhook_immediately() {
    use axum::routing::post as axum_post;
    use gitx_server::OutboxResponse;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let pub_hits = Arc::new(AtomicUsize::new(0));
    let pub_hits_srv = Arc::clone(&pub_hits);
    let wh_app = axum::Router::new().route(
        "/embargo-pub",
        axum_post(move || {
            let c = Arc::clone(&pub_hits_srv);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::OK
            }
        }),
    );
    let wh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wh_addr = wh_listener.local_addr().unwrap();
    let wh_handle = tokio::spawn(async move {
        let _ = axum::serve(wh_listener, wh_app).await;
    });

    let tmp = TempDir::new().unwrap();
    let acl = "\
path ** -> public
domain public read=* write=*
domain team:sec read=team:sec write=team:sec
";
    let cfg = ServerConfig::new(tmp.path())
        .with_default_acl(acl)
        .with_webhook_url(format!("http://{wh_addr}/embargo-pub"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_handle = tokio::spawn(async move {
        let _ = serve(listener, cfg).await;
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // Seed master
    client
        .post(format!("{base}/v1/repos/sec/pubwh/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({
            "files": { "README.md": "hello\n" },
            "message": "Seed",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Commit active embargo
    let emb: CommitResponse = client
        .post(format!("{base}/v1/repos/sec/pubwh/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({
            "files": { "fix.rs": "pub fn fixed() {}\n" },
            "target": "embargo/cve-99",
            "embargo_advisory": "cve-99",
            "embargo_allowed_teams": ["sec"],
            "message": "Embargo CVE-99",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Publish embargo -> MUST immediately record outbox event AND deliver webhook without restart!
    client
        .post(format!("{base}/v1/repos/sec/pubwh/embargo/cve-99/publish"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({ "changeset_id": emb.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Poll briefly for async webhook delivery (must arrive promptly without any second land/restart)
    let mut delivered = false;
    for _ in 0..50 {
        if pub_hits.load(Ordering::SeqCst) >= 1 {
            delivered = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        delivered,
        "publish_embargo must immediately dispatch webhook via outbox without waiting for restart"
    );
    assert_eq!(pub_hits.load(Ordering::SeqCst), 1);

    let outbox: OutboxResponse = client
        .get(format!("{base}/v1/repos/sec/pubwh/outbox?limit=10"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(outbox.events.len(), 1);
    assert_eq!(outbox.events[0].event_type, "land");
    assert!(outbox.events[0].payload_json.contains("cve-99"));

    // Verify durable `advisory_id` survives crash-window reconciliation on a fresh outbox DB!
    let fresh_outbox = gitx_server::WebhookOutbox::in_memory().unwrap();
    let repo_store = gitx_store::LocalStore::open(tmp.path().join("repos/sec/pubwh")).unwrap();
    let recovered = fresh_outbox
        .reconcile_from_store(&repo_store, "sec/pubwh")
        .unwrap();
    assert_eq!(recovered, 1);
    let rec_events = fresh_outbox.list_events(10).unwrap();
    assert_eq!(rec_events.len(), 1);
    assert_eq!(rec_events[0].event_type, "land");
    assert!(
        rec_events[0].payload_json.contains("cve-99"),
        "reconcile_from_store must preserve advisory_id from published changeset, got: {}",
        rec_events[0].payload_json
    );

    srv_handle.abort();
    wh_handle.abort();
}

#[tokio::test]
async fn round11_embargo_publish_concurrent_targets_serialized_and_post_land_hook_auto_reverts() {
    use gitx_server::OutboxResponse;
    use gitx_store::{LocalStore, ObjectStore};

    let tmp = TempDir::new().unwrap();
    let acl = "\
path ** -> public
domain public read=* write=*
domain team:sec read=team:sec write=team:sec
";

    // 1. Concurrent publish requests for the same advisory targeting DIFFERENT bookmarks
    //    (`master` and `release`) MUST be serialized: exactly ONE succeeds and the other gets 409!
    let srv_cfg = ServerConfig::new(tmp.path().join("srv1")).with_default_acl(acl);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_handle = tokio::spawn(async move {
        let _ = serve(listener, srv_cfg).await;
    });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    for target in ["master", "release"] {
        client
            .post(format!("{base}/v1/repos/sec/race/commit"))
            .header("X-Gitx-User", "alice")
            .header("X-Gitx-Teams", "sec")
            .json(&json!({
                "files": { "README.md": format!("seed {target}\n") },
                "target": target,
                "message": format!("Seed {target}"),
                "author_name": "Alice",
                "author_email": "alice@org.dev"
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }
    client
        .post(format!("{base}/v1/repos/sec/race/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({
            "files": { "fix.rs": "pub fn fix() {}\n" },
            "target": "embargo/cve-race",
            "embargo_advisory": "cve-race",
            "embargo_allowed_teams": ["sec"],
            "message": "Embargo race fix",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let (r1, r2) = tokio::join!(
        client
            .post(format!("{base}/v1/repos/sec/race/embargo/cve-race/publish"))
            .header("X-Gitx-User", "alice")
            .header("X-Gitx-Teams", "sec")
            .json(&json!({ "target": "master" }))
            .send(),
        client
            .post(format!("{base}/v1/repos/sec/race/embargo/cve-race/publish"))
            .header("X-Gitx-User", "alice")
            .header("X-Gitx-Teams", "sec")
            .json(&json!({ "target": "release" }))
            .send()
    );
    let mut statuses = vec![r1.unwrap().status(), r2.unwrap().status()];
    statuses.sort_by_key(|s| s.as_u16());
    assert_eq!(
        statuses,
        vec![StatusCode::OK, StatusCode::CONFLICT],
        "concurrent embargo publishes to different bookmarks must allow exactly one publish"
    );
    srv_handle.abort();

    // 2. Failing `post_land_cmd` on `publish_embargo` MUST auto-revert `master` and return 409!
    let hook_dir = tmp.path().join("srv2");
    let hook_cfg = ServerConfig::new(&hook_dir)
        .with_default_acl(acl)
        .with_post_land_cmd("exit 1");
    let hook_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = hook_listener.local_addr().unwrap();
    let hook_handle = tokio::spawn(async move {
        let _ = serve(hook_listener, hook_cfg).await;
    });
    let hook_base = format!("http://{hook_addr}");

    let seed: CommitResponse = client
        .post(format!("{hook_base}/v1/repos/sec/hookpub/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({
            "files": { "README.md": "clean\n" },
            "message": "Seed",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
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
        .post(format!("{hook_base}/v1/repos/sec/hookpub/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({
            "files": { "fix.rs": "pub fn broken() {}\n" },
            "target": "embargo/cve-hook",
            "embargo_advisory": "cve-hook",
            "embargo_allowed_teams": ["sec"],
            "message": "Embargo hook test",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let pub_fail = client
        .post(format!(
            "{hook_base}/v1/repos/sec/hookpub/embargo/cve-hook/publish"
        ))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({ "target": "master" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        pub_fail.status(),
        StatusCode::CONFLICT,
        "failing post_land_cmd during publish_embargo must trigger O(1) auto-revert (409)"
    );

    let store2 = LocalStore::open(hook_dir.join("repos/sec/hookpub")).unwrap();
    assert_eq!(
        store2.get_bookmark("master").unwrap().map(|h| h.to_hex()),
        Some(seed.changeset_id.clone()),
        "master bookmark must be restored to pre-publish head after auto-revert"
    );

    let outbox2: OutboxResponse = client
        .get(format!("{hook_base}/v1/repos/sec/hookpub/outbox?limit=10"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        outbox2
            .events
            .iter()
            .any(|e| e.event_type == "auto_revert" && e.payload_json.contains("cve-hook")),
        "auto-reverted publish_embargo must record auto_revert outbox event with advisory_id"
    );

    // 2b. Unprivileged `bob` MUST NOT see the auto-reverted embargo event in `/outbox` OR read the
    //     auto-reverted `Published` changeset via `/tree?rev=<hash>` or `/blob/fix.rs?rev=<hash>`!
    let reverted_pub_hash = outbox2
        .events
        .iter()
        .find(|e| e.event_type == "auto_revert")
        .and_then(|e| e.previous_head.clone())
        .expect("auto_revert event should record previous_head");
    let bob_outbox: OutboxResponse = client
        .get(format!("{hook_base}/v1/repos/sec/hookpub/outbox?limit=10"))
        .header("X-Gitx-User", "bob")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !bob_outbox
            .events
            .iter()
            .any(|e| e.payload_json.contains("cve-hook") || e.event_type == "auto_revert"),
        "auto-reverted embargo must NEVER leak via GET /outbox to unprivileged callers: {:?}",
        bob_outbox.events
    );
    let bob_tree: TreeResponse = client
        .get(format!(
            "{hook_base}/v1/repos/sec/hookpub/tree?rev={reverted_pub_hash}"
        ))
        .header("X-Gitx-User", "bob")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        bob_tree.files.is_empty() && bob_tree.rev.is_none(),
        "auto-reverted Published changeset must NOT be readable by bob via /tree?rev="
    );
    let bob_grep: GrepResponse = client
        .get(format!(
            "{hook_base}/v1/repos/sec/hookpub/grep?q=broken&rev={reverted_pub_hash}"
        ))
        .header("X-Gitx-User", "bob")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        bob_grep.matches.is_empty(),
        "auto-reverted Published changeset must NOT match bob /grep?rev="
    );

    // 2b-ii. Unprivileged `bob` MUST NOT be able to un-revert the `auto_revert` land record via
    //        `POST /revert/{auto_revert_land_seq}` to re-expose the auto-reverted embargo!
    let auto_revert_seq = outbox2
        .events
        .iter()
        .find(|e| e.event_type == "auto_revert")
        .map(|e| e.land_seq)
        .expect("auto_revert event should exist");
    let bob_unrevert = client
        .post(format!(
            "{hook_base}/v1/repos/sec/hookpub/revert/{auto_revert_seq}"
        ))
        .header("X-Gitx-User", "bob")
        .send()
        .await
        .unwrap();
    assert!(
        bob_unrevert.status() == StatusCode::CONFLICT
            || bob_unrevert.status() == StatusCode::FORBIDDEN,
        "bob must NEVER be able to un-revert an auto-reverted embargo publication, got {}",
        bob_unrevert.status()
    );
    assert_eq!(
        store2.get_bookmark("master").unwrap().map(|h| h.to_hex()),
        Some(seed.changeset_id),
        "master must remain at pre-publish seed after blocked un-revert attempt"
    );

    // 2c. Authorized embargo member `alice` CAN still commit a fix to `cve-hook` after auto-revert!
    let followup_fix = client
        .post(format!("{hook_base}/v1/repos/sec/hookpub/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({
            "files": { "fix.rs": "pub fn fixed_now() {}\n" },
            "target": "embargo/cve-hook",
            "embargo_advisory": "cve-hook",
            "embargo_allowed_teams": ["sec"],
            "message": "Fix after auto-revert",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        followup_fix.status(),
        StatusCode::OK,
        "follow-up embargo fix commit must be allowed after an auto-reverted publish"
    );
    hook_handle.abort();

    // 3. Orphaned unlanded `Published` changeset (simulating crash/CAS failure between `put_changeset`
    //    and `record_land`) MUST NOT disclose embargo to bob AND MUST NOT brick `publish_embargo`!
    let orphan_dir = tmp.path().join("srv3");
    let orphan_cfg = ServerConfig::new(&orphan_dir).with_default_acl(acl);
    let orphan_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let orphan_addr = orphan_listener.local_addr().unwrap();
    let orphan_handle = tokio::spawn(async move {
        let _ = serve(orphan_listener, orphan_cfg).await;
    });
    let orphan_base = format!("http://{orphan_addr}");

    client
        .post(format!("{orphan_base}/v1/repos/sec/orphan/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({
            "files": { "README.md": "seed\n" },
            "message": "Seed",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    client
        .post(format!("{orphan_base}/v1/repos/sec/orphan/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({
            "files": { "secret_patch.rs": "pub fn patch() {}\n" },
            "target": "embargo/cve-orphan",
            "embargo_advisory": "cve-orphan",
            "embargo_allowed_teams": ["sec"],
            "message": "Active embargo",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Inject an unlanded `Published` changeset directly into LocalStore (simulating crash between
    // `put_changeset` and `record_land`)
    let store3 = LocalStore::open(orphan_dir.join("repos/sec/orphan")).unwrap();
    let pub_blob = store3.put_blob_bytes(b"ORPHAN_SECRET_PATCH\n").unwrap();
    let mut pub_tree = gitx_core::DomainTree::new(gitx_core::DomainId::public());
    pub_tree.insert(
        "secret_patch.rs",
        gitx_core::EntryKind::File {
            blob_hash: pub_blob.manifest_hash(),
            mode: gitx_core::FileMode::Regular,
            size: pub_blob.total_size,
        },
    );
    let pub_tree_h = store3.put_tree(&pub_tree).unwrap();
    let orphan_pub_cs = gitx_core::ChangeSetBuilder::new(gitx_core::Identity {
        name: "Alice".to_string(),
        email: "alice@org.dev".to_string(),
        key_fingerprint: None,
    })
    .domain_tree(gitx_core::DomainId::public(), pub_tree_h)
    .visibility(gitx_core::VisibilityPolicy {
        primary_domain: gitx_core::DomainId::public(),
        reveal_on_land: false,
        embargo: Some(gitx_core::EmbargoState::Published {
            advisory_id: "cve-orphan".to_string(),
            published_at: chrono::Utc::now(),
        }),
    })
    .description("Orphan unlanded publish")
    .build();
    let orphan_pub_id = store3.put_changeset(&orphan_pub_cs).unwrap();

    // Bob MUST NOT be able to read the unlanded orphan `Published` changeset via active `/tree` or `/grep`
    let bob_orphan_tree: TreeResponse = client
        .get(format!(
            "{orphan_base}/v1/repos/sec/orphan/tree?rev={orphan_pub_id}"
        ))
        .header("X-Gitx-User", "bob")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        bob_orphan_tree.files.is_empty() && bob_orphan_tree.rev.is_none(),
        "unlanded orphan Published changeset must NOT be readable by bob via /tree?rev="
    );
    let bob_orphan_grep: GrepResponse = client
        .get(format!(
            "{orphan_base}/v1/repos/sec/orphan/grep?q=ORPHAN_SECRET_PATCH&rev={orphan_pub_id}"
        ))
        .header("X-Gitx-User", "bob")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        bob_orphan_grep.matches.is_empty(),
        "unlanded orphan Published changeset must NOT leak via /grep?rev="
    );

    // Real `publish_embargo` MUST STILL SUCCEED (not permanently bricked by orphan!)
    let real_pub = client
        .post(format!(
            "{orphan_base}/v1/repos/sec/orphan/embargo/cve-orphan/publish"
        ))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({ "target": "master" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        real_pub.status(),
        StatusCode::OK,
        "unlanded Published orphan must NOT brick publish_embargo"
    );
    orphan_handle.abort();

    // 4. Concurrent `GET /outbox` during an in-flight slow `post_land_cmd` that fails MUST NOT
    //    backfill a premature `"land"` row or overwrite the eventual `"auto_revert"` event!
    let slow_dir = tmp.path().join("srv4");
    let slow_cfg = ServerConfig::new(&slow_dir)
        .with_default_acl(acl)
        .with_post_land_cmd("sleep 0.4; exit 1");
    let slow_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    let slow_handle = tokio::spawn(async move {
        let _ = serve(slow_listener, slow_cfg).await;
    });
    let slow_base = format!("http://{slow_addr}");

    client
        .post(format!("{slow_base}/v1/repos/sec/slowhook/commit"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "files": { "a.txt": "v1\n" },
            "message": "Seed",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let staged: CommitResponse = client
        .post(format!("{slow_base}/v1/repos/sec/slowhook/commit"))
        .header("X-Gitx-User", "alice")
        .json(&json!({
            "files": { "a.txt": "v2\n" },
            "update_target": false,
            "message": "Will fail hook",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let land_fut = client
        .post(format!("{slow_base}/v1/repos/sec/slowhook/land"))
        .header("X-Gitx-User", "alice")
        .json(&json!({ "changeset_id": staged.changeset_id, "target": "master" }))
        .send();
    let probe_fut = async {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        client
            .get(format!("{slow_base}/v1/repos/sec/slowhook/outbox?limit=10"))
            .header("X-Gitx-User", "alice")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<OutboxResponse>()
            .await
            .unwrap()
    };
    let (land_res, mid_outbox) = tokio::join!(land_fut, probe_fut);
    assert_eq!(land_res.unwrap().status(), StatusCode::CONFLICT);
    assert!(
        !mid_outbox.events.iter().any(|e| e.event_type == "land"),
        "concurrent GET /outbox during in-flight post_land_cmd must NOT backfill a premature land row: {:?}",
        mid_outbox.events
    );
    let final_outbox: OutboxResponse = client
        .get(format!("{slow_base}/v1/repos/sec/slowhook/outbox?limit=10"))
        .header("X-Gitx-User", "alice")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !final_outbox.events.iter().any(|e| e.event_type == "land"),
        "auto-reverted land must NOT leave behind a bogus land row: {:?}",
        final_outbox.events
    );
    assert!(
        final_outbox
            .events
            .iter()
            .any(|e| e.event_type == "auto_revert" && e.payload_json.contains("reason")),
        "final outbox must preserve the live auto_revert event with reason: {:?}",
        final_outbox.events
    );
    slow_handle.abort();

    // 5. Concurrent unprivileged `POST /commit` (implicit parent = `master`, both `update_target=false`
    //    and `update_target=true`) and `POST /land` during an in-flight failing `publish_embargo`
    //    `post_land_cmd` MUST be rejected with 409 Conflict — never copying the embargo payload into
    //    a public changeset and never sabotaging the auto-revert CAS check!
    let inflight_dir = tmp.path().join("srv5");
    let inflight_cfg = ServerConfig::new(&inflight_dir)
        .with_default_acl(acl)
        .with_post_land_cmd("sleep 0.4; exit 1");
    let inflight_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inflight_addr = inflight_listener.local_addr().unwrap();
    let inflight_handle = tokio::spawn(async move {
        let _ = serve(inflight_listener, inflight_cfg).await;
    });
    let inflight_base = format!("http://{inflight_addr}");

    let seed5: CommitResponse = client
        .post(format!("{inflight_base}/v1/repos/sec/inflight/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({
            "files": { "README.md": "clean base\n" },
            "message": "Seed",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let bob_pre_staged: CommitResponse = client
        .post(format!("{inflight_base}/v1/repos/sec/inflight/commit"))
        .header("X-Gitx-User", "bob")
        .json(&json!({
            "files": { "bob_other.txt": "pre-staged\n" },
            "update_target": false,
            "message": "Bob pre-staged change",
            "author_name": "Bob",
            "author_email": "bob@org.dev"
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
        .post(format!("{inflight_base}/v1/repos/sec/inflight/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({
            "files": { "cve_fix.rs": "pub const SECRET: &str = \"TOP_SECRET_INFLIGHT_EMBARGO_PAYLOAD\";\n" },
            "target": "embargo/cve-inflight",
            "embargo_advisory": "cve-inflight",
            "embargo_allowed_teams": ["sec"],
            "message": "Embargo in-flight test",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let pub_fut = client
        .post(format!(
            "{inflight_base}/v1/repos/sec/inflight/embargo/cve-inflight/publish"
        ))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "sec")
        .json(&json!({ "target": "master" }))
        .send();
    let race_writers_fut = async {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        // Attempt 1: implicit-parent staged commit (`update_target: false`) trying to copy pending `master`
        let c_staged = client
            .post(format!("{inflight_base}/v1/repos/sec/inflight/commit"))
            .header("X-Gitx-User", "bob")
            .json(&json!({
                "files": { "probe.txt": "exfil attempt\n" },
                "update_target": false,
                "message": "Bob implicit-parent exfil probe",
                "author_name": "Bob",
                "author_email": "bob@org.dev"
            }))
            .send()
            .await
            .unwrap()
            .status();
        // Attempt 2: implicit-parent commit advancing `master` (`update_target: true`)
        let c_advance = client
            .post(format!("{inflight_base}/v1/repos/sec/inflight/commit"))
            .header("X-Gitx-User", "bob")
            .json(&json!({
                "files": { "probe2.txt": "advance attempt\n" },
                "message": "Bob advance probe",
                "author_name": "Bob",
                "author_email": "bob@org.dev"
            }))
            .send()
            .await
            .unwrap()
            .status();
        // Attempt 3: concurrent `POST /land` onto `master`
        let c_land = client
            .post(format!("{inflight_base}/v1/repos/sec/inflight/land"))
            .header("X-Gitx-User", "bob")
            .json(&json!({ "changeset_id": bob_pre_staged.changeset_id, "target": "master" }))
            .send()
            .await
            .unwrap()
            .status();
        (c_staged, c_advance, c_land)
    };
    let (pub_res, (c_staged, c_advance, c_land)) = tokio::join!(pub_fut, race_writers_fut);
    assert_eq!(
        c_staged,
        StatusCode::CONFLICT,
        "implicit-parent commit during in-flight publish must be rejected with 409"
    );
    assert_eq!(
        c_advance,
        StatusCode::CONFLICT,
        "target-advancing commit during in-flight publish must be rejected with 409"
    );
    assert_eq!(
        c_land,
        StatusCode::CONFLICT,
        "concurrent land onto pending-verification target must be rejected with 409"
    );
    assert_eq!(
        pub_res.unwrap().status(),
        StatusCode::CONFLICT,
        "publish_embargo must cleanly auto-revert (409, not 500) when post_land_cmd fails"
    );

    // Master must be back at seed5 and bob must see zero embargo content via `/tree` and `/grep`
    let store5 = LocalStore::open(inflight_dir.join("repos/sec/inflight")).unwrap();
    assert_eq!(
        store5.get_bookmark("master").unwrap().map(|h| h.to_hex()),
        Some(seed5.changeset_id)
    );
    let bob_grep5: GrepResponse = client
        .get(format!(
            "{inflight_base}/v1/repos/sec/inflight/grep?q=TOP_SECRET_INFLIGHT_EMBARGO_PAYLOAD"
        ))
        .header("X-Gitx-User", "bob")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(bob_grep5.matches.is_empty());
    inflight_handle.abort();

    // 6. Auto-reverting a `.gitxacl`-adding land on `master` MUST preserve an API-configured
    //    per-repo `<root_dir>/.gitxacl` intact (never overwriting or deleting it mid-hook/revert)!
    let acl_hook_dir = tmp.path().join("srv6");
    let acl_hook_cfg = ServerConfig::new(&acl_hook_dir).with_post_land_cmd("exit 1");
    let acl_hook_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let acl_hook_addr = acl_hook_listener.local_addr().unwrap();
    let acl_hook_handle = tokio::spawn(async move {
        let _ = serve(acl_hook_listener, acl_hook_cfg).await;
    });
    let acl_hook_base = format!("http://{acl_hook_addr}");

    let per_repo_acl = "\
path ** -> public
path packages/private/** -> team:core
domain public read=* write=*
domain team:core read=team:core write=team:core
";
    client
        .post(format!("{acl_hook_base}/v1/repos/sec/aclhook"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Roles", "admin")
        .json(&json!({ "acl": per_repo_acl }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    client
        .post(format!("{acl_hook_base}/v1/repos/sec/aclhook/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Teams", "core")
        .json(&json!({
            "files": {
                "README.md": "ok\n",
                "packages/private/core_only.rs": "pub const SECRET_CORE: &str = \"CORE_SECRET\";\n"
            },
            "message": "Seed without committed .gitxacl",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let staged_acl: CommitResponse = client
        .post(format!("{acl_hook_base}/v1/repos/sec/aclhook/commit"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Roles", "admin")
        .json(&json!({
            "files": { ".gitxacl": "path ** -> public\ndomain public read=* write=*\n" },
            "update_target": false,
            "message": "Staged .gitxacl that fails post_land_cmd",
            "author_name": "Alice",
            "author_email": "alice@org.dev"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let land_acl_fail = client
        .post(format!("{acl_hook_base}/v1/repos/sec/aclhook/land"))
        .header("X-Gitx-User", "alice")
        .header("X-Gitx-Roles", "admin")
        .json(&json!({ "changeset_id": staged_acl.changeset_id, "target": "master" }))
        .send()
        .await
        .unwrap();
    assert_eq!(land_acl_fail.status(), StatusCode::CONFLICT);
    // API-configured per-repo `.gitxacl` MUST still be intact and still deny `bob`!
    let bob_core_write = client
        .post(format!("{acl_hook_base}/v1/repos/sec/aclhook/commit"))
        .header("X-Gitx-User", "bob")
        .json(&json!({
            "files": { "packages/private/pwn.rs": "pwn\n" },
            "update_target": false,
            "message": "Bob probe after auto-reverted .gitxacl land",
            "author_name": "Bob",
            "author_email": "bob@org.dev"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        bob_core_write.status(),
        StatusCode::FORBIDDEN,
        "API-configured per-repo .gitxacl must survive an auto-reverted .gitxacl-adding land"
    );
    acl_hook_handle.abort();
}
