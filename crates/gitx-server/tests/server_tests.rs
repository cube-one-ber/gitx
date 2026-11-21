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
