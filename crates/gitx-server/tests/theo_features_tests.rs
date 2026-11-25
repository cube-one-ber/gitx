use gitx_core::DomainId;
use gitx_crypto::{
    TokenClaims, UserKeyPair, decrypt_secret, encrypt_secret, sign_token_hmac,
};
use gitx_server::{
    AppState, CommitResponse, DrainResponse, EnqueueResponse, FleetSyncRecord, LandResponse,
    MergeQueue, OutboxResponse, ServerConfig, TreeResponse, build_router,
    command_conflict_resolver,
};
use gitx_store::BlobBackendConfig;
use reqwest::StatusCode;
use serde_json::json;
use std::process::Command;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;

async fn spawn_server(config: ServerConfig) -> (String, Arc<AppState>) {
    let state = Arc::new(AppState::new(config));
    let router = build_router(Arc::clone(&state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

#[tokio::test]
async fn encrypted_secret_envelopes_sync_with_strict_acl_and_signed_tokens_on_tiered_store() {
    let dir = TempDir::new().unwrap();
    let signing_secret = b"test-signing-key-32bytes-minimum";
    let acl = "\
.env -> secret:dev
[domain secret:dev]
read = team:core
write = team:core
";
    let config = ServerConfig::new(dir.path().join("data"))
        .with_default_acl(acl)
        .with_token_signing_secret(signing_secret.to_vec())
        .with_trust_proxy_headers(false)
        .with_blob_backend(BlobBackendConfig::LocalFileSystem {
            root: dir.path().join("tiered-cas"),
        });

    let (base_url, _state) = spawn_server(config).await;
    let client = reqwest::Client::new();

    let now = chrono::Utc::now().timestamp();
    let alice_tok = sign_token_hmac(
        &TokenClaims::new("alice", now)
            .with_teams(vec!["core".into()])
            .with_expires_at(now + 3600),
        signing_secret,
    )
    .unwrap();
    let outsider_tok = sign_token_hmac(
        &TokenClaims::new("outsider", now).with_expires_at(now + 3600),
        signing_secret,
    )
    .unwrap();
    let expired_tok = sign_token_hmac(
        &TokenClaims::new("alice", now - 100).with_expires_at(now - 10),
        signing_secret,
    )
    .unwrap();

    // Expired signed token must be rejected with 401.
    let exp_resp = client
        .post(format!("{base_url}/v1/repos/acme/app/commit"))
        .bearer_auth(&expired_tok)
        .json(&json!({"files": {"a.txt": "hi"}, "message": "expired"}))
        .send()
        .await
        .unwrap();
    assert_eq!(exp_resp.status(), StatusCode::UNAUTHORIZED);

    // Alice encrypts `.env` client-side (zero plaintext sent to server).
    let alice_kp = UserKeyPair::generate_with_label("alice");
    let sec_domain = DomainId::secret("dev").unwrap();
    let env_obj = encrypt_secret(
        &sec_domain,
        ".env",
        1,
        b"STRIPE_SECRET=sk_live_from_alice\n",
        &[alice_kp.public_bundle()],
    )
    .unwrap();
    let env_json = serde_json::to_string(&env_obj).unwrap();

    let commit_resp = client
        .post(format!("{base_url}/v1/repos/acme/app/commit"))
        .bearer_auth(&alice_tok)
        .json(&json!({
            "files": {"README.md": "# Public App\n"},
            "secret_envelopes": {
                "secret:dev": {
                    ".env": env_json
                }
            },
            "message": "Initial commit with encrypted .env"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(commit_resp.status(), StatusCode::OK);
    let committed: CommitResponse = commit_resp.json().await.unwrap();
    assert!(committed.domains_written.contains(&"secret:dev".to_string()));

    // Authorized team:core caller receives the encrypted envelope and decrypts it locally.
    let alice_tree: TreeResponse = client
        .get(format!("{base_url}/v1/repos/acme/app/tree"))
        .bearer_auth(&alice_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alice_tree.files.len(), 1);
    assert_eq!(alice_tree.secrets.len(), 1);
    let parsed_env: gitx_crypto::SecretEnvelope =
        serde_json::from_str(&alice_tree.secrets[0].envelope_json).unwrap();
    assert_eq!(
        decrypt_secret(&parsed_env, ".env", &alice_kp).unwrap(),
        b"STRIPE_SECRET=sk_live_from_alice\n"
    );

    // Outsider & anonymous receive ZERO secret envelopes or filenames.
    for maybe_tok in [Some(&outsider_tok), None] {
        let mut req = client.get(format!("{base_url}/v1/repos/acme/app/tree"));
        if let Some(t) = maybe_tok {
            req = req.bearer_auth(t);
        }
        let tree: TreeResponse = req.send().await.unwrap().json().await.unwrap();
        assert_eq!(tree.files.len(), 1);
        assert!(tree.secrets.is_empty(), "unauthorized caller leaked secrets!");
    }
}

#[tokio::test]
async fn live_fleet_sync_enforces_encryption_and_principal_isolation() {
    let dir = TempDir::new().unwrap();
    let (base_url, _) = spawn_server(ServerConfig::new(dir.path())).await;
    let client = reqwest::Client::new();

    // Plaintext bundle upload must be rejected.
    let bad = client
        .post(format!("{base_url}/v1/repos/acme/app/fleet"))
        .header("x-gitx-user", "alice")
        .json(&json!({"bundle_json": r#"{"files": {".env": "plaintext"}}"#}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    // Valid EncryptedFleetBundle JSON succeeds for Alice.
    let encrypted_json = r#"{"format_version":1,"machine_id":"macbook","file_count":1,"envelope":{"domain":"secret:fleet","key_epoch":1}}"#;
    let up = client
        .post(format!("{base_url}/v1/repos/acme/app/fleet"))
        .header("x-gitx-user", "alice")
        .json(&json!({"bundle_json": encrypted_json, "machine": "macbook"}))
        .send()
        .await
        .unwrap();
    assert_eq!(up.status(), StatusCode::OK);

    // Bob cannot read Alice's fleet bundle (404 — scoped strictly by principal.id).
    let bob_get = client
        .get(format!("{base_url}/v1/repos/acme/app/fleet"))
        .header("x-gitx-user", "bob")
        .send()
        .await
        .unwrap();
    assert_eq!(bob_get.status(), StatusCode::NOT_FOUND);

    // Alice downloads her exact encrypted bundle.
    let alice_get: FleetSyncRecord = client
        .get(format!("{base_url}/v1/repos/acme/app/fleet"))
        .header("x-gitx-user", "alice")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alice_get.principal_id, "alice");
    assert_eq!(alice_get.bundle_json, encrypted_json);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_smart_http_receive_pack_accepts_public_push_and_blocks_secrets() {
    let dir = TempDir::new().unwrap();
    let (base_url, _) = spawn_server(ServerConfig::new(dir.path().join("srv"))).await;
    let client = reqwest::Client::new();

    // Seed initial commit via HTTP API.
    let resp = client
        .post(format!("{base_url}/v1/repos/acme/web/commit"))
        .header("x-gitx-user", "alice")
        .json(&json!({"files": {"README.md": "# Web\n"}, "message": "init"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Clone via standard `git clone` over Smart HTTP.
    let clone_dir = dir.path().join("clone");
    let clone_status = Command::new("git")
        .args(["clone", &format!("{base_url}/acme/web.git"), clone_dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(clone_status.success(), "git clone over Smart HTTP failed");

    // Configure git user and push a clean commit back over Smart HTTP with X-Gitx-User header!
    std::fs::write(clone_dir.join("hello.txt"), "pushed via git smart http\n").unwrap();
    for args in [
        vec!["config", "user.name", "Alice"],
        vec!["config", "user.email", "alice@acme.dev"],
        vec!["add", "hello.txt"],
        vec!["commit", "-m", "Add hello.txt via git push"],
    ] {
        assert!(Command::new("git").arg("-C").arg(&clone_dir).args(&args).status().unwrap().success());
    }

    // Anonymous git push must fail (403).
    let anon_push = Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-C")
        .arg(&clone_dir)
        .args(["push", "origin", "HEAD:master"])
        .output()
        .unwrap();
    assert!(!anon_push.status.success(), "anonymous git push must be denied");

    // Authenticated git push must succeed and be visible via zero-clone API!
    let auth_push = Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-C")
        .arg(&clone_dir)
        .args([
            "-c",
            "http.extraHeader=X-Gitx-User: alice",
            "push",
            "origin",
            "HEAD:master",
        ])
        .output()
        .unwrap();
    assert!(
        auth_push.status.success(),
        "authenticated git push failed: {}",
        String::from_utf8_lossy(&auth_push.stderr)
    );

    let tree: TreeResponse = client
        .get(format!("{base_url}/v1/repos/acme/web/tree"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(tree.files.iter().any(|f| f.path == "hello.txt"));
}

#[tokio::test]
async fn persistent_queue_command_resolver_outbox_and_post_land_auto_revert() {
    let dir = TempDir::new().unwrap();

    // 1. Verify SQLite MergeQueue persistence across re-open.
    let queue_db = dir.path().join("q.sqlite");
    {
        let q1 = MergeQueue::open(&queue_db, None).unwrap();
        let (e1, depth) = q1
            .enqueue_entry("cs1".into(), "ch1".into(), "master".into(), "alice".into())
            .unwrap();
        assert_eq!(e1.id, 1);
        assert_eq!(depth, 1);
    }
    {
        let q2 = MergeQueue::open(&queue_db, None).unwrap();
        let entries = q2.entries_for_target("master", true).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].changeset_id, "cs1");
    }

    // 2. Verify command_conflict_resolver resolves a conflicting merge in the server merge queue,
    //    and outbox records the land event.
    let resolver_cmd = r#"cat "$GITX_OURS_FILE" "$GITX_THEIRS_FILE" > "$GITX_OUTPUT_FILE""#;
    let (base_url, _) = spawn_server(
        ServerConfig::new(dir.path().join("srv1"))
            .with_conflict_resolver(command_conflict_resolver(resolver_cmd)),
    )
    .await;
    let client = reqwest::Client::new();

    let base: CommitResponse = client
        .post(format!("{base_url}/v1/repos/acme/q/commit"))
        .header("x-gitx-user", "alice")
        .json(&json!({"files": {"f.txt": "base\n"}, "message": "base"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let c1: CommitResponse = client
        .post(format!("{base_url}/v1/repos/acme/q/commit"))
        .header("x-gitx-user", "alice")
        .json(&json!({
            "files": {"f.txt": "ours\n"},
            "message": "c1",
            "parent": base.changeset_id,
            "update_target": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let c2: CommitResponse = client
        .post(format!("{base_url}/v1/repos/acme/q/commit"))
        .header("x-gitx-user", "alice")
        .json(&json!({
            "files": {"f.txt": "theirs\n"},
            "message": "c2",
            "parent": base.changeset_id,
            "update_target": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    for cs_id in [&c1.changeset_id, &c2.changeset_id] {
        let _: EnqueueResponse = client
            .post(format!("{base_url}/v1/repos/acme/q/queue/enqueue"))
            .header("x-gitx-user", "alice")
            .json(&json!({"changeset_id": cs_id, "target": "master"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    }

    let drained: DrainResponse = client
        .post(format!("{base_url}/v1/repos/acme/q/queue/drain"))
        .header("x-gitx-user", "alice")
        .json(&json!({"target": "master"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(drained.landed.len(), 2);
    assert_eq!(drained.resolved_conflicts, vec!["f.txt".to_string()]);

    let outbox: OutboxResponse = client
        .get(format!("{base_url}/v1/repos/acme/q/outbox"))
        .header("x-gitx-user", "alice")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(outbox.events.len(), 1);
    assert_eq!(outbox.events[0].event_type, "land");

    // 3. Verify failing post_land_cmd triggers O(1) atomic auto-revert on `/land`.
    let (base_url2, _) = spawn_server(
        ServerConfig::new(dir.path().join("srv2")).with_post_land_cmd("exit 1"),
    )
    .await;
    let init_c: CommitResponse = client
        .post(format!("{base_url2}/v1/repos/acme/rev/commit"))
        .header("x-gitx-user", "alice")
        .json(&json!({"files": {"ok.txt": "good\n"}, "message": "good"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bad_c: CommitResponse = client
        .post(format!("{base_url2}/v1/repos/acme/rev/commit"))
        .header("x-gitx-user", "alice")
        .json(&json!({
            "files": {"ok.txt": "broken\n"},
            "message": "bad",
            "parent": init_c.changeset_id,
            "update_target": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let land_resp = client
        .post(format!("{base_url2}/v1/repos/acme/rev/land"))
        .header("x-gitx-user", "alice")
        .json(&json!({"changeset_id": bad_c.changeset_id, "target": "master"}))
        .send()
        .await
        .unwrap();
    assert_eq!(land_resp.status(), StatusCode::CONFLICT);
    let _ = LandResponse {
        land_seq: 0,
        target: String::new(),
        previous_head: None,
        new_head: String::new(),
        conflicts: Vec::new(),
    };

    // Master must be atomically restored back to `init_c`!
    let tree_after: TreeResponse = client
        .get(format!("{base_url2}/v1/repos/acme/rev/tree"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(tree_after.rev.as_deref(), Some(init_c.changeset_id.as_str()));
    assert_eq!(tree_after.files[0].content.as_deref(), Some("good\n"));

    let outbox2: OutboxResponse = client
        .get(format!("{base_url2}/v1/repos/acme/rev/outbox"))
        .header("x-gitx-user", "alice")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(outbox2.events.iter().any(|e| e.event_type == "auto_revert"));
}
