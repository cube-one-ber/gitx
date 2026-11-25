use gitx_crypto::Principal;
use gitx_proto::gitx_service_client::GitxServiceClient;
use gitx_proto::{
    ActorAgent, BlameRequest, CommitRequest, CreateRepoRequest, DiffRequest,
    DrainMergeQueueRequest, EnqueueMergeRequest, FileWrite, GetTreeRequest, GrepRequest,
    HealthRequest, LandRequest, ListReposRequest, ReadBlobRequest, RevertRequest,
};
use gitx_server::{AppState, ServerConfig, serve_grpc};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::{Code, Request};

const CORE_TOKEN: &str = "tok-core-alice-001";
const PUBLIC_TOKEN: &str = "tok-public-viewer-002";

struct GrpcTestServer {
    addr: SocketAddr,
    _tmp: TempDir,
    handle: JoinHandle<()>,
}

impl GrpcTestServer {
    async fn start(default_acl: Option<&str>) -> Self {
        let tmp = TempDir::new().expect("temp dir");
        let mut config = ServerConfig::new(tmp.path())
            .with_token(
                CORE_TOKEN,
                Principal::user("alice").with_teams(["core", "security"]),
            )
            .with_token(PUBLIC_TOKEN, Principal::user("public-reader"));

        if let Some(acl) = default_acl {
            config = config.with_default_acl(acl);
        }

        let state = Arc::new(AppState::new(config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let _ = serve_grpc(listener, state).await;
        });

        Self {
            addr,
            _tmp: tmp,
            handle,
        }
    }

    async fn client(&self) -> GitxServiceClient<Channel> {
        let endpoint = format!("http://{}", self.addr);
        GitxServiceClient::connect(endpoint)
            .await
            .expect("connect gRPC client")
    }
}

impl Drop for GrpcTestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn with_bearer<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    let val: MetadataValue<_> = format!("Bearer {token}").parse().unwrap();
    req.metadata_mut().insert("authorization", val);
    req
}

#[tokio::test]
async fn grpc_end_to_end_zero_clone_and_merge_queue_workflow() {
    let srv = GrpcTestServer::start(None).await;
    let mut client = srv.client().await;

    // 1. Health
    let health = client
        .health(Request::new(HealthRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(health.status, "ok");

    // 2. CreateRepo & ListRepos
    let created = client
        .create_repo(with_bearer(
            CreateRepoRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                acl: None,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    let repo_info = created.repo.expect("repo info");
    assert_eq!(repo_info.full_name, "acme/platform");

    let listed = client
        .list_repos(with_bearer(
            ListReposRequest {
                owner: Some("acme".to_string()),
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.repos.len(), 1);
    assert_eq!(listed.repos[0].full_name, "acme/platform");

    // 3. Initial Commit (v1)
    let c1 = client
        .commit(with_bearer(
            CommitRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                files: vec![
                    FileWrite {
                        path: "src/lib.rs".to_string(),
                        content: b"pub fn alpha() -> u32 {\n    1\n}\n".to_vec(),
                    },
                    FileWrite {
                        path: "assets/raw.bin".to_string(),
                        content: vec![0x00, 0xFF, 0x10, 0xAB],
                    },
                ],
                delete_files: vec![],
                message: "Initial gRPC commit".to_string(),
                author_name: "Alice".to_string(),
                author_email: "alice@acme.dev".to_string(),
                actor_agent: Some(ActorAgent {
                    harness: "gitx-grpc-test".to_string(),
                    model: "test-model".to_string(),
                    session_id: "sess-1".to_string(),
                }),
                target: None,
                parent: None,
                update_target: Some(true),
                visibility_domain: None,
                embargo_advisory: None,
                embargo_allowed_teams: vec![],
                context_prompt: Some("Create alpha helper".to_string()),
                secret_envelopes: vec![],
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(c1.domains_written, vec!["public"]);

    // 4. Second Commit (v2) modifying src/lib.rs without advancing master yet -> test Land & Revert
    let c2 = client
        .commit(with_bearer(
            CommitRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                files: vec![FileWrite {
                    path: "src/lib.rs".to_string(),
                    content:
                        b"pub fn alpha() -> u32 {\n    1\n}\n\npub fn beta() -> u32 {\n    2\n}\n"
                            .to_vec(),
                }],
                delete_files: vec![],
                message: "Add beta helper".to_string(),
                author_name: "Bob".to_string(),
                author_email: "bob@acme.dev".to_string(),
                actor_agent: None,
                target: Some("master".to_string()),
                parent: Some(c1.changeset_id.clone()),
                update_target: Some(false),
                visibility_domain: None,
                embargo_advisory: None,
                embargo_allowed_teams: vec![],
                context_prompt: None,
                secret_envelopes: vec![],
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();

    // Land c2 onto master
    let landed = client
        .land(with_bearer(
            LandRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                changeset_id: c2.changeset_id.clone(),
                target: "master".to_string(),
                expected_head: Some(c1.changeset_id.clone()),
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(landed.land_seq, 1);
    assert_eq!(landed.new_head, c2.changeset_id);
    assert!(landed.conflicts.is_empty());

    // 5. GetTree & ReadBlob (by path and by blob_hash, including binary asset)
    let tree = client
        .get_tree(with_bearer(
            GetTreeRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                rev: None,
                domain: None,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(tree.files.len(), 2);

    let bin_entry = tree
        .files
        .iter()
        .find(|f| f.path == "assets/raw.bin")
        .expect("binary file in tree");
    assert_eq!(bin_entry.content, vec![0x00, 0xFF, 0x10, 0xAB]);

    let blob_by_path = client
        .read_blob(with_bearer(
            ReadBlobRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                rev: None,
                path: "src/lib.rs".to_string(),
                blob_hash: None,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(String::from_utf8_lossy(&blob_by_path.content).contains("pub fn beta()"));

    let blob_by_hash = client
        .read_blob(with_bearer(
            ReadBlobRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                rev: None,
                path: String::new(),
                blob_hash: Some(bin_entry.blob_hash.clone()),
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(blob_by_hash.path, "assets/raw.bin");
    assert_eq!(blob_by_hash.content, vec![0x00, 0xFF, 0x10, 0xAB]);

    // 6. Diff
    let diff = client
        .diff(with_bearer(
            DiffRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                from: Some(c1.changeset_id.clone()),
                to: Some(c2.changeset_id.clone()),
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(diff.files.len(), 1);
    assert_eq!(diff.files[0].status, "modified");
    assert!(diff.unified_diff.contains("+pub fn beta()"));

    // 7. Grep
    let grep = client
        .grep(with_bearer(
            GrepRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                query: "beta".to_string(),
                rev: None,
                case_insensitive: false,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(grep.matches.len(), 1);
    assert_eq!(grep.matches[0].path, "src/lib.rs");
    assert_eq!(grep.matches[0].line_number, 5);

    // 8. Blame (lines 1-3 Alice, lines 5-7 Bob)
    let blame = client
        .blame(with_bearer(
            BlameRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                path: "src/lib.rs".to_string(),
                rev: None,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(blame.lines.len(), 7);
    assert_eq!(blame.lines[0].author_name, "Alice");
    assert_eq!(blame.lines[4].author_name, "Bob");

    // 9. Revert land_seq 1 -> restores master to c1
    let reverted = client
        .revert(with_bearer(
            RevertRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                land_seq: landed.land_seq,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reverted.reverted_land_seq, landed.land_seq);
    assert_eq!(reverted.restored_head, c1.changeset_id);

    // Confirm beta() is gone after O(1) revert
    let post_revert_blob = client
        .read_blob(with_bearer(
            ReadBlobRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                rev: None,
                path: "src/lib.rs".to_string(),
                blob_hash: None,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!String::from_utf8_lossy(&post_revert_blob.content).contains("beta"));

    // 10. EnqueueMerge & DrainMergeQueue with 2 parallel changesets on c1
    let q1 = client
        .commit(with_bearer(
            CommitRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                files: vec![FileWrite {
                    path: "src/worker_a.rs".to_string(),
                    content: b"pub fn worker_a() {}\n".to_vec(),
                }],
                delete_files: vec![],
                message: "Add worker_a".to_string(),
                author_name: "Agent A".to_string(),
                author_email: "agent-a@acme.dev".to_string(),
                actor_agent: None,
                target: Some("master".to_string()),
                parent: Some(c1.changeset_id.clone()),
                update_target: Some(false),
                visibility_domain: None,
                embargo_advisory: None,
                embargo_allowed_teams: vec![],
                context_prompt: None,
                secret_envelopes: vec![],
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();

    let q2 = client
        .commit(with_bearer(
            CommitRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                files: vec![FileWrite {
                    path: "src/worker_b.rs".to_string(),
                    content: b"pub fn worker_b() {}\n".to_vec(),
                }],
                delete_files: vec![],
                message: "Add worker_b".to_string(),
                author_name: "Agent B".to_string(),
                author_email: "agent-b@acme.dev".to_string(),
                actor_agent: None,
                target: Some("master".to_string()),
                parent: Some(c1.changeset_id.clone()),
                update_target: Some(false),
                visibility_domain: None,
                embargo_advisory: None,
                embargo_allowed_teams: vec![],
                context_prompt: None,
                secret_envelopes: vec![],
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();

    let enq1 = client
        .enqueue_merge(with_bearer(
            EnqueueMergeRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                changeset_id: q1.changeset_id.clone(),
                target: "master".to_string(),
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(enq1.queue_depth, 1);

    let enq2 = client
        .enqueue_merge(with_bearer(
            EnqueueMergeRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                changeset_id: q2.changeset_id.clone(),
                target: "master".to_string(),
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(enq2.queue_depth, 2);

    let drained = client
        .drain_merge_queue(with_bearer(
            DrainMergeQueueRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                target: "master".to_string(),
                max_batch_size: None,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(drained.landed.len(), 2);
    assert!(drained.conflicted.is_empty());
    assert!(drained.rejected.is_empty());
    assert!(drained.land_seq.is_some());

    // Both worker files are now present on master
    let final_tree = client
        .get_tree(with_bearer(
            GetTreeRequest {
                owner: "acme".to_string(),
                name: "platform".to_string(),
                rev: None,
                domain: None,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    let paths: Vec<&str> = final_tree.files.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.contains(&"src/worker_a.rs"));
    assert!(paths.contains(&"src/worker_b.rs"));
}

#[tokio::test]
async fn grpc_enforces_bearer_auth_and_strict_acl_isolation() {
    let acl = "packages/private/** -> team:core\n.env -> secret:prod allow=team:security\n";
    let srv = GrpcTestServer::start(Some(acl)).await;
    let mut client = srv.client().await;

    // 1. Invalid bearer token is rejected with UNAUTHENTICATED
    let bad_auth = client
        .list_repos(with_bearer(ListReposRequest { owner: None }, "invalid-tok"))
        .await
        .unwrap_err();
    assert_eq!(bad_auth.code(), Code::Unauthenticated);

    // 2. Privileged core+security token commits public, private (team:core), and secret (secret:prod) files
    let c_pub = client
        .commit(with_bearer(
            CommitRequest {
                owner: "org".to_string(),
                name: "mono".to_string(),
                files: vec![FileWrite {
                    path: "src/public.rs".to_string(),
                    content: b"pub const PUBLIC_HELLO: &str = \"hello_world\";\n".to_vec(),
                }],
                delete_files: vec![],
                message: "Public commit".to_string(),
                author_name: "Alice".to_string(),
                author_email: "alice@org.dev".to_string(),
                actor_agent: None,
                target: None,
                parent: None,
                update_target: Some(true),
                visibility_domain: None,
                embargo_advisory: None,
                embargo_allowed_teams: vec![],
                context_prompt: None,
                secret_envelopes: vec![],
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(c_pub.domains_written, vec!["public"]);

    let c_priv = client
        .commit(with_bearer(
            CommitRequest {
                owner: "org".to_string(),
                name: "mono".to_string(),
                files: vec![
                    FileWrite {
                        path: "packages/private/billing.rs".to_string(),
                        content:
                            b"pub const SECRET_CORE_FORMULA: &str = \"CORE_ONLY_SECRET_999\";\n"
                                .to_vec(),
                    },
                    FileWrite {
                        path: ".env".to_string(),
                        content: b"PROD_API_KEY=SUPER_SENSITIVE_PROD_SECRET\n".to_vec(),
                    },
                ],
                delete_files: vec![],
                message: "Private billing + prod env".to_string(),
                author_name: "Alice".to_string(),
                author_email: "alice@org.dev".to_string(),
                actor_agent: None,
                target: None,
                parent: None,
                update_target: Some(true),
                visibility_domain: None,
                embargo_advisory: None,
                embargo_allowed_teams: vec![],
                context_prompt: None,
                secret_envelopes: vec![],
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(c_priv.domains_written.contains(&"team:core".to_string()));

    // Authorized token retrieves private file and records its blob_hash
    let priv_blob = client
        .read_blob(with_bearer(
            ReadBlobRequest {
                owner: "org".to_string(),
                name: "mono".to_string(),
                rev: None,
                path: "packages/private/billing.rs".to_string(),
                blob_hash: None,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(String::from_utf8_lossy(&priv_blob.content).contains("CORE_ONLY_SECRET_999"));

    // 3. PUBLIC TOKEN ISOLATION: must NEVER see private or secret files across any RPC!
    let pub_tree = client
        .get_tree(with_bearer(
            GetTreeRequest {
                owner: "org".to_string(),
                name: "mono".to_string(),
                rev: None,
                domain: None,
            },
            PUBLIC_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    let pub_paths: Vec<&str> = pub_tree.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(pub_paths, vec!["src/public.rs"]);

    // Public token explicitly requesting private domain -> PERMISSION_DENIED
    let dom_err = client
        .get_tree(with_bearer(
            GetTreeRequest {
                owner: "org".to_string(),
                name: "mono".to_string(),
                rev: None,
                domain: Some("team:core".to_string()),
            },
            PUBLIC_TOKEN,
        ))
        .await
        .unwrap_err();
    assert_eq!(dom_err.code(), Code::PermissionDenied);

    // Public token ReadBlob on private path, .env, AND private blob_hash -> NOT_FOUND (zero leak)
    for (path, hash) in [
        ("packages/private/billing.rs", None),
        (".env", None),
        ("", Some(priv_blob.blob_hash.clone())),
    ] {
        let err = client
            .read_blob(with_bearer(
                ReadBlobRequest {
                    owner: "org".to_string(),
                    name: "mono".to_string(),
                    rev: None,
                    path: path.to_string(),
                    blob_hash: hash,
                },
                PUBLIC_TOKEN,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            Code::NotFound,
            "public token should not read private blob (path='{path}')"
        );
    }

    // Public token Grep for private and secret strings -> ZERO matches
    for needle in ["CORE_ONLY_SECRET_999", "SUPER_SENSITIVE_PROD_SECRET"] {
        let grep = client
            .grep(with_bearer(
                GrepRequest {
                    owner: "org".to_string(),
                    name: "mono".to_string(),
                    query: needle.to_string(),
                    rev: None,
                    case_insensitive: false,
                },
                PUBLIC_TOKEN,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(
            grep.matches.is_empty(),
            "public gRPC grep leaked {needle}: {:?}",
            grep.matches
        );
    }

    // Public token Diff from c_pub to c_priv -> ZERO private diffs
    let pub_diff = client
        .diff(with_bearer(
            DiffRequest {
                owner: "org".to_string(),
                name: "mono".to_string(),
                from: Some(c_pub.changeset_id.clone()),
                to: Some(c_priv.changeset_id.clone()),
            },
            PUBLIC_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(pub_diff.files.is_empty());
    assert!(pub_diff.unified_diff.is_empty());

    // Public token Blame on private path -> NOT_FOUND
    let blame_err = client
        .blame(with_bearer(
            BlameRequest {
                owner: "org".to_string(),
                name: "mono".to_string(),
                path: "packages/private/billing.rs".to_string(),
                rev: None,
            },
            PUBLIC_TOKEN,
        ))
        .await
        .unwrap_err();
    assert_eq!(blame_err.code(), Code::NotFound);

    // Public token attempting to write to private path -> PERMISSION_DENIED
    let write_err = client
        .commit(with_bearer(
            CommitRequest {
                owner: "org".to_string(),
                name: "mono".to_string(),
                files: vec![FileWrite {
                    path: "packages/private/pwn.rs".to_string(),
                    content: b"fn pwn() {}\n".to_vec(),
                }],
                delete_files: vec![],
                message: "Unauthorized private write".to_string(),
                author_name: "Public".to_string(),
                author_email: "public@org.dev".to_string(),
                actor_agent: None,
                target: None,
                parent: None,
                update_target: Some(true),
                visibility_domain: None,
                embargo_advisory: None,
                embargo_allowed_teams: vec![],
                context_prompt: None,
                secret_envelopes: vec![],
            },
            PUBLIC_TOKEN,
        ))
        .await
        .unwrap_err();
    assert_eq!(write_err.code(), Code::PermissionDenied);

    // Anonymous (no bearer header) attempting to land -> PERMISSION_DENIED
    let anon_land = client
        .land(Request::new(LandRequest {
            owner: "org".to_string(),
            name: "mono".to_string(),
            changeset_id: c_pub.changeset_id.clone(),
            target: "master".to_string(),
            expected_head: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(anon_land.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn grpc_parity_log_why_symbols_rebase_embargo_fleet_and_secret_envelopes() {
    use gitx_core::DomainId;
    use gitx_crypto::{UserKeyPair, encrypt_secret};
    use gitx_proto::{
        DownloadFleetBundleRequest, LogRequest, PublishEmbargoRequest, RebaseRequest,
        SecretEnvelopeEntry, SymbolsRequest, UploadFleetBundleRequest, WhyRequest,
    };

    let acl = "\
.env -> secret:dev
[domain secret:dev]
read = team:core
write = team:core
";
    let srv = GrpcTestServer::start(Some(acl)).await;
    let mut client = srv.client().await;

    let alice_kp = UserKeyPair::generate_with_label("alice");
    let env_obj = encrypt_secret(
        &DomainId::secret("dev").unwrap(),
        ".env",
        1,
        b"GRPC_SECRET=super_hidden\n",
        &[alice_kp.public_bundle()],
    )
    .unwrap();

    // 1. Commit with context_prompt AND encrypted secret_envelope via gRPC!
    let c1 = client
        .commit(with_bearer(
            CommitRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                files: vec![FileWrite {
                    path: "src/engine.rs".to_string(),
                    content: b"pub fn run_engine() -> u32 {\n    42\n}\n".to_vec(),
                }],
                delete_files: vec![],
                message: "Initial engine + encrypted .env".to_string(),
                author_name: "Alice".to_string(),
                author_email: "alice@acme.dev".to_string(),
                actor_agent: None,
                target: None,
                parent: None,
                update_target: Some(true),
                visibility_domain: None,
                embargo_advisory: None,
                embargo_allowed_teams: vec![],
                context_prompt: Some("Implement deterministic engine entrypoint".to_string()),
                secret_envelopes: vec![SecretEnvelopeEntry {
                    domain: "secret:dev".to_string(),
                    path: ".env".to_string(),
                    envelope_json: serde_json::to_string(&env_obj).unwrap(),
                }],
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(c1.domains_written.contains(&"secret:dev".to_string()));

    // 2. Log RPC
    let log = client
        .log(with_bearer(
            LogRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                rev: None,
                limit: Some(10),
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(log.commits.len(), 1);
    assert_eq!(log.commits[0].changeset_id, c1.changeset_id);

    // 3. Why RPC
    let why = client
        .why(with_bearer(
            WhyRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                path: "src/engine.rs".to_string(),
                line: Some(1),
                rev: None,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(why.matches_json.contains("deterministic engine entrypoint"));

    // 4. Symbols RPC
    let syms = client
        .symbols(with_bearer(
            SymbolsRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                rev: None,
                path: None,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(syms.symbols.iter().any(|s| s.name == "run_engine"));

    // 5. Rebase RPC
    let master_adv = client
        .commit(with_bearer(
            CommitRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                files: vec![FileWrite {
                    path: "src/engine.rs".to_string(),
                    content: b"pub fn run_engine() -> u32 {\n    42\n}\npub fn master_fn() {}\n"
                        .to_vec(),
                }],
                delete_files: vec![],
                message: "Add master_fn".to_string(),
                author_name: "Alice".to_string(),
                author_email: "alice@acme.dev".to_string(),
                actor_agent: None,
                target: None,
                parent: None,
                update_target: Some(true),
                visibility_domain: None,
                embargo_advisory: None,
                embargo_allowed_teams: vec![],
                context_prompt: None,
                secret_envelopes: vec![],
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();

    let feat = client
        .commit(with_bearer(
            CommitRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                files: vec![FileWrite {
                    path: "src/engine.rs".to_string(),
                    content: b"pub fn run_engine() -> u32 {\n    42\n}\npub fn feat_fn() {}\n"
                        .to_vec(),
                }],
                delete_files: vec![],
                message: "Add feat_fn".to_string(),
                author_name: "Alice".to_string(),
                author_email: "alice@acme.dev".to_string(),
                actor_agent: None,
                target: None,
                parent: Some(c1.changeset_id.clone()),
                update_target: Some(false),
                visibility_domain: None,
                embargo_advisory: None,
                embargo_allowed_teams: vec![],
                context_prompt: None,
                secret_envelopes: vec![],
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();

    let rebased = client
        .rebase(with_bearer(
            RebaseRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                changeset_id: feat.changeset_id,
                onto: "master".to_string(),
                update_bookmark: Some("feat-grpc".to_string()),
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!rebased.has_conflicts);
    assert_eq!(rebased.onto, master_adv.changeset_id);

    // 6. Embargo commit + PublishEmbargo RPC
    let _embargo = client
        .commit(with_bearer(
            CommitRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                files: vec![FileWrite {
                    path: "src/patch.rs".to_string(),
                    content: b"pub fn cve_fix() -> bool { true }\n".to_vec(),
                }],
                delete_files: vec![],
                message: "CVE-2026-9999 fix".to_string(),
                author_name: "Alice".to_string(),
                author_email: "alice@acme.dev".to_string(),
                actor_agent: None,
                target: None,
                parent: None,
                update_target: Some(false),
                visibility_domain: None,
                embargo_advisory: Some("CVE-2026-9999".to_string()),
                embargo_allowed_teams: vec!["security".to_string()],
                context_prompt: None,
                secret_envelopes: vec![],
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();

    let published = client
        .publish_embargo(with_bearer(
            PublishEmbargoRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                advisory: "CVE-2026-9999".to_string(),
                target: Some("master".to_string()),
                message: Some("Publish CVE-2026-9999".to_string()),
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(published.advisory, "CVE-2026-9999");
    assert!(published.land_seq >= 1);

    // 7. UploadFleetBundle + DownloadFleetBundle RPC (scoped per principal!)
    let enc_bundle = r#"{"format_version":1,"machine_id":"box-a","file_count":1,"envelope":{"domain":"secret:fleet","key_epoch":1}}"#;
    let uploaded = client
        .upload_fleet_bundle(with_bearer(
            UploadFleetBundleRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                bundle_json: enc_bundle.to_string(),
                machine: Some("box-a".to_string()),
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(uploaded.principal_id, "alice");

    // Different principal cannot read Alice's fleet bundle.
    let other_err = client
        .download_fleet_bundle(with_bearer(
            DownloadFleetBundleRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                machine: None,
            },
            PUBLIC_TOKEN,
        ))
        .await
        .unwrap_err();
    assert_eq!(other_err.code(), Code::NotFound);

    let downloaded = client
        .download_fleet_bundle(with_bearer(
            DownloadFleetBundleRequest {
                owner: "acme".to_string(),
                name: "parity".to_string(),
                machine: None,
            },
            CORE_TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(downloaded.bundle_json, enc_bundle);
}
