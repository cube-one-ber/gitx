use chrono::{Duration, Utc};
use gitx_core::{
    ChangeId, ChangeSetBuilder, DomainId, DomainTree, EntryKind, FileMode, GitxError, Identity,
    ObjectHash, OpId, OpKind, OpLogEntry, Stack, StackState, VisibilityPolicy, WorkspaceRef,
    oplog::WorkspaceBackendKind,
};
use gitx_store::{
    BlobBackendConfig, CacheConfig, GcsConfig, ObjectStore, POSTGRES_MIGRATIONS, PostgresConfig,
    PostgresSslMode, S3Config, SQLITE_MIGRATIONS, SqlDialect, SqlMetadataBackend,
    TieredObjectStore, pg_queries, postgres_schema_ddl, sqlite_schema_ddl,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::TempDir;

fn test_identity() -> Identity {
    Identity {
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
        key_fingerprint: Some("fp-alice".to_string()),
    }
}

fn pseudo_random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.max(1);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let val = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        for b in val.to_le_bytes() {
            if out.len() < len {
                out.push(b);
            }
        }
    }
    out
}

fn verify_full_object_store_workflow(store: &TieredObjectStore) {
    // 1. Multi-chunk FastCDC blob persistence
    let large = pseudo_random_bytes(280 * 1024, 0xFACE_B00C_9876_5432);
    let manifest = store.put_blob_bytes(&large).unwrap();
    assert!(manifest.chunks.len() > 1);
    for chunk in &manifest.chunks {
        assert!(store.has_chunk(chunk.hash).unwrap());
    }
    assert_eq!(
        store.read_blob_bytes(manifest.manifest_hash()).unwrap(),
        large
    );

    // 2. DomainTree & ChangeSet revision ordering
    let mut tree = DomainTree::new(DomainId::public());
    tree.insert(
        "src/lib.rs",
        EntryKind::File {
            blob_hash: manifest.manifest_hash(),
            mode: FileMode::Regular,
            size: manifest.total_size,
        },
    );
    let tree_hash = store.put_tree(&tree).unwrap();
    assert_eq!(store.get_tree(tree_hash).unwrap(), tree);

    let cid = ChangeId::new();
    let now = Utc::now();
    let rev1 = ChangeSetBuilder::new(test_identity())
        .change_id(cid)
        .domain_tree(DomainId::public(), tree_hash)
        .created_at(now)
        .description("distributed rev 1")
        .build();
    let rev2 = ChangeSetBuilder::new(test_identity())
        .change_id(cid)
        .previous_revision(Some(rev1.id))
        .domain_tree(DomainId::public(), tree_hash)
        .created_at(now + Duration::seconds(1))
        .description("distributed rev 2")
        .build();
    store.put_changeset(&rev2).unwrap();
    store.put_changeset(&rev1).unwrap();
    assert_eq!(
        store.get_revisions_for_change(cid).unwrap(),
        vec![rev1.clone(), rev2.clone()]
    );

    // 3. Stacks, OpLog, Workspaces
    let stack = Stack {
        name: "dist/stack".to_string(),
        base_target: "main".to_string(),
        changes: vec![cid],
        visibility: VisibilityPolicy::public(),
        state: StackState::InReview,
        created_at: now,
        updated_at: now,
    };
    store.put_stack(&stack).unwrap();
    assert_eq!(store.get_stack("dist/stack").unwrap(), stack);
    assert_eq!(store.list_stacks().unwrap().len(), 1);

    let ws = WorkspaceRef {
        name: "ci-runner".to_string(),
        root_path: None,
        backend: WorkspaceBackendKind::Memory,
        head_changeset: rev2.id,
        head_change_id: cid,
    };
    store.put_workspace(&ws).unwrap();
    assert_eq!(store.get_workspace("ci-runner").unwrap(), Some(ws));

    let op = OpLogEntry {
        id: OpId::new(),
        parent: None,
        timestamp: now,
        kind: OpKind::Init,
        summary: "init distributed store".to_string(),
        bookmarks: BTreeMap::new(),
        workspaces: store.list_workspaces().unwrap(),
        change_heads: BTreeMap::from([(cid, rev2.id)]),
    };
    store.append_op(&op).unwrap();
    assert_eq!(store.latest_op().unwrap(), Some(op));

    // 4. Atomic CAS landing ledger + revert
    let l1 = store.record_land("main", None, rev1.id, vec![cid]).unwrap();
    assert_eq!(l1.land_seq, 1);
    let l2 = store
        .record_land("main", Some(rev1.id), rev2.id, vec![cid])
        .unwrap();
    assert_eq!(l2.land_seq, 2);

    // Stale CAS must fail without mutating bookmark
    let stale_err = store
        .record_land(
            "main",
            Some(rev1.id),
            ObjectHash::of_bytes(b"stale"),
            vec![],
        )
        .unwrap_err();
    assert!(matches!(stale_err, GitxError::Merge(_)));
    assert_eq!(store.get_bookmark("main").unwrap(), Some(rev2.id));

    let l3 = store
        .record_land("main", Some(rev2.id), rev1.id, vec![])
        .unwrap();
    store.mark_reverted(l2.land_seq, l3.land_seq).unwrap();
    assert_eq!(
        store.get_land(l2.land_seq).unwrap().reverted_by,
        Some(l3.land_seq)
    );
}

#[test]
fn tiered_store_over_in_memory_object_store_and_cache_metrics() {
    // Disable write_through so we deterministically observe cold miss -> warm hit -> eviction!
    let cache_cfg = CacheConfig::new(2048, 2).with_write_through(false);
    let store = TieredObjectStore::in_memory(cache_cfg).unwrap();

    let h1 = ObjectHash::of_typed("gitx:chunk:v1", b"chunk-one-payload");
    let h2 = ObjectHash::of_typed("gitx:chunk:v1", b"chunk-two-payload");
    let h3 = ObjectHash::of_typed("gitx:chunk:v1", b"chunk-three-payload");

    store.put_chunk(h1, b"chunk-one-payload").unwrap();
    store.put_chunk(h2, b"chunk-two-payload").unwrap();
    store.put_chunk(h3, b"chunk-three-payload").unwrap();

    assert_eq!(store.cache_metrics().cached_entries, 0);

    // Cold read of h1 -> 1 miss, populated in cache
    assert_eq!(store.get_chunk(h1).unwrap(), b"chunk-one-payload");
    let m1 = store.cache_metrics();
    assert_eq!(m1.misses, 1);
    assert_eq!(m1.hits, 0);
    assert_eq!(m1.cached_entries, 1);

    // Warm read of h1 -> 1 hit
    assert_eq!(store.get_chunk(h1).unwrap(), b"chunk-one-payload");
    let m2 = store.cache_metrics();
    assert_eq!(m2.hits, 1);
    assert_eq!(m2.misses, 1);
    assert!((m2.hit_rate - 0.5).abs() < 1e-6);

    // Cold read of h2 -> 2 misses, cache now at max_entries=2 (h1, h2)
    assert_eq!(store.get_chunk(h2).unwrap(), b"chunk-two-payload");
    assert_eq!(store.cache_metrics().cached_entries, 2);
    assert_eq!(store.cache_metrics().evictions, 0);

    // Touch h1 so h2 becomes the LRU victim, then read h3 -> evicts h2
    assert_eq!(store.get_chunk(h1).unwrap(), b"chunk-one-payload");
    assert_eq!(store.get_chunk(h3).unwrap(), b"chunk-three-payload");
    let m3 = store.cache_metrics();
    assert_eq!(m3.evictions, 1);
    assert_eq!(m3.cached_entries, 2);

    // h1 should still be a hit; h2 should be a miss (re-fetched cleanly from InMemory remote)
    let hits_before = m3.hits;
    let misses_before = m3.misses;
    assert_eq!(store.get_chunk(h1).unwrap(), b"chunk-one-payload");
    assert_eq!(store.cache_metrics().hits, hits_before + 1);

    assert_eq!(store.get_chunk(h2).unwrap(), b"chunk-two-payload");
    assert_eq!(store.cache_metrics().misses, misses_before + 1);
    assert_eq!(store.cache_metrics().evictions, 2);

    // Missing chunk returns NotFound
    let missing = ObjectHash::of_bytes(b"non-existent");
    assert!(!store.has_chunk(missing).unwrap());
    assert!(matches!(
        store.get_chunk(missing),
        Err(GitxError::NotFound(_))
    ));

    // Full ObjectStore suite over InMemory tiered store
    let full_store = TieredObjectStore::in_memory(CacheConfig::default()).unwrap();
    verify_full_object_store_workflow(&full_store);
}

#[test]
fn tiered_store_over_local_filesystem_persists_across_reopen() {
    let dir = TempDir::new().unwrap();
    let blob_dir = dir.path().join("blobs");
    let db_path = dir.path().join("meta.sqlite");

    let payload = pseudo_random_bytes(192 * 1024, 0x1337_C0DE);
    let (manifest_hash, cs_id, land_seq) = {
        let store =
            TieredObjectStore::local_fs(&blob_dir, &db_path, CacheConfig::default()).unwrap();
        let blob = store.put_blob_bytes(&payload).unwrap();

        let mut tree = DomainTree::new(DomainId::public());
        tree.insert(
            "weights/model.bin",
            EntryKind::File {
                blob_hash: blob.manifest_hash(),
                mode: FileMode::Regular,
                size: blob.total_size,
            },
        );
        let tree_hash = store.put_tree(&tree).unwrap();

        let cid = ChangeId::new();
        let cs = ChangeSetBuilder::new(test_identity())
            .change_id(cid)
            .domain_tree(DomainId::public(), tree_hash)
            .description("persist on local object_store")
            .build();
        store.put_changeset(&cs).unwrap();

        let land = store.record_land("master", None, cs.id, vec![cid]).unwrap();
        assert!(store.cache_metrics().puts > 0);
        (blob.manifest_hash(), cs.id, land.land_seq)
    };

    // Reopen fresh TieredObjectStore with empty cache and verify cold-read persistence
    let reopened =
        TieredObjectStore::local_fs(&blob_dir, &db_path, CacheConfig::default()).unwrap();
    assert_eq!(reopened.cache_metrics().cached_entries, 0);

    let read_back = reopened.read_blob_bytes(manifest_hash).unwrap();
    assert_eq!(read_back, payload);
    let m_cold = reopened.cache_metrics();
    assert!(m_cold.misses > 0, "first read after reopen must miss cache");

    // Second read should be 100% cache hits
    let hits_before = m_cold.hits;
    let misses_before = m_cold.misses;
    assert_eq!(reopened.read_blob_bytes(manifest_hash).unwrap(), payload);
    let m_warm = reopened.cache_metrics();
    assert!(m_warm.hits > hits_before);
    assert_eq!(m_warm.misses, misses_before);

    // Verify metadata persisted across reopen
    assert_eq!(reopened.get_bookmark("master").unwrap(), Some(cs_id));
    assert_eq!(reopened.get_land(land_seq).unwrap().new_head, cs_id);
    assert_eq!(reopened.get_changeset(cs_id).unwrap().id, cs_id);

    // Clearing cache forces subsequent reads to hit remote LocalFileSystem again
    reopened.clear_cache();
    assert_eq!(reopened.cache_metrics().cached_entries, 0);
    let misses_before_clear = reopened.cache_metrics().misses;
    assert_eq!(reopened.read_blob_bytes(manifest_hash).unwrap(), payload);
    assert!(reopened.cache_metrics().misses > misses_before_clear);
}

#[tokio::test]
async fn tiered_store_works_cleanly_inside_tokio_current_thread_runtime() {
    let store = TieredObjectStore::in_memory(CacheConfig::default()).unwrap();
    let blob = store.put_blob_bytes(b"tokio-bridge-test-payload").unwrap();
    store.clear_cache();
    let out = store.read_blob_bytes(blob.manifest_hash()).unwrap();
    assert_eq!(out, b"tokio-bridge-test-payload");
}

#[test]
fn s3_r2_and_gcs_config_builders_and_validation() {
    // AWS S3 config builds a real object_store::aws::AmazonS3 client
    let s3_cfg = S3Config::new("gitx-cas-prod", "us-east-1")
        .with_credentials("AKIAEXAMPLE", "secret-example")
        .with_prefix("tenant-a");
    assert!(s3_cfg.validate().is_ok());
    let s3_store = BlobBackendConfig::S3(s3_cfg.clone())
        .build_object_store()
        .unwrap();
    let meta = Arc::new(SqlMetadataBackend::in_memory_sqlite().unwrap());
    let _tiered = TieredObjectStore::new(s3_store, meta, CacheConfig::default()).unwrap();

    // Cloudflare R2 helper sets auto region and R2 endpoint
    let r2_cfg = S3Config::cloudflare_r2("acct123", "gitx-r2", "r2-key", "r2-secret");
    assert_eq!(r2_cfg.region, "auto");
    assert_eq!(
        r2_cfg.endpoint.as_deref(),
        Some("https://acct123.r2.cloudflarestorage.com")
    );
    assert!(r2_cfg.build().is_ok());

    // Invalid empty bucket rejected
    assert!(S3Config::new("", "us-east-1").validate().is_err());
    assert!(S3Config::new("bucket", "").validate().is_err());

    // GCS config validation
    let gcs_cfg = GcsConfig::new("gitx-gcs-bucket").with_prefix("cas-v1");
    assert!(gcs_cfg.validate().is_ok());
    assert_eq!(BlobBackendConfig::Gcs(gcs_cfg).key_prefix(), Some("cas-v1"));
    assert!(GcsConfig::new("  ").validate().is_err());
}

#[test]
fn postgres_config_migrations_and_sql_metadata_backend_verification() {
    // SQLite backend records all migrations cleanly
    let sqlite_meta = SqlMetadataBackend::in_memory_sqlite().unwrap();
    assert_eq!(sqlite_meta.dialect(), SqlDialect::Sqlite);
    assert_eq!(sqlite_meta.migrations().len(), SQLITE_MIGRATIONS.len());
    assert_eq!(sqlite_meta.applied_migrations().unwrap(), vec![1, 2]);
    let sqlite_ddl = sqlite_schema_ddl();
    assert!(sqlite_ddl.contains("CREATE TABLE IF NOT EXISTS changesets"));
    assert!(sqlite_ddl.contains("CREATE TABLE IF NOT EXISTS lands"));
    assert!(sqlite_ddl.contains("CREATE TABLE IF NOT EXISTS land_outbox"));

    // Valid PostgresConfig + URI normalization + custom schema DDL
    let pg_cfg = PostgresConfig::new("postgres://gitx:pass@db.internal:5432/gitx_prod")
        .with_max_connections(32)
        .with_min_connections(4)
        .with_connect_timeout_secs(15)
        .with_schema("gitx_meta")
        .with_ssl_mode(PostgresSslMode::VerifyFull)
        .with_application_name("gitx-prod");

    pg_cfg.validate().unwrap();
    let uri = pg_cfg.connection_uri().unwrap();
    assert!(uri.contains("sslmode=verify-full"));
    assert!(uri.contains("connect_timeout=15"));
    assert!(uri.contains("application_name=gitx-prod"));

    let pg_backend = SqlMetadataBackend::from_postgres_config(pg_cfg.clone()).unwrap();
    assert_eq!(pg_backend.dialect(), SqlDialect::Postgres);
    assert_eq!(pg_backend.postgres_config(), Some(&pg_cfg));
    assert_eq!(pg_backend.migrations().len(), POSTGRES_MIGRATIONS.len());

    let ddl = pg_backend.schema_ddl().unwrap();
    assert!(ddl.contains("CREATE SCHEMA IF NOT EXISTS gitx_meta;"));
    assert!(ddl.contains("SET search_path TO gitx_meta, public;"));
    assert!(ddl.contains("BIGSERIAL PRIMARY KEY"));
    assert!(ddl.contains("BYTEA NOT NULL"));
    assert!(ddl.contains("TIMESTAMPTZ NOT NULL"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS land_outbox"));

    // Verify full Postgres DDL and parameterized query constants
    let raw_pg_ddl = postgres_schema_ddl();
    assert!(raw_pg_ddl.contains("idx_changesets_change_id"));
    assert!(raw_pg_ddl.contains("idx_lands_target"));
    assert!(pg_queries::LOCK_BOOKMARK_FOR_CAS.contains("FOR UPDATE"));
    assert!(pg_queries::INSERT_LAND_RETURNING.contains("RETURNING land_seq"));
    assert!(pg_queries::UPSERT_BOOKMARK.contains("ON CONFLICT"));

    // Validation catches invalid Postgres configs
    assert!(PostgresConfig::new("mysql://host/db").validate().is_err());
    assert!(PostgresConfig::new("postgres://host").validate().is_err());
    assert!(
        PostgresConfig::new("postgres://host/db")
            .with_max_connections(0)
            .validate()
            .is_err()
    );
    assert!(
        PostgresConfig::new("postgres://host/db")
            .with_max_connections(4)
            .with_min_connections(8)
            .validate()
            .is_err()
    );
    assert!(
        PostgresConfig::new("postgres://host/db")
            .with_schema("bad;DROP TABLE lands")
            .validate()
            .is_err()
    );

    // Credentials are redacted in Debug output and validation errors
    let bad_secret_pg = PostgresConfig::new("mysql://admin:SuperSecretPass99@db.internal/gitx");
    let dbg_str = format!("{bad_secret_pg:?}");
    assert!(!dbg_str.contains("SuperSecretPass99"));
    let err_str = bad_secret_pg.validate().unwrap_err().to_string();
    assert!(!err_str.contains("SuperSecretPass99"));

    let s3_dbg = format!(
        "{:?}",
        S3Config::new("b", "us-east-1").with_credentials("AKIAKEY", "VerySecretKey99")
    );
    assert!(!s3_dbg.contains("VerySecretKey99"));
}

#[test]
fn local_store_rejects_oversized_lz4_header_and_enforces_atomic_revert() {
    use gitx_store::LocalStore;

    let tmp = TempDir::new().unwrap();
    let store = LocalStore::open(tmp.path()).unwrap();

    // Write a forged CAS chunk claiming a 1 GiB uncompressed payload
    let fake_hash = ObjectHash::of_bytes(b"lz4-bomb-test");
    let hex = fake_hash.to_hex();
    let shard = tmp.path().join("cas").join(&hex[..2]);
    std::fs::create_dir_all(&shard).unwrap();
    let mut forged = Vec::new();
    forged.extend_from_slice(&(1024u32 * 1024 * 1024).to_le_bytes());
    forged.extend_from_slice(&[0u8; 16]);
    std::fs::write(shard.join(&hex), &forged).unwrap();

    let err = store.get_chunk(fake_hash).unwrap_err();
    assert!(
        err.to_string().contains("exceeds limit"),
        "expected decompression cap error, got: {err}"
    );

    // Atomic revert_land rejects non-tip land and double revert
    let pub_dom = DomainId::public();
    let t1 = store.put_tree(&DomainTree::new(pub_dom.clone())).unwrap();
    let cs1 = ChangeSetBuilder::new(test_identity())
        .domain_tree(pub_dom.clone(), t1)
        .description("cs1")
        .build();
    store.put_changeset(&cs1).unwrap();
    let cs2 = ChangeSetBuilder::new(test_identity())
        .parents(vec![cs1.id])
        .domain_tree(pub_dom, t1)
        .description("cs2")
        .build();
    store.put_changeset(&cs2).unwrap();

    let l1 = store
        .record_land("master", None, cs1.id, vec![cs1.change_id])
        .unwrap();
    let l2 = store
        .record_land("master", Some(cs1.id), cs2.id, vec![cs2.change_id])
        .unwrap();

    // Reverting non-tip l1 fails
    assert!(store.revert_land(l1.land_seq).is_err());
    // Reverting tip l2 succeeds and moves bookmark back to cs1
    let rev = store.revert_land(l2.land_seq).unwrap();
    assert_eq!(rev.new_head, cs1.id);
    assert_eq!(store.get_bookmark("master").unwrap(), Some(cs1.id));
    // Double-reverting l2 fails
    assert!(store.revert_land(l2.land_seq).is_err());
}

#[test]
fn live_postgres_driver_validates_redacts_and_handles_unreachable_endpoint_safely() {
    // SQLite backend reports is_live_postgres() == false.
    let sqlite_meta = SqlMetadataBackend::in_memory_sqlite().unwrap();
    assert!(!sqlite_meta.is_live_postgres());

    // Invalid URL rejects before connecting and redacts password.
    let err = match SqlMetadataBackend::connect_postgres_url(
        "mysql://user:TopSecretPgPass42@127.0.0.1:5432/gitx",
    ) {
        Ok(_) => panic!("expected invalid postgres URL to fail"),
        Err(e) => e,
    };
    assert!(!err.to_string().contains("TopSecretPgPass42"));

    // Valid Postgres URL pointing to an unbound local port returns clean storage error
    // without panicking (both outside and inside an active Tokio runtime).
    let closed_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unused_port = closed_listener.local_addr().unwrap().port();
    drop(closed_listener);

    let unreachable_url =
        format!("postgres://gitx:TopSecretPgPass42@127.0.0.1:{unused_port}/gitx_test");
    let conn_err = match SqlMetadataBackend::connect_postgres_url(&unreachable_url) {
        Ok(_) => panic!("expected unreachable postgres to fail"),
        Err(e) => e,
    };
    assert!(!conn_err.to_string().contains("TopSecretPgPass42"));

    // Verify connecting from inside a Tokio runtime does not panic ("cannot start runtime from within a runtime").
    let rt = tokio::runtime::Runtime::new().unwrap();
    let rt_err = rt.block_on(async {
        match SqlMetadataBackend::connect_postgres_url(&unreachable_url) {
            Ok(_) => panic!("expected unreachable postgres to fail inside tokio"),
            Err(e) => e,
        }
    });
    assert!(!rt_err.to_string().contains("TopSecretPgPass42"));

    // Optional live PostgreSQL end-to-end suite when `GITX_TEST_POSTGRES_URL` is configured.
    if let Ok(live_url) = std::env::var("GITX_TEST_POSTGRES_URL") {
        let cfg =
            PostgresConfig::new(live_url).with_schema(format!("gitx_test_{}", std::process::id()));
        let pg_meta = SqlMetadataBackend::connect_postgres(cfg).expect("connect live postgres");
        assert!(pg_meta.is_live_postgres());
        let store = TieredObjectStore::from_config(
            &BlobBackendConfig::InMemory,
            Arc::new(pg_meta),
            CacheConfig::default(),
        )
        .unwrap();
        verify_full_object_store_workflow(&store);
    }
}
