use chrono::{Duration, TimeZone, Utc};
use gitx_core::{
    ChangeSetBuilder, DomainId, DomainTree, EmbargoState, EntryKind, FileMode, GitxError, Identity,
    ObjectHash, VisibilityPolicy,
};
use gitx_crypto::{
    AccessEvent, AclPolicy, Principal, PublicKeyBundle, SecretAuditLog, SecretEnvelope,
    SecretKeyBundle, SecretKind, SubjectMatcher, UserKeyPair, decrypt_secret, encrypt_secret,
    rotate_secret, rotation_report_for_revoked, route_domain_zero_trust, scan_content,
};
use proptest::prelude::*;

fn test_identity(name: &str) -> Identity {
    Identity {
        name: name.to_string(),
        email: format!("{name}@example.com"),
        key_fingerprint: None,
    }
}

#[test]
fn keypair_generation_serialization_and_signing() {
    let alice = UserKeyPair::generate_with_label("alice@laptop");
    let pub_bundle = alice.public_bundle();
    assert_eq!(alice.fingerprint(), pub_bundle.fingerprint());
    assert_eq!(alice.fingerprint().len(), gitx_crypto::FINGERPRINT_HEX_LEN);
    assert_eq!(alice.label(), Some("alice@laptop"));

    // PublicKeyBundle JSON round-trip
    let pub_json = serde_json::to_string(&pub_bundle).unwrap();
    let pub_roundtrip: PublicKeyBundle = serde_json::from_str(&pub_json).unwrap();
    assert_eq!(pub_bundle, pub_roundtrip);
    assert_eq!(pub_bundle.fingerprint(), pub_roundtrip.fingerprint());

    // SecretKeyBundle JSON round-trip & reconstruction
    let sec_bundle = alice.to_secret_bundle();
    let sec_json = serde_json::to_string(&sec_bundle).unwrap();
    let sec_roundtrip: SecretKeyBundle = serde_json::from_str(&sec_json).unwrap();
    let restored = UserKeyPair::from_secret_bundle(&sec_roundtrip).unwrap();
    assert_eq!(restored.fingerprint(), alice.fingerprint());
    assert_eq!(restored.public_bundle(), pub_bundle);

    // Ed25519 sign & verify
    let msg = b"gitx changeset payload";
    let sig = alice.sign(msg);
    alice.verify(msg, &sig).unwrap();
    pub_bundle.verify(msg, &sig).unwrap();
    assert!(pub_bundle.verify(b"tampered payload", &sig).is_err());

    // Debug output redacts private keys
    let dbg = format!("{alice:?}");
    assert!(dbg.contains("[REDACTED]"));
    let sec_dbg = format!("{sec_bundle:?}");
    assert!(sec_dbg.contains("[REDACTED]"));
}

#[test]
fn multi_recipient_envelope_encrypt_decrypt_and_revocation_rotation() {
    let alice = UserKeyPair::generate_with_label("alice");
    let bob = UserKeyPair::generate_with_label("bob");
    let carol = UserKeyPair::generate_with_label("carol");
    let mallory = UserKeyPair::generate_with_label("mallory");

    let domain = DomainId::secret("prod").unwrap();
    let path = ".env.prod";
    let secret_bytes = b"DATABASE_URL=postgres://user:supersecret@db.internal:5432/app\n";

    // Epoch 1: Alice, Bob, Carol
    let env_v1 = encrypt_secret(
        &domain,
        path,
        1,
        secret_bytes,
        &[
            alice.public_bundle(),
            bob.public_bundle(),
            carol.public_bundle(),
        ],
    )
    .unwrap();

    assert_eq!(env_v1.key_epoch, 1);
    assert_eq!(env_v1.wrapped_keys.len(), 3);
    assert!(env_v1.has_recipient(&alice.fingerprint()));
    assert!(env_v1.has_recipient(&bob.fingerprint()));
    assert!(env_v1.has_recipient(&carol.fingerprint()));
    assert!(!env_v1.has_recipient(&mallory.fingerprint()));

    // All authorized recipients decrypt cleanly
    assert_eq!(decrypt_secret(&env_v1, path, &alice).unwrap(), secret_bytes);
    assert_eq!(decrypt_secret(&env_v1, path, &bob).unwrap(), secret_bytes);
    assert_eq!(decrypt_secret(&env_v1, path, &carol).unwrap(), secret_bytes);

    // Unauthorized recipient gets AccessDenied
    let err = decrypt_secret(&env_v1, path, &mallory).unwrap_err();
    assert!(matches!(err, GitxError::AccessDenied { .. }));

    // Envelope JSON serialization round-trip preserves hash and decryptability
    let serialized = serde_json::to_string(&env_v1).unwrap();
    let deserialized: SecretEnvelope = serde_json::from_str(&serialized).unwrap();
    assert_eq!(env_v1.hash(), deserialized.hash());
    assert_eq!(
        decrypt_secret(&deserialized, path, &bob).unwrap(),
        secret_bytes
    );

    // Rotate secret: revoke Carol, keep only Alice and Bob
    let env_v2 = rotate_secret(
        &env_v1,
        path,
        &alice,
        &[alice.public_bundle(), bob.public_bundle()],
    )
    .unwrap();

    assert_eq!(env_v2.key_epoch, 2);
    assert_eq!(env_v2.domain, domain);
    assert_ne!(env_v2.ciphertext, env_v1.ciphertext);
    assert_ne!(env_v2.nonce, env_v1.nonce);
    assert_ne!(env_v2.hash(), env_v1.hash());
    assert!(!env_v2.has_recipient(&carol.fingerprint()));

    // Alice and Bob can still decrypt epoch 2
    assert_eq!(decrypt_secret(&env_v2, path, &alice).unwrap(), secret_bytes);
    assert_eq!(decrypt_secret(&env_v2, path, &bob).unwrap(), secret_bytes);

    // Carol is revoked and can NO LONGER decrypt epoch 2
    let carol_err = decrypt_secret(&env_v2, path, &carol).unwrap_err();
    assert!(matches!(carol_err, GitxError::AccessDenied { .. }));

    // Even if Carol tries to splice her epoch 1 WrappedDek into epoch 2, unwrap fails!
    let mut spliced = env_v2.clone();
    spliced.wrapped_keys.insert(
        carol.fingerprint(),
        env_v1.wrapped_keys.get(&carol.fingerprint()).unwrap().clone(),
    );
    assert!(decrypt_secret(&spliced, path, &carol).is_err());

    // Empty recipients rejected
    assert!(encrypt_secret(&domain, path, 1, secret_bytes, &[]).is_err());
}

#[test]
fn envelope_aad_rejects_path_domain_epoch_and_ciphertext_tampering() {
    let alice = UserKeyPair::generate();
    let domain = DomainId::secret("dev").unwrap();
    let path = "services/api/.env";
    let env = encrypt_secret(
        &domain,
        path,
        7,
        b"API_KEY=live_1234567890",
        &[alice.public_bundle()],
    )
    .unwrap();

    // 1. Path tamper
    assert!(decrypt_secret(&env, "services/web/.env", &alice).is_err());
    assert!(decrypt_secret(&env, ".env", &alice).is_err());

    // 2. Domain tamper
    let mut bad_domain = env.clone();
    bad_domain.domain = DomainId::secret("prod").unwrap();
    assert!(decrypt_secret(&bad_domain, path, &alice).is_err());

    // 3. Epoch tamper
    let mut bad_epoch = env.clone();
    bad_epoch.key_epoch = 8;
    assert!(decrypt_secret(&bad_epoch, path, &alice).is_err());

    // 4. Nonce tamper
    let mut bad_nonce = env.clone();
    bad_nonce.nonce[0] ^= 0x01;
    assert!(decrypt_secret(&bad_nonce, path, &alice).is_err());

    // 5. Ciphertext tamper
    let mut bad_ct = env.clone();
    bad_ct.ciphertext[0] ^= 0x80;
    assert!(decrypt_secret(&bad_ct, path, &alice).is_err());

    // 6. Wrapped DEK ciphertext tamper
    let mut bad_wrap = env.clone();
    bad_wrap
        .wrapped_keys
        .get_mut(&alice.fingerprint())
        .unwrap()
        .ciphertext[0] ^= 0x01;
    assert!(decrypt_secret(&bad_wrap, path, &alice).is_err());
}

#[test]
fn rotation_report_for_revoked_lists_exact_exposed_versions() {
    let t0 = Utc.with_ymd_and_hms(2026, 6, 1, 10, 0, 0).unwrap();
    let t1 = t0 + Duration::minutes(15);
    let t2 = t0 + Duration::hours(2);
    let t3 = t0 + Duration::hours(5);

    let sec_dev = DomainId::secret("dev").unwrap();
    let sec_prod = DomainId::secret("prod").unwrap();

    let mut log = SecretAuditLog::new();
    // Alice decrypts .env.prod epoch 1 twice
    log.record_decrypt_at("fp_alice", sec_prod.clone(), ".env.prod", 1, t0);
    log.record_decrypt_at("fp_alice", sec_prod.clone(), ".env.prod", 1, t2);
    // Alice decrypts .env.prod epoch 2 once
    log.record_decrypt_at("fp_alice", sec_prod.clone(), ".env.prod", 2, t3);
    // Alice decrypts .env epoch 1 in secret:dev
    log.record_decrypt_at("fp_alice", sec_dev.clone(), ".env", 1, t1);
    // Bob decrypts secrets/stripe.key (should NOT appear in Alice's report)
    log.record_decrypt_at("fp_bob", sec_prod.clone(), "secrets/stripe.key", 3, t1);
    // Alice is revoked
    log.record_revoke_at("fp_alice", sec_prod.clone(), t3 + Duration::minutes(1));

    let report = log.rotation_report_for_revoked("fp_alice");
    assert_eq!(report, rotation_report_for_revoked(log.events(), "fp_alice"));
    assert_eq!(report.len(), 3);

    // Deterministic BTreeMap ordering: (secret:dev, .env, 1), (secret:prod, .env.prod, 1), (secret:prod, .env.prod, 2)
    assert_eq!(report[0].domain, sec_dev);
    assert_eq!(report[0].path, ".env");
    assert_eq!(report[0].key_epoch, 1);
    assert_eq!(report[0].access_count, 1);
    assert_eq!(report[0].first_accessed, t1);
    assert_eq!(report[0].last_accessed, t1);

    assert_eq!(report[1].domain, sec_prod);
    assert_eq!(report[1].path, ".env.prod");
    assert_eq!(report[1].key_epoch, 1);
    assert_eq!(report[1].access_count, 2);
    assert_eq!(report[1].first_accessed, t0);
    assert_eq!(report[1].last_accessed, t2);

    assert_eq!(report[2].domain, sec_prod);
    assert_eq!(report[2].path, ".env.prod");
    assert_eq!(report[2].key_epoch, 2);
    assert_eq!(report[2].access_count, 1);

    // User with zero decrypts gets an empty report
    assert!(rotation_report_for_revoked(log.events(), "fp_nobody").is_empty());

    // Direct slice construction with AccessEvent enum variants works as expected
    let raw_events = vec![
        AccessEvent::Decrypted {
            fingerprint: "fp_x".to_string(),
            domain: sec_dev.clone(),
            path: "secrets/a.key".to_string(),
            key_epoch: 4,
            timestamp: t0,
        },
        AccessEvent::Revoked {
            fingerprint: "fp_x".to_string(),
            domain: sec_dev.clone(),
            timestamp: t1,
        },
    ];
    let raw_report = rotation_report_for_revoked(&raw_events, "fp_x");
    assert_eq!(raw_report.len(), 1);
    assert_eq!(raw_report[0].key_epoch, 4);
}

#[test]
fn acl_default_secure_and_gitxacl_routing_and_permissions() {
    let default_policy = AclPolicy::default_secure();
    let sec_dev = DomainId::secret("dev").unwrap();

    // Built-in default rules route secret patterns to secret:dev
    for secret_path in [
        ".env",
        "apps/web/.env",
        ".env.local",
        "services/api/.env.production",
        "server.pem",
        "certs/tls/ca.pem",
        "id_rsa.key",
        "keys/signing.key",
        "secrets/db.toml",
        "secrets/nested/deep/creds.json",
    ] {
        assert_eq!(
            default_policy.domain_for_path(secret_path),
            sec_dev,
            "expected '{secret_path}' to default to secret:dev"
        );
    }

    // Ordinary paths default to public
    for pub_path in ["README.md", "src/main.rs", "crates/gitx-core/Cargo.toml"] {
        assert_eq!(default_policy.domain_for_path(pub_path), DomainId::public());
    }

    // Parse full .gitxacl overriding defaults and configuring domain permissions
    let gitxacl = r#"
        # Override example env file to be public
        .env.example -> public

        # Route production secrets to secret:prod with strict ACL
        .env.prod -> secret:prod read=team:ops,role:release write=role:release
        secrets/prod/** -> secret:prod

        # Route internal packages to team:core
        packages/internal/** -> team:core

        # Section syntax for secret:dev
        [domain secret:dev]
        read = team:eng, user:contractor
        write = team:eng

        # One-line domain directive with fingerprint match
        domain team:security allow=team:security,fp:deadbeef01234567
    "#;

    let policy = AclPolicy::parse(gitxacl).unwrap();

    // Routing overrides
    assert_eq!(policy.domain_for_path(".env.example"), DomainId::public());
    assert_eq!(
        policy.domain_for_path("apps/web/.env.example"),
        DomainId::public()
    );
    assert_eq!(
        policy.domain_for_path(".env.prod"),
        DomainId::secret("prod").unwrap()
    );
    assert_eq!(
        policy.domain_for_path(".env.local"),
        DomainId::secret("dev").unwrap()
    );
    assert_eq!(
        policy.domain_for_path("secrets/prod/stripe.json"),
        DomainId::secret("prod").unwrap()
    );
    assert_eq!(
        policy.domain_for_path("secrets/dev/local.json"),
        DomainId::secret("dev").unwrap()
    );
    assert_eq!(
        policy.domain_for_path("packages/internal/billing/mod.rs"),
        DomainId::team("core").unwrap()
    );

    // Principals
    let anon = Principal::anonymous();
    let eng = Principal::user("alice").with_team("eng").with_team("core");
    let contractor = Principal::user("contractor");
    let ops = Principal::user("ops_bob").with_team("ops");
    let releaser = Principal::user("rel_carol").with_role("release");
    let sec_key = Principal::user("ci_bot").with_fingerprint("deadbeef01234567");

    let dom_pub = DomainId::public();
    let dom_dev = DomainId::secret("dev").unwrap();
    let dom_prod = DomainId::secret("prod").unwrap();
    let dom_core = DomainId::team("core").unwrap();
    let dom_sec = DomainId::team("security").unwrap();
    let dom_alice_priv = DomainId::private_user("alice").unwrap();

    // Public domain
    assert!(policy.can_read_domain(&anon, &dom_pub));
    assert!(!policy.can_write_domain(&anon, &dom_pub));
    assert!(policy.can_write_domain(&eng, &dom_pub));

    // secret:dev
    assert!(!policy.can_read_domain(&anon, &dom_dev));
    assert!(policy.can_read_domain(&eng, &dom_dev));
    assert!(policy.can_write_domain(&eng, &dom_dev));
    assert!(policy.can_read_domain(&contractor, &dom_dev));
    assert!(!policy.can_write_domain(&contractor, &dom_dev));

    // secret:prod
    assert!(!policy.can_read_domain(&eng, &dom_prod));
    assert!(policy.can_read_domain(&ops, &dom_prod));
    assert!(!policy.can_write_domain(&ops, &dom_prod));
    assert!(policy.can_read_domain(&releaser, &dom_prod));
    assert!(policy.can_write_domain(&releaser, &dom_prod));

    // team:core (implicit team ownership)
    assert!(policy.can_read_domain(&eng, &dom_core));
    assert!(policy.can_write_domain(&eng, &dom_core));
    assert!(!policy.can_read_domain(&ops, &dom_core));
    assert!(!policy.can_read_domain(&anon, &dom_core));

    // team:security (fingerprint match)
    assert!(policy.can_read_domain(&sec_key, &dom_sec));
    assert!(policy.can_write_domain(&sec_key, &dom_sec));
    assert!(!policy.can_read_domain(&eng, &dom_sec));

    // private:user:alice
    assert!(policy.can_read_domain(&eng, &dom_alice_priv));
    assert!(policy.can_write_domain(&eng, &dom_alice_priv));
    assert!(!policy.can_read_domain(&ops, &dom_alice_priv));
    assert!(!policy.can_read_domain(&anon, &dom_alice_priv));

    // Invalid .gitxacl returns an error
    assert!(AclPolicy::parse("not a valid directive").is_err());
    assert!(AclPolicy::parse("domain secret:prod read=invalid_prefix").is_err());
}

#[test]
fn acl_embargo_and_private_changeset_visibility_isolation() {
    let mut policy = AclPolicy::default_secure();
    let sec_prod = DomainId::secret("prod").unwrap();
    policy.grant_read_write(sec_prod.clone(), SubjectMatcher::Role("sre".to_string()));

    let team_security = DomainId::team("security").unwrap();
    let team_distros = DomainId::team("distros").unwrap();
    let team_core = DomainId::team("core").unwrap();

    let h_pub = ObjectHash::of_bytes(b"pub-tree");
    let h_embargo = ObjectHash::of_bytes(b"cve-fix-tree");
    let h_prod = ObjectHash::of_bytes(b"prod-secret-tree");
    let h_core = ObjectHash::of_bytes(b"core-internal-tree");

    // 1. Active embargoed changeset
    let active_vis = VisibilityPolicy::embargoed(
        "cve-2026-0001",
        vec![team_security.clone(), team_distros.clone()],
        Some(Utc::now() + Duration::days(30)),
    )
    .unwrap();
    let embargo_domain = active_vis.primary_domain.clone();

    let active_cs = ChangeSetBuilder::new(test_identity("sec_lead"))
        .visibility(active_vis)
        .domain_tree(DomainId::public(), h_pub)
        .domain_tree(embargo_domain.clone(), h_embargo)
        .domain_tree(sec_prod.clone(), h_prod)
        .description("Fix RCE vulnerability")
        .build();

    let anon = Principal::anonymous();
    let core_dev = Principal::user("dave").with_team("core");
    let sec_eng = Principal::user("eve").with_team("security");
    let distro_maint = Principal::user("frank").with_team("distros");
    let sre_sec = Principal::user("grace")
        .with_team("security")
        .with_role("sre");

    // Unauthorized principals cannot see the active embargoed changeset or ANY of its trees
    assert!(!policy.can_read_changeset(&anon, &active_cs));
    assert!(policy.filter_domain_trees(&anon, &active_cs).is_empty());

    assert!(!policy.can_read_changeset(&core_dev, &active_cs));
    assert!(policy.filter_domain_trees(&core_dev, &active_cs).is_empty());

    // Security & distro principals CAN read the embargoed changeset,
    // see the embargo + public trees, and STILL cannot see secret:prod!
    for p in [&sec_eng, &distro_maint] {
        assert!(policy.can_read_changeset(p, &active_cs));
        let trees = policy.filter_domain_trees(p, &active_cs);
        assert_eq!(trees.len(), 2);
        assert_eq!(trees.get(&DomainId::public()), Some(&h_pub));
        assert_eq!(trees.get(&embargo_domain), Some(&h_embargo));
        assert!(!trees.contains_key(&sec_prod));
    }

    // Security + SRE sees all 3 trees
    let sre_trees = policy.filter_domain_trees(&sre_sec, &active_cs);
    assert_eq!(sre_trees.len(), 3);
    assert_eq!(sre_trees.get(&sec_prod), Some(&h_prod));

    // 2. Published embargoed changeset becomes visible to public, while keeping secret:prod isolated
    let mut published_cs = active_cs.clone();
    published_cs.visibility.embargo = Some(EmbargoState::Published {
        advisory_id: "cve-2026-0001".to_string(),
        published_at: Utc::now(),
    });

    assert!(policy.can_read_changeset(&anon, &published_cs));
    let anon_pub_trees = policy.filter_domain_trees(&anon, &published_cs);
    assert_eq!(anon_pub_trees.len(), 2);
    assert_eq!(anon_pub_trees.get(&DomainId::public()), Some(&h_pub));
    assert_eq!(anon_pub_trees.get(&embargo_domain), Some(&h_embargo));
    assert!(!anon_pub_trees.contains_key(&sec_prod));

    // 3. Private stack with reveal_on_land=true MUST NOT leak staged public tree before landing
    let private_cs = ChangeSetBuilder::new(test_identity("dave"))
        .visibility(VisibilityPolicy::private(team_core.clone(), true))
        .domain_tree(DomainId::public(), h_pub)
        .domain_tree(team_core.clone(), h_core)
        .description("Unannounced feature")
        .build();

    assert!(!policy.can_read_changeset(&anon, &private_cs));
    assert!(policy.filter_domain_trees(&anon, &private_cs).is_empty());

    assert!(policy.can_read_changeset(&core_dev, &private_cs));
    let core_trees = policy.filter_domain_trees(&core_dev, &private_cs);
    assert_eq!(core_trees.len(), 2);
    assert_eq!(core_trees.get(&team_core), Some(&h_core));
    assert_eq!(core_trees.get(&DomainId::public()), Some(&h_pub));
}

#[test]
fn secret_scanner_detects_all_patterns_and_redacts_matches() {
    // 1. .env filename
    let env_findings = scan_content("apps/web/.env.local", b"PORT=3000\n");
    assert!(env_findings.iter().any(|f| f.kind == SecretKind::DotEnvFile));

    // 2. Private key header
    let pem_content = b"-----BEGIN OPENSSH PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n";
    let pem_findings = scan_content("notes.txt", pem_content);
    assert!(
        pem_findings
            .iter()
            .any(|f| f.kind == SecretKind::PrivateKeyHeader && f.line == Some(1))
    );

    // 3. AWS access key
    let aws_raw = "AKIAIOSFODNN7EXAMPLE";
    let aws_content = format!("aws_access_key_id = {aws_raw}\n");
    let aws_findings = scan_content("config.ini", aws_content.as_bytes());
    assert!(
        aws_findings
            .iter()
            .any(|f| f.kind == SecretKind::AwsAccessKey && !f.redacted_match.contains(aws_raw))
    );

    // 4. GitHub tokens (ghp_ and gho_)
    let ghp_raw = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
    let gho_raw = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    let gh_content = format!("token1={ghp_raw}\ntoken2={gho_raw}\n");
    let gh_findings = scan_content("deploy.sh", gh_content.as_bytes());
    let gh_hits: Vec<_> = gh_findings
        .iter()
        .filter(|f| f.kind == SecretKind::GitHubToken)
        .collect();
    assert_eq!(gh_hits.len(), 2);
    assert!(!gh_hits[0].redacted_match.contains(ghp_raw));
    assert!(!gh_hits[1].redacted_match.contains(gho_raw));

    // 5. API key (sk-...)
    let sk_raw = "sk-proj-abc123def456ghi789jkl012";
    let sk_findings = scan_content("client.ts", format!("const key = \"{sk_raw}\";").as_bytes());
    assert!(
        sk_findings
            .iter()
            .any(|f| f.kind == SecretKind::ApiKey && !f.redacted_match.contains(sk_raw))
    );

    // 6. Generic SECRET= / API_KEY= assignments
    let generic_raw = "my_super_hardcoded_secret_99";
    let gen_findings = scan_content(
        "app.conf",
        format!("STRIPE_SECRET={generic_raw}\nMY_API_KEY=\"abcdef1234567890\"\n").as_bytes(),
    );
    let gen_hits: Vec<_> = gen_findings
        .iter()
        .filter(|f| f.kind == SecretKind::GenericSecretAssignment)
        .collect();
    assert_eq!(gen_hits.len(), 2);
    assert!(!gen_hits[0].redacted_match.contains(generic_raw));

    // 7. Placeholders & clean code produce zero findings
    let clean_code = b"
        pub fn connect() {
            let api_key = std::env::var(\"API_KEY\").unwrap();
            let secret = \"${MY_SECRET}\";
            println!(\"connected: {}\", !api_key.is_empty() && !secret.is_empty());
        }
    ";
    assert!(scan_content("src/db.rs", clean_code).is_empty());

    // 8. Zero-trust routing automatically moves leaked secret file into secret:dev
    let policy = AclPolicy::default_secure();
    assert_eq!(
        route_domain_zero_trust("src/db.rs", clean_code, &policy),
        DomainId::public()
    );
    assert_eq!(
        route_domain_zero_trust("src/leaked.rs", aws_content.as_bytes(), &policy),
        DomainId::secret("dev").unwrap()
    );
}

#[test]
fn public_projection_hash_invariant_under_secret_envelope_rotation() {
    let alice = UserKeyPair::generate();
    let bob = UserKeyPair::generate();
    let sec_dev = DomainId::secret("dev").unwrap();

    let mut pub_tree = DomainTree::new(DomainId::public());
    pub_tree.insert(
        "src/lib.rs",
        EntryKind::File {
            blob_hash: ObjectHash::of_bytes(b"pub fn hello() {}"),
            mode: FileMode::Regular,
            size: 17,
        },
    );
    let pub_tree_hash = pub_tree.hash();

    let env1 = encrypt_secret(
        &sec_dev,
        ".env",
        1,
        b"SECRET=alpha_123456",
        &[alice.public_bundle(), bob.public_bundle()],
    )
    .unwrap();
    let mut sec_tree1 = DomainTree::new(sec_dev.clone());
    sec_tree1.insert(
        ".env",
        EntryKind::EncryptedSecret {
            envelope_hash: env1.hash(),
            key_epoch: env1.key_epoch,
            mode: FileMode::Regular,
        },
    );

    let env2 = rotate_secret(&env1, ".env", &alice, &[alice.public_bundle()]).unwrap();
    let mut sec_tree2 = DomainTree::new(sec_dev.clone());
    sec_tree2.insert(
        ".env",
        EntryKind::EncryptedSecret {
            envelope_hash: env2.hash(),
            key_epoch: env2.key_epoch,
            mode: FileMode::Regular,
        },
    );

    let ts = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let change_id = gitx_core::ChangeId::new();
    let author = test_identity("alice");

    let cs1 = ChangeSetBuilder::new(author.clone())
        .change_id(change_id)
        .created_at(ts)
        .description("Initial commit")
        .domain_tree(DomainId::public(), pub_tree_hash)
        .domain_tree(sec_dev.clone(), sec_tree1.hash())
        .build();

    let cs2 = ChangeSetBuilder::new(author)
        .change_id(change_id)
        .created_at(ts)
        .description("Initial commit")
        .domain_tree(DomainId::public(), pub_tree_hash)
        .domain_tree(sec_dev, sec_tree2.hash())
        .build();

    assert_ne!(cs1.id, cs2.id);
    assert_eq!(cs1.public_projection_hash, cs2.public_projection_hash);
}

proptest! {
    #[test]
    fn prop_envelope_roundtrip_and_aad_binding(
        plaintext in prop::collection::vec(any::<u8>(), 0..512),
        path in "[a-z0-9_./-]{1,40}",
        other_suffix in "[a-z0-9]{1,8}",
        epoch in 0u64..10_000,
    ) {
        let alice = UserKeyPair::generate();
        let bob = UserKeyPair::generate();
        let domain = DomainId::secret("dev").unwrap();

        let env = encrypt_secret(
            &domain,
            &path,
            epoch,
            &plaintext,
            &[alice.public_bundle(), bob.public_bundle()],
        ).unwrap();

        prop_assert_eq!(decrypt_secret(&env, &path, &alice).unwrap(), plaintext.clone());
        prop_assert_eq!(decrypt_secret(&env, &path, &bob).unwrap(), plaintext);

        // Wrong path always fails AAD verification
        let wrong_path = format!("{path}_{other_suffix}");
        prop_assert!(decrypt_secret(&env, &wrong_path, &alice).is_err());

        // Single-bit ciphertext corruption always fails authentication
        let mut tampered = env.clone();
        tampered.ciphertext[0] ^= 0x01;
        prop_assert!(decrypt_secret(&tampered, &path, &alice).is_err());
    }

    #[test]
    fn prop_anonymous_never_sees_non_public_trees_under_default_secure(
        secret_env in "[a-z]{2,8}",
        team_name in "[a-z]{2,8}",
        user_name in "[a-z]{2,8}",
    ) {
        let policy = AclPolicy::default_secure();
        let anon = Principal::anonymous();

        let d_sec = DomainId::secret(&secret_env).unwrap();
        let d_team = DomainId::team(&team_name).unwrap();
        let d_priv = DomainId::private_user(&user_name).unwrap();

        let cs = ChangeSetBuilder::new(test_identity("owner"))
            .domain_tree(DomainId::public(), ObjectHash::of_bytes(b"pub"))
            .domain_tree(d_sec.clone(), ObjectHash::of_bytes(b"sec"))
            .domain_tree(d_team.clone(), ObjectHash::of_bytes(b"team"))
            .domain_tree(d_priv.clone(), ObjectHash::of_bytes(b"priv"))
            .build();

        let visible = policy.filter_domain_trees(&anon, &cs);
        prop_assert_eq!(visible.len(), 1);
        prop_assert!(visible.contains_key(&DomainId::public()));
        prop_assert!(!visible.contains_key(&d_sec));
        prop_assert!(!visible.contains_key(&d_team));
        prop_assert!(!visible.contains_key(&d_priv));
    }
}

#[test]
fn openssh_ed25519_import_derives_matching_x25519_and_decrypts_secrets() {
    use gitx_crypto::{
        PublicKeyBundle, encode_openssh_ed25519_private, format_openssh_ed25519_pub,
    };

    let seed = [42u8; 32];
    let pem = encode_openssh_ed25519_private(&seed, "theo@t3.gg");
    let kp = UserKeyPair::from_openssh_ed25519(&pem, None).unwrap();
    assert_eq!(kp.label(), Some("theo@t3.gg"));

    let pub_line = format_openssh_ed25519_pub(&kp.public_bundle().ed25519_public, Some("theo@t3.gg"));
    let imported_pub = PublicKeyBundle::from_openssh_ed25519_pub(&pub_line).unwrap();

    // Derived X25519 key & fingerprint from `.pub` MUST match the PEM private key identically.
    assert_eq!(imported_pub.x25519_public, kp.public_bundle().x25519_public);
    assert_eq!(imported_pub.ed25519_public, kp.public_bundle().ed25519_public);
    assert_eq!(imported_pub.fingerprint(), kp.fingerprint());

    // Encrypting a `.env` secret to the teammate's OpenSSH `.pub` decrypts with their private key!
    let domain = DomainId::secret("prod").unwrap();
    let env = encrypt_secret(&domain, ".env", 1, b"DATABASE_URL=postgres://secret\n", &[imported_pub])
        .unwrap();
    let plain = decrypt_secret(&env, ".env", &kp).unwrap();
    assert_eq!(plain, b"DATABASE_URL=postgres://secret\n");

    // Malformed / wrong-type keys are cleanly rejected.
    assert!(PublicKeyBundle::from_openssh_ed25519_pub("ssh-rsa AAAA fake").is_err());
    assert!(UserKeyPair::from_openssh_ed25519("not-a-pem", None).is_err());
}

#[test]
fn signed_hmac_and_ed25519_tokens_verify_and_reject_tamper_or_expiry() {
    use gitx_crypto::{
        TokenClaims, sign_token_ed25519, sign_token_hmac, verify_token_ed25519, verify_token_hmac,
    };

    let claims = TokenClaims::new("theo", 1_000)
        .with_teams(vec!["core".into(), "security".into()])
        .with_roles(vec!["admin".into()])
        .with_expires_at(2_000);

    let secret = b"super-secret-signing-key";
    let hmac_tok = sign_token_hmac(&claims, secret).unwrap();
    assert!(hmac_tok.starts_with("gitx1h."));

    let principal = verify_token_hmac(&hmac_tok, secret, 1_500).unwrap();
    assert_eq!(principal.id, "theo");
    assert_eq!(principal.teams, vec!["core", "security"]);
    assert_eq!(principal.roles, vec!["admin"]);
    assert!(!principal.is_anonymous);

    // Expired token rejected.
    assert!(verify_token_hmac(&hmac_tok, secret, 2_001).is_err());
    // Wrong secret rejected.
    assert!(verify_token_hmac(&hmac_tok, b"wrong-secret", 1_500).is_err());
    // Tampered token rejected.
    let tampered = format!("{hmac_tok}x");
    assert!(verify_token_hmac(&tampered, secret, 1_500).is_err());

    // Asymmetric Ed25519 signed token roundtrip.
    let kp = UserKeyPair::generate_with_label("issuer");
    let ed_tok = sign_token_ed25519(&claims, &kp).unwrap();
    assert!(ed_tok.starts_with("gitx1e."));
    let ed_principal = verify_token_ed25519(&ed_tok, &kp.public_bundle(), 1_500).unwrap();
    assert_eq!(ed_principal.id, "theo");
    assert!(verify_token_ed25519(&ed_tok, &kp.public_bundle(), 2_500).is_err());
    let other_kp = UserKeyPair::generate();
    assert!(verify_token_ed25519(&ed_tok, &other_kp.public_bundle(), 1_500).is_err());
}
