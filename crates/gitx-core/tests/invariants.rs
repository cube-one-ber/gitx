use chrono::Utc;
use gitx_core::{
    ChangeId, ChangeSetBuilder, DomainId, DomainTree, EntryKind, FileMode, Identity, ObjectHash,
    VisibilityPolicy, chunk_bytes,
};
use proptest::prelude::*;

fn test_identity() -> Identity {
    Identity {
        name: "Theo".into(),
        email: "theo@t3.gg".into(),
        key_fingerprint: None,
    }
}

#[test]
fn public_projection_hash_is_invariant_to_private_and_secret_domains() {
    let ts = Utc::now();
    let cid = ChangeId::new();

    let mut pub_tree = DomainTree::new(DomainId::public());
    pub_tree.insert(
        "src/main.rs",
        EntryKind::File {
            blob_hash: ObjectHash::of_bytes(b"fn main() {}"),
            mode: FileMode::Regular,
            size: 12,
        },
    );
    let pub_hash = pub_tree.hash();

    let cs_public_only = ChangeSetBuilder::new(test_identity())
        .change_id(cid)
        .created_at(ts)
        .description("initial commit")
        .domain_tree(DomainId::public(), pub_hash)
        .build();

    let mut secret_tree = DomainTree::new(DomainId::secret("prod").unwrap());
    secret_tree.insert(
        ".env",
        EntryKind::EncryptedSecret {
            envelope_hash: ObjectHash::of_bytes(b"ciphertext-v1"),
            key_epoch: 1,
            mode: FileMode::Regular,
        },
    );

    let mut private_tree = DomainTree::new(DomainId::team("core").unwrap());
    private_tree.insert(
        "packages/private/secret.rs",
        EntryKind::File {
            blob_hash: ObjectHash::of_bytes(b"pub const MAGIC: u64 = 42;"),
            mode: FileMode::Regular,
            size: 26,
        },
    );

    let cs_with_private = ChangeSetBuilder::new(test_identity())
        .change_id(cid)
        .created_at(ts)
        .description("initial commit")
        .domain_tree(DomainId::public(), pub_hash)
        .domain_tree(DomainId::secret("prod").unwrap(), secret_tree.hash())
        .domain_tree(DomainId::team("core").unwrap(), private_tree.hash())
        .build();

    // Full revision IDs differ because private/secret trees were attached...
    assert_ne!(cs_public_only.id, cs_with_private.id);
    // ...but the public projection hash is BYTE-FOR-BYTE IDENTICAL!
    assert_eq!(
        cs_public_only.public_projection_hash,
        cs_with_private.public_projection_hash
    );
}

#[test]
fn embargoed_changes_hide_public_tree_and_description_from_public_projection() {
    let ts = Utc::now();
    let cid = ChangeId::new();

    let mut pub_tree = DomainTree::new(DomainId::public());
    pub_tree.insert(
        "src/auth.rs",
        EntryKind::File {
            blob_hash: ObjectHash::of_bytes(b"patched auth check"),
            mode: FileMode::Regular,
            size: 18,
        },
    );

    let vis = VisibilityPolicy::embargoed(
        "cve-2026-0001",
        vec![DomainId::team("security").unwrap()],
        None,
    )
    .unwrap();

    let cs_a = ChangeSetBuilder::new(test_identity())
        .change_id(cid)
        .created_at(ts)
        .description("Fix critical RCE in auth")
        .visibility(vis.clone())
        .domain_tree(DomainId::public(), pub_tree.hash())
        .build();

    let cs_b = ChangeSetBuilder::new(test_identity())
        .change_id(cid)
        .created_at(ts)
        .description("completely different secret description")
        .visibility(vis)
        .build();

    assert_eq!(cs_a.public_projection_hash, cs_b.public_projection_hash);
}

proptest! {
    #[test]
    fn fastcdc_roundtrip_preserves_bytes_and_content_hash(data in prop::collection::vec(any::<u8>(), 0..200_000)) {
        let (blob, chunks) = chunk_bytes(&data);
        prop_assert_eq!(blob.total_size as usize, data.len());
        let mut reassembled = Vec::with_capacity(data.len());
        for (meta, (hash, bytes)) in blob.chunks.iter().zip(chunks.iter()) {
            prop_assert_eq!(meta.hash, *hash);
            prop_assert_eq!(meta.length as usize, bytes.len());
            reassembled.extend_from_slice(bytes);
        }
        prop_assert_eq!(reassembled, data);
    }
}
