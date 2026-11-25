pub mod acl;
pub mod envelope;
pub mod keys;
pub mod scanner;
pub mod ssh_keys;
pub mod tokens;

pub use acl::{AclPolicy, DomainPermissions, PathRule, Principal, SubjectMatcher};
pub use envelope::{
    AccessEvent, ExposedSecret, SecretAuditLog, SecretEnvelope, WrappedDek, decrypt_secret,
    encrypt_secret, rotate_secret, rotation_report_for_revoked,
};
pub use keys::{
    FINGERPRINT_HEX_LEN, PublicKeyBundle, SecretKeyBundle, UserKeyPair, compute_fingerprint,
};
pub use scanner::{
    SecretFinding, SecretKind, Severity, contains_secrets, route_domain_zero_trust, scan_content,
};
pub use ssh_keys::{
    ed25519_public_to_x25519, encode_openssh_ed25519_private, format_openssh_ed25519_pub,
    parse_openssh_ed25519_private, parse_openssh_ed25519_pub, user_keypair_from_ed25519_seed,
};
pub use tokens::{
    ED25519_TOKEN_PREFIX, HMAC_TOKEN_PREFIX, TokenClaims, sign_token_ed25519, sign_token_hmac,
    verify_token_ed25519, verify_token_hmac,
};
