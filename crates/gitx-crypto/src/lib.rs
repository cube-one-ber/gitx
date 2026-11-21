pub mod acl;
pub mod envelope;
pub mod keys;
pub mod scanner;

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
