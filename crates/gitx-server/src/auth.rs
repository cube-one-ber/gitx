use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use gitx_core::{ChangeSet, DomainId, EmbargoState};
use gitx_crypto::{AclPolicy, Principal};
use gitx_store::ObjectStore;
use std::collections::BTreeSet;
use std::convert::Infallible;

pub const HEADER_USER: &str = "x-gitx-user";
pub const HEADER_TEAMS: &str = "x-gitx-teams";
pub const HEADER_ROLES: &str = "x-gitx-roles";
pub const HEADER_FINGERPRINT: &str = "x-gitx-fingerprint";

/// Extract a [`Principal`] from incoming HTTP request headers.
///
/// - No `X-Gitx-User` header (or empty) -> [`Principal::anonymous()`], which can ONLY read `public`.
/// - `X-Gitx-User: <user>` + optional `X-Gitx-Teams`, `X-Gitx-Roles`, `X-Gitx-Fingerprint` ->
///   authenticated [`Principal`].
pub fn extract_principal(headers: &HeaderMap) -> Principal {
    let Some(user) = header_str(headers, HEADER_USER).filter(|s| !s.is_empty()) else {
        return Principal::anonymous();
    };

    let mut principal = Principal::user(user);

    if let Some(teams_raw) = header_str(headers, HEADER_TEAMS) {
        let teams = split_csv(teams_raw);
        if !teams.is_empty() {
            principal = principal.with_teams(teams);
        }
    }

    if let Some(roles_raw) = header_str(headers, HEADER_ROLES) {
        let roles = split_csv(roles_raw);
        if !roles.is_empty() {
            principal = principal.with_roles(roles);
        }
    }

    if let Some(fp) = header_str(headers, HEADER_FINGERPRINT).filter(|s| !s.is_empty()) {
        principal = principal.with_fingerprint(fp);
    }

    principal
}

/// Axum extractor that resolves the caller's [`Principal`] from request headers.
#[derive(Debug, Clone)]
pub struct AuthenticatedPrincipal(pub Principal);

impl<S> FromRequestParts<S> for AuthenticatedPrincipal
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(extract_principal(&parts.headers)))
    }
}

/// Filter `candidate_domains` to the sorted, deduplicated subset that `principal`
/// is permitted to read under `policy`.
///
/// Anonymous principals can NEVER receive non-public domains unless explicitly
/// authorized, and built-in non-public domains (`team:*`, `secret:*`, `private:*`,
/// `embargo:*`) are always denied for anonymous callers.
pub fn allowed_domains_for_repo(
    policy: &AclPolicy,
    principal: &Principal,
    candidate_domains: &[DomainId],
) -> Vec<DomainId> {
    let mut allowed: BTreeSet<DomainId> = BTreeSet::new();
    for domain in candidate_domains {
        if principal.is_anonymous && !domain.is_public() {
            continue;
        }
        if policy.can_read_domain(principal, domain) {
            allowed.insert(domain.clone());
        }
    }
    allowed.into_iter().collect()
}

/// Collect all domains known in `store` and `policy` and return the effective list of
/// domains that `principal` is authorized to read, including any active/published embargo
/// primary domains unlocked via `policy.can_read_changeset`.
pub fn effective_allowed_domains(
    store: &dyn ObjectStore,
    policy: &AclPolicy,
    principal: &Principal,
) -> Vec<DomainId> {
    let mut candidates: BTreeSet<DomainId> = BTreeSet::new();
    candidates.insert(DomainId::public());

    for rule in policy.path_rules() {
        candidates.insert(rule.domain.clone());
    }
    for domain in policy.domain_permissions().keys() {
        candidates.insert(domain.clone());
    }

    let changesets = store.list_changesets().unwrap_or_default();
    let mut unlocked_embargo_domains: BTreeSet<DomainId> = BTreeSet::new();

    for cs in &changesets {
        candidates.insert(cs.visibility.primary_domain.clone());
        for domain in cs.domain_trees.keys() {
            candidates.insert(domain.clone());
        }
        if let Some(EmbargoState::Active {
            allowed_domains, ..
        }) = &cs.visibility.embargo
        {
            for d in allowed_domains {
                candidates.insert(d.clone());
            }
            if !principal.is_anonymous && policy.can_read_changeset(principal, cs) {
                unlocked_embargo_domains.insert(cs.visibility.primary_domain.clone());
            }
        } else if let Some(EmbargoState::Published { .. }) = &cs.visibility.embargo
            && policy.can_read_changeset(principal, cs)
        {
            unlocked_embargo_domains.insert(cs.visibility.primary_domain.clone());
        }
    }

    let candidate_vec: Vec<DomainId> = candidates.into_iter().collect();
    let mut allowed: BTreeSet<DomainId> =
        allowed_domains_for_repo(policy, principal, &candidate_vec)
            .into_iter()
            .collect();

    for dom in unlocked_embargo_domains {
        if !principal.is_anonymous || dom.is_public() {
            allowed.insert(dom);
        }
    }

    allowed.into_iter().collect()
}

/// Check whether `principal` is authorized to write to `domain` under `policy`,
/// taking into account admin roles and embargo allowed domains.
pub fn can_write_domain_effective(
    policy: &AclPolicy,
    principal: &Principal,
    domain: &DomainId,
    embargo_allowed_domains: &[DomainId],
) -> bool {
    if principal.is_anonymous {
        return policy.can_write_domain(principal, domain);
    }

    if principal.roles.iter().any(|r| r == "admin") {
        return true;
    }

    if policy.can_write_domain(principal, domain) {
        return true;
    }

    if domain.is_embargo() {
        if embargo_allowed_domains.is_empty() {
            return true;
        }
        return embargo_allowed_domains
            .iter()
            .any(|d| !d.is_public() && policy.can_write_domain(principal, d));
    }

    domain.is_secret() && !policy.domain_permissions().contains_key(domain)
}

/// Check whether `principal` is authorized to publish an active embargoed changeset.
pub fn can_publish_embargo(policy: &AclPolicy, principal: &Principal, cs: &ChangeSet) -> bool {
    if principal.is_anonymous {
        return false;
    }
    if principal.roles.iter().any(|r| r == "admin") {
        return true;
    }
    policy.can_read_changeset(principal, cs)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}
