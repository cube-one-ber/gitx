use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use gitx_core::{ChangeSet, DomainId, EmbargoState};
use gitx_crypto::{AclPolicy, Principal};
use gitx_store::ObjectStore;
use std::collections::BTreeSet;
use std::sync::Arc;
use tonic::Status;
use tonic::metadata::MetadataMap;

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

/// Axum extractor that resolves the caller's [`Principal`] from `Authorization: Bearer <token>`
/// (strictly validated against [`AppState`] tokens) and, ONLY when [`AppState::trusts_proxy_headers`]
/// is enabled, falls back to `X-Gitx-*` reverse-proxy headers.
#[derive(Debug, Clone)]
pub struct AuthenticatedPrincipal(pub Principal);

impl FromRequestParts<Arc<AppState>> for AuthenticatedPrincipal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let principal = extract_principal_from_http(state, &parts.headers)?;
        Ok(Self(principal))
    }
}

/// Extract and authenticate a [`Principal`] from HTTP request headers against [`AppState`].
pub fn extract_principal_from_http(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<Principal, ApiError> {
    if let Some(auth_val) = headers.get(AUTHORIZATION) {
        let raw = auth_val
            .to_str()
            .map_err(|_| ApiError::unauthorized("authorization header must be valid ASCII"))?
            .trim();

        let Some((scheme, token)) = raw.split_once(' ') else {
            return Err(ApiError::unauthorized(
                "invalid authorization header; expected 'Bearer <token>'",
            ));
        };
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(ApiError::unauthorized(
                "unsupported authorization scheme; expected 'Bearer <token>'",
            ));
        }
        let token = token.trim();
        if token.is_empty() {
            return Err(ApiError::unauthorized("empty bearer token"));
        }

        if let Some(principal) = state.resolve_token(token) {
            return Ok(principal);
        }

        if state.has_configured_tokens() || !state.trusts_proxy_headers() {
            return Err(ApiError::unauthorized(
                "invalid or unrecognized bearer token",
            ));
        }

        // Local-dev / trusted-proxy mode with zero configured bearer tokens:
        // only fall back to proxy headers if `X-Gitx-User` was explicitly supplied.
        let header_principal = extract_principal(headers);
        if !header_principal.is_anonymous {
            return Ok(header_principal);
        }
        return Err(ApiError::unauthorized(
            "invalid or unrecognized bearer token",
        ));
    }

    if state.trusts_proxy_headers() {
        Ok(extract_principal(headers))
    } else {
        Ok(Principal::anonymous())
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

/// Collect all non-embargo domains known in `store` and `policy` that `principal` is authorized
/// to read. Active `embargo:*` domains are intentionally excluded from this flat allowlist so
/// per-changeset `AclPolicy::can_read_changeset` checks govern every embargoed commit.
pub fn readable_non_embargo_domains(
    store: &dyn ObjectStore,
    policy: &AclPolicy,
    principal: &Principal,
) -> Vec<DomainId> {
    let mut candidates: BTreeSet<DomainId> = BTreeSet::new();
    candidates.insert(DomainId::public());

    for rule in policy.path_rules() {
        if !rule.domain.is_embargo() {
            candidates.insert(rule.domain.clone());
        }
    }
    for domain in policy.domain_permissions().keys() {
        if !domain.is_embargo() {
            candidates.insert(domain.clone());
        }
    }

    let changesets = store.list_changesets().unwrap_or_default();
    for cs in &changesets {
        if !cs.visibility.primary_domain.is_embargo() {
            candidates.insert(cs.visibility.primary_domain.clone());
        }
        for domain in cs.domain_trees.keys() {
            if !domain.is_embargo() {
                candidates.insert(domain.clone());
            }
        }
        if let Some(EmbargoState::Active {
            allowed_domains, ..
        }) = &cs.visibility.embargo
        {
            for d in allowed_domains {
                if !d.is_embargo() {
                    candidates.insert(d.clone());
                }
            }
        }
    }

    let candidate_vec: Vec<DomainId> = candidates.into_iter().collect();
    allowed_domains_for_repo(policy, principal, &candidate_vec)
}

/// Collect all domains known in `store` and `policy` and return the effective list of
/// domains that `principal` is authorized to read (for context `/why` and `/derived/stats`).
///
/// An `embargo:<advisory>` domain is included ONLY when `principal` can read EVERY active
/// embargo changeset for that advisory in `store`, preventing decoy changesets from unlocking
/// an advisory's domain id.
pub fn effective_allowed_domains(
    store: &dyn ObjectStore,
    policy: &AclPolicy,
    principal: &Principal,
) -> Vec<DomainId> {
    let mut allowed: BTreeSet<DomainId> = readable_non_embargo_domains(store, policy, principal)
        .into_iter()
        .collect();

    let changesets = store.list_changesets().unwrap_or_default();
    let mut readable_embargoes: BTreeSet<DomainId> = BTreeSet::new();
    let mut unreadable_active_embargoes: BTreeSet<DomainId> = BTreeSet::new();

    for cs in &changesets {
        if !cs.visibility.primary_domain.is_embargo() {
            continue;
        }
        match &cs.visibility.embargo {
            Some(EmbargoState::Active { .. }) => {
                if !principal.is_anonymous && policy.can_read_changeset(principal, cs) {
                    readable_embargoes.insert(cs.visibility.primary_domain.clone());
                } else {
                    unreadable_active_embargoes.insert(cs.visibility.primary_domain.clone());
                }
            }
            Some(EmbargoState::Published { .. })
                if policy.can_read_changeset(principal, cs) =>
            {
                readable_embargoes.insert(cs.visibility.primary_domain.clone());
            }
            Some(EmbargoState::Published { .. }) | None => {}
        }
    }

    for dom in readable_embargoes {
        if !unreadable_active_embargoes.contains(&dom) {
            allowed.insert(dom);
        }
    }

    allowed.into_iter().collect()
}

/// Check whether `principal` is authorized to administer `.gitxacl` policy changes.
///
/// Only callers with `role:admin` (or explicit write permission on the `acl` domain in the
/// existing policy) may modify `.gitxacl`. Anonymous callers are always denied.
pub fn can_administer_acl(policy: &AclPolicy, principal: &Principal) -> bool {
    if principal.is_anonymous {
        return false;
    }
    if principal.roles.iter().any(|r| r == "admin") {
        return true;
    }
    if let Ok(acl_domain) = DomainId::new("acl")
        && policy.domain_permissions().contains_key(&acl_domain)
    {
        return policy.can_write_domain(principal, &acl_domain);
    }
    false
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
            return false;
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
    let embargo_allowed = match &cs.visibility.embargo {
        Some(EmbargoState::Active {
            allowed_domains, ..
        }) => allowed_domains.as_slice(),
        _ => return false,
    };
    policy.can_read_changeset(principal, cs)
        && can_write_domain_effective(
            policy,
            principal,
            &cs.visibility.primary_domain,
            embargo_allowed,
        )
}

/// Extract and authenticate a [`Principal`] from incoming gRPC [`MetadataMap`].
///
/// - If `authorization` metadata is present, it MUST use the `Bearer <token>` scheme and
///   match a registered token in [`AppState`], otherwise `Status::unauthenticated` is returned.
/// - If `authorization` is absent, falls back to `x-gitx-*` metadata headers ONLY when
///   [`AppState::trusts_proxy_headers`] is enabled (disabled automatically whenever bearer tokens
///   are registered); otherwise returns [`Principal::anonymous()`].
pub fn extract_principal_from_grpc_metadata(
    state: &AppState,
    metadata: &MetadataMap,
) -> std::result::Result<Principal, Status> {
    if let Some(auth_val) = metadata.get("authorization") {
        let raw = auth_val
            .to_str()
            .map_err(|_| Status::unauthenticated("authorization metadata must be valid ASCII"))?
            .trim();

        let Some((scheme, token)) = raw.split_once(' ') else {
            return Err(Status::unauthenticated(
                "invalid authorization metadata; expected 'Bearer <token>'",
            ));
        };
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(Status::unauthenticated(
                "unsupported authorization scheme; expected 'Bearer <token>'",
            ));
        }
        let token = token.trim();
        if token.is_empty() {
            return Err(Status::unauthenticated("empty bearer token"));
        }

        return state
            .resolve_token(token)
            .ok_or_else(|| Status::unauthenticated("invalid or unrecognized bearer token"));
    }

    if !state.trusts_proxy_headers() {
        return Ok(Principal::anonymous());
    }

    let Some(user) = metadata_str(metadata, HEADER_USER).filter(|s| !s.is_empty()) else {
        return Ok(Principal::anonymous());
    };

    let mut principal = Principal::user(user);

    if let Some(teams_raw) = metadata_str(metadata, HEADER_TEAMS) {
        let teams = split_csv(teams_raw);
        if !teams.is_empty() {
            principal = principal.with_teams(teams);
        }
    }

    if let Some(roles_raw) = metadata_str(metadata, HEADER_ROLES) {
        let roles = split_csv(roles_raw);
        if !roles.is_empty() {
            principal = principal.with_roles(roles);
        }
    }

    if let Some(fp) = metadata_str(metadata, HEADER_FINGERPRINT).filter(|s| !s.is_empty()) {
        principal = principal.with_fingerprint(fp);
    }

    Ok(principal)
}

fn metadata_str<'a>(metadata: &'a MetadataMap, name: &str) -> Option<&'a str> {
    metadata
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
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
