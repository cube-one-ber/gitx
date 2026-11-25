use gitx_core::{ChangeSet, DomainId, EmbargoState, GitxError, ObjectHash, Result};
use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Authenticated (or anonymous) caller evaluated against Visibility Domain ACLs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub fingerprint: Option<String>,
    pub teams: Vec<String>,
    pub roles: Vec<String>,
    pub is_anonymous: bool,
}

impl Principal {
    pub fn anonymous() -> Self {
        Self {
            id: "anonymous".to_string(),
            fingerprint: None,
            teams: Vec::new(),
            roles: Vec::new(),
            is_anonymous: true,
        }
    }

    pub fn user(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            fingerprint: None,
            teams: Vec::new(),
            roles: Vec::new(),
            is_anonymous: false,
        }
    }

    pub fn with_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    pub fn with_team(mut self, team: impl Into<String>) -> Self {
        self.teams.push(team.into());
        self
    }

    pub fn with_teams<I, S>(mut self, teams: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.teams.extend(teams.into_iter().map(Into::into));
        self
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    pub fn with_roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.roles.extend(roles.into_iter().map(Into::into));
        self
    }
}

/// A subject matcher in a `.gitxacl` policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubjectMatcher {
    /// Matches any principal, including anonymous callers (`*`, `any`, `public`).
    Anyone,
    /// Matches any non-anonymous principal (`authenticated`).
    Authenticated,
    /// Matches a specific user id (`user:<id>`).
    User(String),
    /// Matches any non-anonymous principal belonging to `<team>` (`team:<team>`).
    Team(String),
    /// Matches any non-anonymous principal holding `<role>` (`role:<role>`).
    Role(String),
    /// Matches a non-anonymous principal with a matching key fingerprint (`fp:<fp>` or `key:<fp>`).
    Fingerprint(String),
}

impl SubjectMatcher {
    pub fn parse(raw: &str) -> Result<Self> {
        let token = raw.trim();
        if token.is_empty() {
            return Err(GitxError::Crypto("empty ACL subject".to_string()));
        }
        match token {
            "*" | "any" | "public" => Ok(Self::Anyone),
            "authenticated" => Ok(Self::Authenticated),
            _ => {
                if let Some(id) = token.strip_prefix("user:") {
                    if id.is_empty() {
                        return Err(GitxError::Crypto("empty user subject".to_string()));
                    }
                    Ok(Self::User(id.to_string()))
                } else if let Some(team) = token.strip_prefix("team:") {
                    if team.is_empty() {
                        return Err(GitxError::Crypto("empty team subject".to_string()));
                    }
                    Ok(Self::Team(team.to_string()))
                } else if let Some(role) = token.strip_prefix("role:") {
                    if role.is_empty() {
                        return Err(GitxError::Crypto("empty role subject".to_string()));
                    }
                    Ok(Self::Role(role.to_string()))
                } else if let Some(fp) = token
                    .strip_prefix("fp:")
                    .or_else(|| token.strip_prefix("key:"))
                {
                    if fp.is_empty() {
                        return Err(GitxError::Crypto("empty fingerprint subject".to_string()));
                    }
                    Ok(Self::Fingerprint(fp.to_string()))
                } else {
                    Err(GitxError::Crypto(format!(
                        "invalid ACL subject '{token}' (expected *, authenticated, user:<id>, team:<name>, role:<name>, or fp:<fingerprint>)"
                    )))
                }
            }
        }
    }

    pub fn matches(&self, principal: &Principal) -> bool {
        match self {
            Self::Anyone => true,
            Self::Authenticated => !principal.is_anonymous,
            Self::User(id) => !principal.is_anonymous && principal.id == *id,
            Self::Team(team) => {
                !principal.is_anonymous && principal.teams.iter().any(|t| t == team)
            }
            Self::Role(role) => {
                !principal.is_anonymous && principal.roles.iter().any(|r| r == role)
            }
            Self::Fingerprint(fp) => {
                !principal.is_anonymous && principal.fingerprint.as_deref() == Some(fp.as_str())
            }
        }
    }
}

/// Read and write subject matchers configured for a Visibility Domain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainPermissions {
    pub read: Vec<SubjectMatcher>,
    pub write: Vec<SubjectMatcher>,
}

/// Compiled glob rule mapping matching repository paths to a `DomainId`.
#[derive(Debug, Clone)]
pub struct PathRule {
    pub pattern: String,
    pub domain: DomainId,
    matcher: GlobMatcher,
}

impl PathRule {
    fn compile(pattern: impl Into<String>, domain: DomainId) -> Result<Self> {
        let pattern = pattern.into();
        let trimmed = pattern.trim();
        if trimmed.is_empty() {
            return Err(GitxError::Crypto(
                "empty glob pattern in .gitxacl".to_string(),
            ));
        }
        // Patterns without a path separator match the filename at any depth
        // (matching `.gitignore` conventions: `.env`, `.env.*`, `*.pem`, `*.key`).
        // Patterns containing `/` are anchored to the repository root.
        let normalized = trimmed.trim_start_matches("./").trim_start_matches('/');
        let effective = if normalized.contains('/') {
            normalized.to_string()
        } else {
            format!("**/{normalized}")
        };
        let glob = GlobBuilder::new(&effective)
            .literal_separator(true)
            .build()
            .map_err(|e| GitxError::Crypto(format!("invalid glob '{trimmed}': {e}")))?;

        Ok(Self {
            pattern: trimmed.to_string(),
            domain,
            matcher: glob.compile_matcher(),
        })
    }

    pub fn is_match(&self, normalized_path: &str) -> bool {
        self.matcher.is_match(normalized_path)
    }
}

/// Built-in default secret glob patterns that route to `secret:dev` unless overridden.
const DEFAULT_SECRET_PATTERNS: &[&str] = &[".env", ".env.*", "*.pem", "*.key", "secrets/**"];

/// Visibility Domain ACL policy engine compiled from built-in secure defaults and `.gitxacl`.
#[derive(Debug, Clone)]
pub struct AclPolicy {
    default_rules: Vec<PathRule>,
    rules: Vec<PathRule>,
    domain_permissions: BTreeMap<DomainId, DomainPermissions>,
}

impl Default for AclPolicy {
    fn default() -> Self {
        Self::default_secure()
    }
}

impl AclPolicy {
    /// Create a policy with built-in secure defaults:
    /// `.env`, `.env.*`, `*.pem`, `*.key`, and `secrets/**` automatically route to `secret:dev`.
    pub fn default_secure() -> Self {
        let secret_dev = DomainId::secret("dev").expect("secret:dev is always valid");
        let default_rules = DEFAULT_SECRET_PATTERNS
            .iter()
            .map(|pat| PathRule::compile(*pat, secret_dev.clone()).expect("built-in glob is valid"))
            .collect();

        Self {
            default_rules,
            rules: Vec::new(),
            domain_permissions: BTreeMap::new(),
        }
    }

    /// Parse a `.gitxacl` policy file layered on top of `AclPolicy::default_secure()`.
    ///
    /// Supported syntax:
    /// - Comments: `# ...` (full-line or inline after whitespace)
    /// - Path routing (with optional inline permissions):
    ///   `<glob> -> <domain> [read=<subjects>] [write=<subjects>] [allow=<subjects>]`
    ///   `path <glob> -> <domain> [read=...] [write=...] [allow=...]`
    /// - Domain permission line:
    ///   `domain <domain> [read=<subjects>] [write=<subjects>] [allow=<subjects>]`
    /// - Domain section:
    ///   `[domain <domain>]` (or `[domain "<domain>"]`)
    ///   `read = <subjects>`
    ///   `write = <subjects>`
    ///   `allow = <subjects>`
    ///   `paths = <glob1>, <glob2>`
    ///
    /// Explicit path rules override built-in defaults; among explicit rules, the last match wins.
    pub fn parse(text: &str) -> Result<Self> {
        let mut policy = Self::default_secure();
        let mut current_domain: Option<DomainId> = None;

        for (idx, raw_line) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            // Section header: [domain <id>] or [domain "<id>"]
            if line.starts_with('[') && line.ends_with(']') {
                let inner = line[1..line.len() - 1].trim();
                let dom_raw = inner.strip_prefix("domain").map(str::trim).ok_or_else(|| {
                    GitxError::Crypto(format!(
                        ".gitxacl:{line_no}: unsupported section header '{line}'"
                    ))
                })?;
                let dom_unquoted = dom_raw.trim_matches('"').trim_matches('\'');
                let domain = DomainId::new(dom_unquoted)?;
                current_domain = Some(domain);
                continue;
            }

            // One-line domain directive: domain <id> read=... write=... allow=...
            if let Some(rest) = line.strip_prefix("domain ") {
                current_domain = None;
                let mut parts = rest.split_whitespace();
                let dom_raw = parts.next().ok_or_else(|| {
                    GitxError::Crypto(format!(".gitxacl:{line_no}: missing domain name"))
                })?;
                let domain = DomainId::new(dom_raw)?;
                let mut saw_perm = false;
                for token in parts {
                    policy.apply_permission_token(&domain, token, line_no)?;
                    saw_perm = true;
                }
                if !saw_perm {
                    return Err(GitxError::Crypto(format!(
                        ".gitxacl:{line_no}: domain directive requires read=, write=, or allow="
                    )));
                }
                continue;
            }

            // Path routing rule: [path ]<glob> -> <domain> [read=... write=... allow=...]
            if let Some((lhs, rhs)) = line.split_once("->") {
                current_domain = None;
                let lhs = lhs.trim();
                let pattern = lhs.strip_prefix("path ").map(str::trim).unwrap_or(lhs);
                if pattern.is_empty() {
                    return Err(GitxError::Crypto(format!(
                        ".gitxacl:{line_no}: missing path glob before '->'"
                    )));
                }
                let mut rhs_parts = rhs.split_whitespace();
                let dom_raw = rhs_parts.next().ok_or_else(|| {
                    GitxError::Crypto(format!(
                        ".gitxacl:{line_no}: missing target domain after '->'"
                    ))
                })?;
                let domain = DomainId::new(dom_raw)?;
                policy.add_path_rule(pattern, domain.clone())?;
                for token in rhs_parts {
                    policy.apply_permission_token(&domain, token, line_no)?;
                }
                continue;
            }

            // Section key = value entries inside `[domain <id>]`
            if let Some(domain) = current_domain.clone()
                && let Some((key, val)) = line.split_once('=')
            {
                let key = key.trim();
                let val = val.trim();
                match key {
                    "read" => {
                        for subject in parse_subject_list(val, line_no)? {
                            policy.grant_read(domain.clone(), subject);
                        }
                    }
                    "write" => {
                        for subject in parse_subject_list(val, line_no)? {
                            policy.grant_write(domain.clone(), subject);
                        }
                    }
                    "allow" => {
                        for subject in parse_subject_list(val, line_no)? {
                            policy.grant_read_write(domain.clone(), subject);
                        }
                    }
                    "paths" => {
                        for pat in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                            policy.add_path_rule(pat, domain.clone())?;
                        }
                    }
                    _ => {
                        return Err(GitxError::Crypto(format!(
                            ".gitxacl:{line_no}: unknown domain key '{key}'"
                        )));
                    }
                }
                continue;
            }

            return Err(GitxError::Crypto(format!(
                ".gitxacl:{line_no}: could not parse directive '{line}'"
            )));
        }

        Ok(policy)
    }

    fn apply_permission_token(
        &mut self,
        domain: &DomainId,
        token: &str,
        line_no: usize,
    ) -> Result<()> {
        let Some((key, val)) = token.split_once('=') else {
            return Err(GitxError::Crypto(format!(
                ".gitxacl:{line_no}: expected key=value permission token, got '{token}'"
            )));
        };
        let subjects = parse_subject_list(val, line_no)?;
        match key {
            "read" => {
                for s in subjects {
                    self.grant_read(domain.clone(), s);
                }
            }
            "write" => {
                for s in subjects {
                    self.grant_write(domain.clone(), s);
                }
            }
            "allow" => {
                for s in subjects {
                    self.grant_read_write(domain.clone(), s);
                }
            }
            _ => {
                return Err(GitxError::Crypto(format!(
                    ".gitxacl:{line_no}: unknown permission modifier '{key}'"
                )));
            }
        }
        Ok(())
    }

    /// Add an explicit glob routing rule. Explicit rules override built-in defaults,
    /// and later explicit rules override earlier ones.
    pub fn add_path_rule(&mut self, pattern: impl Into<String>, domain: DomainId) -> Result<()> {
        self.rules.push(PathRule::compile(pattern, domain)?);
        Ok(())
    }

    pub fn grant_read(&mut self, domain: DomainId, subject: SubjectMatcher) {
        self.domain_permissions
            .entry(domain)
            .or_default()
            .read
            .push(subject);
    }

    pub fn grant_write(&mut self, domain: DomainId, subject: SubjectMatcher) {
        self.domain_permissions
            .entry(domain)
            .or_default()
            .write
            .push(subject);
    }

    pub fn grant_read_write(&mut self, domain: DomainId, subject: SubjectMatcher) {
        let perms = self.domain_permissions.entry(domain).or_default();
        perms.read.push(subject.clone());
        perms.write.push(subject);
    }

    pub fn path_rules(&self) -> &[PathRule] {
        &self.rules
    }

    pub fn domain_permissions(&self) -> &BTreeMap<DomainId, DomainPermissions> {
        &self.domain_permissions
    }

    /// Resolve which `DomainId` owns `path`.
    ///
    /// Precedence:
    /// 1. Last matching explicit rule from `.gitxacl` (or `add_path_rule`).
    /// 2. Built-in default secret rules (`.env`, `.env.*`, `*.pem`, `*.key`, `secrets/**` -> `secret:dev`).
    /// 3. Fallback: `DomainId::public()`.
    pub fn domain_for_path(&self, path: &str) -> DomainId {
        let normalized = normalize_path(path);

        for rule in self.rules.iter().rev() {
            if rule.is_match(&normalized) {
                return rule.domain.clone();
            }
        }

        for rule in self.default_rules.iter().rev() {
            if rule.is_match(&normalized) {
                return rule.domain.clone();
            }
        }

        DomainId::public()
    }

    /// Returns `true` if `principal` is allowed to read objects in `domain`.
    pub fn can_read_domain(&self, principal: &Principal, domain: &DomainId) -> bool {
        if let Some(perms) = self.domain_permissions.get(domain) {
            if perms.read.iter().any(|m| m.matches(principal)) {
                return true;
            }
            // Private user domain always grants its owner access even if extra readers were added.
            if is_private_owner(principal, domain) {
                return true;
            }
            return false;
        }

        if domain.is_public() {
            return true;
        }

        if is_private_owner(principal, domain) {
            return true;
        }

        if let Some(team) = domain.as_str().strip_prefix("team:") {
            return !principal.is_anonymous && principal.teams.iter().any(|t| t == team);
        }

        // `secret:*`, `embargo:*`, and unrecognized domains are deny-by-default.
        false
    }

    /// Returns `true` if `principal` is allowed to write objects in `domain`.
    pub fn can_write_domain(&self, principal: &Principal, domain: &DomainId) -> bool {
        if let Some(perms) = self.domain_permissions.get(domain) {
            if perms.write.iter().any(|m| m.matches(principal)) {
                return true;
            }
            if is_private_owner(principal, domain) {
                return true;
            }
            return false;
        }

        if domain.is_public() {
            return !principal.is_anonymous;
        }

        if is_private_owner(principal, domain) {
            return true;
        }

        if let Some(team) = domain.as_str().strip_prefix("team:") {
            return !principal.is_anonymous && principal.teams.iter().any(|t| t == team);
        }

        false
    }

    /// Returns `true` if `principal` is allowed to see `cs` at all, accounting for
    /// `primary_domain` as well as active vs. published `EmbargoState`.
    pub fn can_read_changeset(&self, principal: &Principal, cs: &ChangeSet) -> bool {
        match &cs.visibility.embargo {
            Some(EmbargoState::Active {
                allowed_domains, ..
            }) => {
                if principal.is_anonymous {
                    return false;
                }
                if !cs.visibility.primary_domain.is_public()
                    && self.can_read_domain(principal, &cs.visibility.primary_domain)
                {
                    return true;
                }
                allowed_domains
                    .iter()
                    .any(|d| !d.is_public() && self.can_read_domain(principal, d))
            }
            Some(EmbargoState::Published { .. }) => {
                self.can_read_domain(principal, &DomainId::public())
                    || self.can_read_domain(principal, &cs.visibility.primary_domain)
            }
            None => self.can_read_domain(principal, &cs.visibility.primary_domain),
        }
    }

    /// Return a filtered map containing ONLY the domain trees inside `cs` that
    /// `principal` is authorized to view.
    ///
    /// If `principal` cannot read the changeset (e.g., private stack or active embargo),
    /// returns an empty map so not even a staged `public` tree leaks prematurely.
    pub fn filter_domain_trees(
        &self,
        principal: &Principal,
        cs: &ChangeSet,
    ) -> BTreeMap<DomainId, ObjectHash> {
        if !self.can_read_changeset(principal, cs) {
            return BTreeMap::new();
        }

        let primary_unlocked_by_embargo = match &cs.visibility.embargo {
            Some(EmbargoState::Active { .. }) => true,
            Some(EmbargoState::Published { .. }) => {
                self.can_read_domain(principal, &DomainId::public())
            }
            None => false,
        };

        cs.domain_trees
            .iter()
            .filter(|(domain, _)| {
                if *domain == &cs.visibility.primary_domain && primary_unlocked_by_embargo {
                    return true;
                }
                self.can_read_domain(principal, domain)
            })
            .map(|(d, h)| (d.clone(), *h))
            .collect()
    }
}

fn is_private_owner(principal: &Principal, domain: &DomainId) -> bool {
    if principal.is_anonymous {
        return false;
    }
    domain
        .as_str()
        .strip_prefix("private:user:")
        .is_some_and(|owner| owner == principal.id)
}

fn normalize_path(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    let parts: Vec<&str> = replaced
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != ".")
        .collect();
    parts.join("/")
}

fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        }
    }
    line
}

fn parse_subject_list(raw: &str, line_no: usize) -> Result<Vec<SubjectMatcher>> {
    let mut out = Vec::new();
    for item in raw.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(
            SubjectMatcher::parse(trimmed)
                .map_err(|e| GitxError::Crypto(format!(".gitxacl:{line_no}: {e}")))?,
        );
    }
    if out.is_empty() {
        return Err(GitxError::Crypto(format!(
            ".gitxacl:{line_no}: expected at least one subject"
        )));
    }
    Ok(out)
}
