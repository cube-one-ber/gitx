use crate::acl::AclPolicy;
use gitx_core::DomainId;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Category of secret detected by the zero-trust scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecretKind {
    DotEnvFile,
    PrivateKeyHeader,
    AwsAccessKey,
    GitHubToken,
    ApiKey,
    GenericSecretAssignment,
}

/// Severity rating of a secret finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Medium,
    High,
    Critical,
}

/// A single finding reported by `scan_content`. Never includes raw secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretFinding {
    pub kind: SecretKind,
    pub severity: Severity,
    pub path: String,
    /// 1-based line number, or `None` for filename-level detections.
    pub line: Option<usize>,
    pub message: String,
    /// Redacted preview of the matched token or assignment.
    pub redacted_match: String,
}

struct ScannerPatterns {
    private_key: Regex,
    aws_key: Regex,
    github_token: Regex,
    api_key: Regex,
    generic_assignment: Regex,
}

fn patterns() -> &'static ScannerPatterns {
    static PATTERNS: OnceLock<ScannerPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| ScannerPatterns {
        private_key: Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
            .expect("valid private key regex"),
        aws_key: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("valid AWS key regex"),
        github_token: Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{12,}\b")
            .expect("valid GitHub token regex"),
        api_key: Regex::new(r"\bsk-[A-Za-z0-9_-]{12,}\b").expect("valid API key regex"),
        generic_assignment: Regex::new(
            r#"(?i)\b([A-Z0-9_]*(?:SECRET|API_KEY|APIKEY|ACCESS_TOKEN|PRIVATE_KEY)[A-Z0-9_]*)\s*[:=]\s*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})'|([^\s"'#;,(){}\[\]]{8,}))"#,
        )
        .expect("valid generic assignment regex"),
    })
}

fn is_dotenv_filename(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let filename = normalized.rsplit('/').next().unwrap_or(&normalized);
    filename == ".env" || filename.starts_with(".env.")
}

fn redact_token(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= 8 {
        return "****".to_string();
    }
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}****{suffix}")
}

fn looks_like_placeholder(value: &str) -> bool {
    value.starts_with('$')
        || value.starts_with("${")
        || value.starts_with("{{")
        || value.starts_with('<')
        || value.eq_ignore_ascii_case("changeme")
        || value.eq_ignore_ascii_case("placeholder")
}

fn looks_like_code_expr(value: &str, trailing: &str) -> bool {
    trailing.starts_with('(')
        || value.contains("::")
        || value.starts_with("process.env.")
        || value.starts_with("os.environ")
        || value.starts_with("env.")
}

/// Scan a file path and its contents for potential secrets.
///
/// Detects:
/// - `.env` and `.env.*` filenames
/// - PEM / OpenSSH / PGP private key headers (`-----BEGIN ... PRIVATE KEY-----`)
/// - AWS access key IDs (`AKIA...`, `ASIA...`)
/// - GitHub tokens (`ghp_...`, `gho_...`, `ghu_...`, `ghs_...`, `ghr_...`)
/// - API keys (`sk-...`)
/// - Generic `SECRET=` / `API_KEY=` / `ACCESS_TOKEN=` / `PRIVATE_KEY=` assignments
pub fn scan_content(path: &str, content: &[u8]) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    let pats = patterns();

    if is_dotenv_filename(path) {
        findings.push(SecretFinding {
            kind: SecretKind::DotEnvFile,
            severity: Severity::High,
            path: path.to_string(),
            line: None,
            message: "dotenv filename detected; must be stored in a secret:* domain".to_string(),
            redacted_match: path.rsplit(['/', '\\']).next().unwrap_or(path).to_string(),
        });
    }

    let text = String::from_utf8_lossy(content);
    for (idx, line_str) in text.lines().enumerate() {
        let line_no = idx + 1;

        for m in pats.private_key.find_iter(line_str) {
            findings.push(SecretFinding {
                kind: SecretKind::PrivateKeyHeader,
                severity: Severity::Critical,
                path: path.to_string(),
                line: Some(line_no),
                message: "private key header detected".to_string(),
                redacted_match: m.as_str().to_string(),
            });
        }

        for m in pats.aws_key.find_iter(line_str) {
            findings.push(SecretFinding {
                kind: SecretKind::AwsAccessKey,
                severity: Severity::Critical,
                path: path.to_string(),
                line: Some(line_no),
                message: "AWS access key ID detected".to_string(),
                redacted_match: redact_token(m.as_str()),
            });
        }

        for m in pats.github_token.find_iter(line_str) {
            findings.push(SecretFinding {
                kind: SecretKind::GitHubToken,
                severity: Severity::Critical,
                path: path.to_string(),
                line: Some(line_no),
                message: "GitHub token detected".to_string(),
                redacted_match: redact_token(m.as_str()),
            });
        }

        for m in pats.api_key.find_iter(line_str) {
            findings.push(SecretFinding {
                kind: SecretKind::ApiKey,
                severity: Severity::High,
                path: path.to_string(),
                line: Some(line_no),
                message: "API key token detected".to_string(),
                redacted_match: redact_token(m.as_str()),
            });
        }

        for caps in pats.generic_assignment.captures_iter(line_str) {
            let key = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let is_quoted = caps.get(2).is_some() || caps.get(3).is_some();
            let Some(val_match) = caps.get(2).or_else(|| caps.get(3)).or_else(|| caps.get(4))
            else {
                continue;
            };
            let val = val_match.as_str();
            if looks_like_placeholder(val) {
                continue;
            }
            if !is_quoted && looks_like_code_expr(val, &line_str[val_match.end()..]) {
                continue;
            }
            findings.push(SecretFinding {
                kind: SecretKind::GenericSecretAssignment,
                severity: Severity::Medium,
                path: path.to_string(),
                line: Some(line_no),
                message: format!("secret assignment detected for '{key}'"),
                redacted_match: format!("{key}={}", redact_token(val)),
            });
        }
    }

    findings
}

/// Convenience predicate returning `true` if `scan_content` produces any findings.
pub fn contains_secrets(path: &str, content: &[u8]) -> bool {
    !scan_content(path, content).is_empty()
}

/// Zero-trust domain routing: consults `policy.domain_for_path(path)` and automatically
/// upgrades `public` paths containing detected secrets into `secret:dev`.
pub fn route_domain_zero_trust(path: &str, content: &[u8], policy: &AclPolicy) -> DomainId {
    let routed = policy.domain_for_path(path);
    if routed.is_public() && contains_secrets(path, content) {
        DomainId::secret("dev").expect("secret:dev is always valid")
    } else {
        routed
    }
}
