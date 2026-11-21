use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use gitx_core::GitxError;
use gitx_crypto::SecretFinding;
use serde::Serialize;

/// Unified HTTP/JSON error type for `gitx-server` handlers.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub findings: Option<Vec<SecretFinding>>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    findings: &'a Option<Vec<SecretFinding>>,
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: msg.into(),
            findings: None,
        }
    }

    pub fn secret_rejected(msg: impl Into<String>, findings: Vec<SecretFinding>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "secret_detected",
            message: msg.into(),
            findings: Some(findings),
        }
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: msg.into(),
            findings: None,
        }
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: msg.into(),
            findings: None,
        }
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: msg.into(),
            findings: None,
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: msg.into(),
            findings: None,
        }
    }
}

impl From<GitxError> for ApiError {
    fn from(err: GitxError) -> Self {
        match err {
            GitxError::NotFound(msg) => Self::not_found(msg),
            GitxError::AccessDenied { domain, reason } => {
                Self::forbidden(format!("access denied for domain '{domain}': {reason}"))
            }
            GitxError::InvalidHash(msg) | GitxError::InvalidDomain(msg) => Self::bad_request(msg),
            GitxError::Merge(msg) | GitxError::ConflictPresent(msg) => Self::conflict(msg),
            GitxError::Crypto(msg) => Self::bad_request(msg),
            other => Self::internal(other.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: &self.message,
            code: self.code,
            findings: &self.findings,
        };
        (self.status, Json(body)).into_response()
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
