use axum::http::{header::RETRY_AFTER, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use std::borrow::Cow;
use std::fmt::Display;
use std::time::Duration;
use thiserror::Error;

/// Convenient result alias for handlers.
pub type AppResult<T> = Result<T, Box<AppError>>;

/// Canonical error codes for API responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    UnprocessableEntity,
    TooManyRequests,
    ServiceUnavailable,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Conflict => "conflict",
            ErrorCode::UnprocessableEntity => "unprocessable_entity",
            ErrorCode::TooManyRequests => "too_many_requests",
            ErrorCode::ServiceUnavailable => "service_unavailable",
            ErrorCode::Internal => "internal_error",
        }
    }
}

/// API error type tailored for Axum + JSON APIs.
/// - Carries an HTTP status, machine-readable code, human message, and optional details.
/// - Implements IntoResponse to produce a consistent JSON error shape.
/// - Provides helpers for common HTTP error types.
#[derive(Debug, Error)]
#[error("{status} {code}: {message}")]
pub struct AppError {
    pub status: StatusCode,
    pub code: Cow<'static, str>,
    pub message: Cow<'static, str>,
    pub details: Option<JsonValue>,
    headers: HeaderMap,
}

impl AppError {
    /// Generic constructor.
    pub fn new(
        status: StatusCode,
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            details: None,
            headers: HeaderMap::new(),
        }
    }

    /// Add a JSON-serializable details payload.
    pub fn with_details(mut self, details: impl Into<JsonValue>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Add/override a header on the response.
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Set Retry-After header using a duration (rounds up to seconds).
    pub fn with_retry_after(mut self, dur: Duration) -> Self {
        let secs = dur.as_secs().max(1);
        if let Ok(val) = HeaderValue::from_str(&secs.to_string()) {
            self.headers.insert(RETRY_AFTER, val);
        }
        self
    }

    /// 400 Bad Request
    pub fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            ErrorCode::BadRequest.as_str(),
            message,
        )
    }

    /// 401 Unauthorized
    pub fn unauthorized(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized.as_str(),
            message,
        )
    }

    /// 403 Forbidden
    pub fn forbidden(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            ErrorCode::Forbidden.as_str(),
            message,
        )
    }

    /// 404 Not Found
    pub fn not_found(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorCode::NotFound.as_str(), message)
    }

    /// 409 Conflict
    pub fn conflict(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::CONFLICT, ErrorCode::Conflict.as_str(), message)
    }

    /// 422 Unprocessable Entity
    pub fn unprocessable_entity(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::UnprocessableEntity.as_str(),
            message,
        )
    }

    /// 429 Too Many Requests
    pub fn too_many_requests(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::TooManyRequests.as_str(),
            message,
        )
    }

    /// 503 Service Unavailable
    pub fn service_unavailable(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ServiceUnavailable.as_str(),
            message,
        )
    }

    /// 500 Internal Server Error
    pub fn internal(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal.as_str(),
            message,
        )
    }

    /// 500 Internal Server Error with a generic message, suitable for unexpected errors.
    pub fn anyhow<E: Display>(err: E) -> Self {
        // Log line for operators; callers can add more context where needed.
        worker::console_log!("Internal error: {}", err);
        Self::internal("An unexpected error occurred")
            .with_details(json!({ "reason": err.to_string() }))
    }

    /// Helper mapping of common sentinel strings used in the codebase today.
    /// This allows a gradual migration from `Result<_, String>` to `AppResult<_>`.
    pub fn from_sentinel(s: &str) -> Self {
        match s {
            "NotFound" | "not_found" => Self::not_found("Resource not found"),
            "Unauthorized" | "unauthorized" => Self::unauthorized("Unauthorized"),
            "Forbidden" | "forbidden" => Self::forbidden("Forbidden"),
            "Conflict" | "conflict" => Self::conflict("Conflict"),
            "BadRequest" | "bad_request" => Self::bad_request("Bad request"),
            "TooManyRequests" | "too_many_requests" => Self::too_many_requests("Too many requests"),
            "UnprocessableEntity" | "unprocessable_entity" => {
                Self::unprocessable_entity("Unprocessable entity")
            }
            other => {
                // Treat unknown strings as internal errors; include as details for debugging.
                Self::anyhow(other.to_string())
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let headers = self.headers;
        // Compose JSON error body
        let body = json!({
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details
            }
        });

        // Return (StatusCode, HeaderMap, Json<Value>) which implements IntoResponse
        (self.status, headers, Json(body)).into_response()
    }
}

impl IntoResponse for Box<AppError> {
    fn into_response(self) -> Response {
        (*self).into_response()
    }
}

// --- Conversions from common error types to AppError ---

impl From<String> for AppError {
    fn from(value: String) -> Self {
        AppError::from_sentinel(&value)
    }
}

impl From<&str> for AppError {
    fn from(value: &str) -> Self {
        AppError::from_sentinel(value)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        // If this happens while parsing input, prefer 400; otherwise internal.
        // Default to 400 since most serde_json errors originate from input handling.
        AppError::bad_request("Invalid JSON payload")
            .with_details(json!({ "reason": err.to_string() }))
    }
}

impl From<worker::Error> for AppError {
    fn from(err: worker::Error) -> Self {
        AppError::anyhow(err)
    }
}

impl From<sqlx_d1::Error> for AppError {
    fn from(err: sqlx_d1::Error) -> Self {
        // Surface constraint violations as conflict; everything else internal.
        let msg = err.to_string();
        let lowered = msg.to_ascii_lowercase();
        if lowered.contains("unique")
            || lowered.contains("constraint")
            || lowered.contains("conflict")
        {
            AppError::conflict("Constraint violation").with_details(json!({ "reason": msg }))
        } else {
            AppError::anyhow(err)
        }
    }
}

impl From<uuid::Error> for AppError {
    fn from(err: uuid::Error) -> Self {
        AppError::bad_request("Invalid UUID").with_details(json!({ "reason": err.to_string() }))
    }
}

// --- Conversions to Box<AppError> for the new AppResult type ---

impl From<String> for Box<AppError> {
    fn from(value: String) -> Self {
        Box::new(AppError::from_sentinel(&value))
    }
}

impl From<&str> for Box<AppError> {
    fn from(value: &str) -> Self {
        Box::new(AppError::from_sentinel(value))
    }
}


impl From<serde_json::Error> for Box<AppError> {
    fn from(err: serde_json::Error) -> Self {
        Box::new(AppError::from(err))
    }
}

impl From<worker::Error> for Box<AppError> {
    fn from(err: worker::Error) -> Self {
        Box::new(AppError::from(err))
    }
}

impl From<sqlx_d1::Error> for Box<AppError> {
    fn from(err: sqlx_d1::Error) -> Self {
        Box::new(AppError::from(err))
    }
}

impl From<uuid::Error> for Box<AppError> {
    fn from(err: uuid::Error) -> Self {
        Box::new(AppError::from(err))
    }
}

// --- Small ergonomic helpers ---

/// Extension trait for Option to convert to AppError.
pub trait OptionExt<T> {
    fn or_not_found(self, what: &'static str) -> AppResult<T>;
    fn or_bad_request(self, msg: &'static str) -> AppResult<T>;
}

impl<T> OptionExt<T> for Option<T> {
    fn or_not_found(self, what: &'static str) -> AppResult<T> {
        self.ok_or_else(|| Box::new(AppError::not_found(what)))
    }
    fn or_bad_request(self, msg: &'static str) -> AppResult<T> {
        self.ok_or_else(|| Box::new(AppError::bad_request(msg)))
    }
}

/// Map any error into an AppError::anyhow, preserving a friendlier external message.
pub trait ResultAnyhowExt<T, E> {
    fn or_internal(self, context: &'static str) -> AppResult<T>
    where
        E: Display;
}

impl<T, E> ResultAnyhowExt<T, E> for Result<T, E> {
    fn or_internal(self, context: &'static str) -> AppResult<T>
    where
        E: Display,
    {
        self.map_err(|e| Box::new(AppError::anyhow(format!("{context}: {e}"))))
    }
}

/// Build a standardized 500 from any error, capturing its Display string in details.
/// Useful with `map_err(AppError::from_anyhow)` style.
pub fn from_anyhow<E: Display>(err: E) -> Box<AppError> {
    Box::new(AppError::anyhow(err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use serde_json::Value;
    use std::time::Duration;

    #[tokio::test]
    async fn test_app_error_envelopes_table() {
        let cases: Vec<(AppError, StatusCode, &str)> = vec![
            (
                AppError::not_found("missing"),
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                AppError::unauthorized("unauth"),
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            ),
            (AppError::conflict("dup"), StatusCode::CONFLICT, "conflict"),
            (
                AppError::bad_request("bad"),
                StatusCode::BAD_REQUEST,
                "bad_request",
            ),
            (
                AppError::unprocessable_entity("bad entity"),
                StatusCode::UNPROCESSABLE_ENTITY,
                "unprocessable_entity",
            ),
            (
                AppError::too_many_requests("slow down"),
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
            ),
            (
                AppError::service_unavailable("unavailable"),
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            ),
            (
                AppError::internal("boom"),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ];

        for (err, expected_status, expected_code) in cases {
            let resp = err.into_response();
            assert_eq!(resp.status(), expected_status);

            let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(v["error"]["code"], expected_code);
            assert!(v["error"]["message"].is_string());
            // details may be null or an object; just ensure the field exists
            assert!(v.get("error").unwrap().get("details").is_some());
        }
    }

    #[tokio::test]
    async fn test_app_error_with_details_and_retry_after() {
        let err = AppError::too_many_requests("slow down")
            .with_retry_after(Duration::from_secs(5))
            .with_details(json!({ "reason": "rate_limit" }));

        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // Validate Retry-After header
        let retry_after = resp
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .expect("Retry-After header missing");
        assert_eq!(retry_after.to_str().unwrap(), "5");

        // Validate body envelope and details
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["code"], "too_many_requests");
        assert_eq!(v["error"]["message"], "slow down");
        assert_eq!(v["error"]["details"]["reason"], "rate_limit");
    }
}
