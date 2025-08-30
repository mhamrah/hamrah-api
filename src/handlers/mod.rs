pub mod auth;
pub mod users;
pub mod internal;
pub mod webauthn;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
pub enum ApiError {
    DatabaseError(String),
    AuthError(crate::auth::AuthError),
    ValidationError(String),
    NotFound,
    Unauthorized,
    Forbidden,
    InternalServerError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::AuthError(err) => match err {
                crate::auth::AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()),
                crate::auth::AuthError::SessionExpired => (StatusCode::UNAUTHORIZED, "Session expired".to_string()),
                crate::auth::AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired".to_string()),
                crate::auth::AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
                crate::auth::AuthError::UserNotFound => (StatusCode::NOT_FOUND, "User not found".to_string()),
                crate::auth::AuthError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            },
            ApiError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_string()),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden".to_string()),
            ApiError::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(json!({
            "error": message,
            "success": false
        }));

        (status, body).into_response()
    }
}

impl From<worker::Error> for ApiError {
    fn from(err: worker::Error) -> Self {
        ApiError::DatabaseError(err.to_string())
    }
}

impl From<crate::auth::AuthError> for ApiError {
    fn from(err: crate::auth::AuthError) -> Self {
        ApiError::AuthError(err)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        ApiError::DatabaseError(err.to_string())
    }
}