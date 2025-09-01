pub mod app_attestation;
pub mod cookies;
pub mod session;
pub mod tokens;

use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)] // Library enum - variants may be used by external consumers
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Session expired")]
    SessionExpired,
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid token")]
    InvalidToken,
    #[error("User not found")]
    UserNotFound,
    #[error("Database error: {0}")]
    DatabaseError(String),
}

pub type Platform = String;

#[allow(dead_code)] // Library constants - may be used by external consumers
pub const PLATFORM_WEB: &str = "web";
#[allow(dead_code)]
pub const PLATFORM_IOS: &str = "ios";
#[allow(dead_code)]
pub const PLATFORM_API: &str = "api";
