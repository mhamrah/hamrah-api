pub mod session;
pub mod tokens;
pub mod cookies;

use thiserror::Error;

#[derive(Error, Debug)]
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

pub const PLATFORM_WEB: &str = "web";
pub const PLATFORM_IOS: &str = "ios";
pub const PLATFORM_API: &str = "api";