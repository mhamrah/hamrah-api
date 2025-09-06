use serde::{Deserialize, Serialize};
use sqlx_d1::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub email_verified: Option<i64>, // Unix timestamp in milliseconds
    pub auth_method: Option<String>,
    pub provider: Option<String>,
    pub provider_id: Option<String>,
    pub last_login_platform: Option<String>,
    pub last_login_at: Option<i64>, // Unix timestamp in milliseconds
    pub created_at: i64,            // Unix timestamp in milliseconds
    pub updated_at: i64,            // Unix timestamp in milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUser {
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub email_verified: Option<i64>, // Unix timestamp in milliseconds
    pub auth_method: Option<String>,
    pub provider: Option<String>,
    pub provider_id: Option<String>,
    pub last_login_platform: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub expires_at: i64, // Unix timestamp in milliseconds
    pub created_at: i64, // Unix timestamp in milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSession {
    pub user_id: String,
    pub expires_at: i64, // Unix timestamp in milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuthToken {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub refresh_token_hash: String,
    pub access_expires_at: i64,  // Unix timestamp in milliseconds
    pub refresh_expires_at: i64, // Unix timestamp in milliseconds
    pub platform: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub revoked: bool,
    pub last_used: Option<i64>, // Unix timestamp in milliseconds
    pub created_at: i64,        // Unix timestamp in milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAuthToken {
    pub user_id: String,
    pub token_hash: String,
    pub refresh_token_hash: String,
    pub access_expires_at: i64,  // Unix timestamp in milliseconds
    pub refresh_expires_at: i64, // Unix timestamp in milliseconds
    pub platform: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WebAuthnCredential {
    pub id: String,
    pub user_id: String,
    pub public_key: String,
    pub counter: i64,
    pub transports: Option<String>,
    pub aaguid: Option<String>,
    pub credential_type: String,
    pub user_verified: i64, // SQLite stores booleans as INTEGER (0/1)
    pub credential_device_type: Option<String>,
    pub credential_backed_up: i64, // SQLite stores booleans as INTEGER (0/1)
    pub name: Option<String>,
    pub last_used: Option<i64>, // Unix timestamp in milliseconds
    pub created_at: i64,        // Unix timestamp in milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewWebAuthnCredential {
    pub id: String,
    pub user_id: String,
    pub public_key: String,
    pub counter: i64,
    pub transports: Option<String>,
    pub aaguid: Option<String>,
    pub credential_type: String,
    pub user_verified: i64, // SQLite stores booleans as INTEGER (0/1)
    pub credential_device_type: Option<String>,
    pub credential_backed_up: i64, // SQLite stores booleans as INTEGER (0/1)
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WebAuthnChallenge {
    pub id: String,
    pub challenge: String,
    pub user_id: Option<String>,
    pub challenge_type: String, // 'registration' | 'authentication'
    pub expires_at: i64,        // Unix timestamp in milliseconds
    pub created_at: i64,        // Unix timestamp in milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewWebAuthnChallenge {
    pub challenge: String,
    pub user_id: Option<String>,
    pub challenge_type: String,
    pub expires_at: i64, // Unix timestamp in milliseconds
}
