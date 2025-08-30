use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub email_verified: Option<DateTime<Utc>>,
    pub auth_method: Option<String>,
    pub provider: Option<String>,
    pub provider_id: Option<String>,
    pub last_login_platform: Option<String>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUser {
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub email_verified: Option<DateTime<Utc>>,
    pub auth_method: Option<String>,
    pub provider: Option<String>,
    pub provider_id: Option<String>,
    pub last_login_platform: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSession {
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuthToken {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub refresh_token_hash: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
    pub platform: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub revoked: bool,
    pub last_used: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAuthToken {
    pub user_id: String,
    pub token_hash: String,
    pub refresh_token_hash: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
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
    pub user_verified: bool,
    pub credential_device_type: Option<String>,
    pub credential_backed_up: bool,
    pub name: Option<String>,
    pub last_used: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
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
    pub user_verified: bool,
    pub credential_device_type: Option<String>,
    pub credential_backed_up: bool,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WebAuthnChallenge {
    pub id: String,
    pub challenge: String,
    pub user_id: Option<String>,
    pub challenge_type: String, // 'registration' | 'authentication'
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewWebAuthnChallenge {
    pub challenge: String,
    pub user_id: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}