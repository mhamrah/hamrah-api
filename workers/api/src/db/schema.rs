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
}

//
// --- LINKS PIPELINE SCHEMA ---
//

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Link {
    pub id: String,
    pub user_id: String,
    pub client_id: Option<String>,
    pub original_url: String,
    pub canonical_url: String,
    pub host: Option<String>,
    pub state: String,
    pub failure_reason: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub site_name: Option<String>,
    pub favicon_url: Option<String>,
    pub image_url: Option<String>,
    pub summary_short: Option<String>,
    pub summary_long: Option<String>,
    pub primary_summary_model_id: Option<String>,
    pub lang: Option<String>,
    pub word_count: Option<i64>,
    pub reading_time_sec: Option<i64>,
    pub content_hash: Option<String>,
    pub archive_etag: Option<String>,
    pub archive_bytes: Option<i64>,
    pub archive_r2_key: Option<String>,
    pub save_count: i64,
    pub created_at: String,
    pub updated_at: String,
    pub ready_at: Option<String>,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LinkSave {
    pub id: String,
    pub link_id: String,
    pub user_id: String,
    pub source_app: Option<String>,
    pub shared_text: Option<String>,
    pub shared_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tag {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LinkTag {
    pub link_id: String,
    pub tag_id: String,
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LinkSummary {
    pub id: String,
    pub link_id: String,
    pub user_id: String,
    pub model_id: String,
    pub prompt_version: Option<String>,
    pub prompt_text: String,
    pub short_summary: String,
    pub long_summary: Option<String>,
    pub tags_json: Option<String>,
    pub usage_json: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PushToken {
    pub id: String,
    pub user_id: String,
    pub device_token: String,
    pub platform: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserPrefs {
    pub user_id: String,
    pub preferred_models: Option<String>,
    pub summary_models: Option<String>,
    pub summary_prompt_override: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Job {
    pub id: String,
    pub link_id: String,
    pub user_id: String,
    pub kind: String,
    pub run_at: String,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IdempotencyKey {
    pub key: String,
    pub user_id: String,
    pub response_body: Option<Vec<u8>>,
    pub status: Option<i64>,
    pub created_at: String,
}
