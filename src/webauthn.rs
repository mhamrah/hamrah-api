use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

// ============================================================================
// WebAuthn Configuration
// ============================================================================

pub struct WebAuthnConfig {
    pub webauthn: Arc<Webauthn>,
}

impl WebAuthnConfig {
    pub fn new(rp_id: &str, rp_origin: &str) -> Result<Self, WebauthnError> {
        let rp_name = "Hamrah App";
        let builder = WebauthnBuilder::new(rp_id, &Url::parse(rp_origin).unwrap())?;
        let builder = builder.rp_name(rp_name);
        let webauthn = Arc::new(builder.build()?);

        Ok(Self { webauthn })
    }
}

// ============================================================================
// Database Models
// ============================================================================

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct WebAuthnCredential {
    pub id: String,
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub counter: i64,
    pub name: Option<String>,
    pub transports: Option<Vec<String>>,
    pub aaguid: Option<Vec<u8>>,
    pub credential_type: Option<String>,
    pub user_verified: Option<bool>,
    pub credential_device_type: Option<String>,
    pub credential_backed_up: Option<bool>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct WebAuthnChallenge {
    pub id: String,
    pub challenge: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RegisterBeginRequest {
    #[serde(alias = "user_id")]
    pub user_id: Uuid,
    pub email: String,
    #[serde(alias = "display_name")]
    pub display_name: Option<String>,
    pub label: Option<String>,
    #[serde(alias = "flow_id")]
    pub flow_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterBeginResponse {
    pub success: bool,
    pub options: Option<CreationChallengeResponse>,
    #[serde(alias = "challengeId")]
    pub challenge_id: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterVerifyRequest {
    #[serde(alias = "challenge_id")]
    pub challenge_id: String,
    pub response: RegisterPublicKeyCredential,
    pub label: Option<String>,
    #[serde(alias = "flow_id")]
    pub flow_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterVerifyResponse {
    pub success: bool,
    #[serde(alias = "credentialId")]
    pub credential_id: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticateBeginRequest {
    #[serde(alias = "flow_id")]
    pub flow_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthenticateBeginResponse {
    pub success: bool,
    #[serde(alias = "challengeId")]
    pub challenge_id: Option<String>,
    pub options: Option<RequestChallengeResponse>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticateVerifyRequest {
    #[serde(alias = "challenge_id")]
    pub challenge_id: Option<String>,
    pub response: PublicKeyCredential,
    #[serde(alias = "flow_id")]
    pub flow_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthenticateVerifyResponse {
    pub success: bool,
    pub message: Option<String>,
    pub user: Option<serde_json::Value>,
    pub session_token: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeCreateRequest {
    pub id: String,
    pub challenge: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub success: bool,
    pub challenge: Option<WebAuthnChallenge>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CredentialCreateRequest {
    pub id: String,
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub counter: i64,
    pub transports: Option<Vec<String>>,
    pub aaguid: Option<Vec<u8>>,
    pub credential_type: Option<String>,
    pub user_verified: Option<bool>,
    pub credential_device_type: Option<String>,
    pub credential_backed_up: Option<bool>,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    pub success: bool,
    pub credential: Option<WebAuthnCredential>,
    pub credentials: Option<Vec<WebAuthnCredential>>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CredentialCounterUpdateRequest {
    pub counter: i64,
    pub last_used: Option<i64>,
}

// ============================================================================
// Database Functions
// ============================================================================

pub async fn create_challenge(
    pool: &PgPool,
    req: &ChallengeCreateRequest,
) -> Result<WebAuthnChallenge, sqlx::Error> {
    let expires_at = chrono::DateTime::from_timestamp_millis(req.expires_at)
        .unwrap_or_else(chrono::Utc::now);

    sqlx::query_as::<_, WebAuthnChallenge>(
        r#"
        INSERT INTO webauthn_challenges (id, challenge, user_id, challenge_type, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(&req.id)
    .bind(&req.challenge)
    .bind(&req.user_id)
    .bind(&req.challenge_type)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

pub async fn get_challenge(
    pool: &PgPool,
    challenge_id: &str,
) -> Result<WebAuthnChallenge, sqlx::Error> {
    sqlx::query_as::<_, WebAuthnChallenge>(
        r#"
        SELECT * FROM webauthn_challenges
        WHERE id = $1
        "#,
    )
    .bind(challenge_id)
    .fetch_one(pool)
    .await
}

pub async fn delete_challenge(pool: &PgPool, challenge_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        DELETE FROM webauthn_challenges
        WHERE id = $1
        "#,
    )
    .bind(challenge_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn create_credential(
    pool: &PgPool,
    req: &CredentialCreateRequest,
) -> Result<WebAuthnCredential, sqlx::Error> {
    sqlx::query_as::<_, WebAuthnCredential>(
        r#"
        INSERT INTO webauthn_credentials
            (id, user_id, public_key, counter, name, transports, aaguid,
             credential_type, user_verified, credential_device_type, credential_backed_up)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *
        "#,
    )
    .bind(&req.id)
    .bind(&req.user_id)
    .bind(&req.public_key)
    .bind(req.counter)
    .bind(&req.name)
    .bind(&req.transports)
    .bind(&req.aaguid)
    .bind(&req.credential_type)
    .bind(req.user_verified)
    .bind(&req.credential_device_type)
    .bind(req.credential_backed_up)
    .fetch_one(pool)
    .await
}

pub async fn get_credential(
    pool: &PgPool,
    credential_id: &str,
) -> Result<WebAuthnCredential, sqlx::Error> {
    sqlx::query_as::<_, WebAuthnCredential>(
        r#"
        SELECT * FROM webauthn_credentials
        WHERE id = $1
        "#,
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
}

pub async fn get_credentials_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<WebAuthnCredential>, sqlx::Error> {
    sqlx::query_as::<_, WebAuthnCredential>(
        r#"
        SELECT * FROM webauthn_credentials
        WHERE user_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn update_credential_counter(
    pool: &PgPool,
    credential_id: &str,
    counter: i64,
    last_used: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE webauthn_credentials
        SET counter = $2, last_used = $3
        WHERE id = $1
        "#,
    )
    .bind(credential_id)
    .bind(counter)
    .bind(last_used)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_credential(pool: &PgPool, credential_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        DELETE FROM webauthn_credentials
        WHERE id = $1
        "#,
    )
    .bind(credential_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ============================================================================
// Route Handlers
// ============================================================================

pub async fn register_begin(
    State((pool, _config)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Json(req): Json<RegisterBeginRequest>,
) -> impl IntoResponse {
    // TODO: Implement registration begin logic
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(RegisterBeginResponse {
            success: false,
            options: None,
            challenge_id: None,
            error: Some("Not yet implemented".to_string()),
        }),
    )
}

pub async fn register_verify(
    State((pool, _config)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Json(req): Json<RegisterVerifyRequest>,
) -> impl IntoResponse {
    // TODO: Implement registration verify logic
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(RegisterVerifyResponse {
            success: false,
            credential_id: None,
            error: Some("Not yet implemented".to_string()),
        }),
    )
}

pub async fn authenticate_begin(
    State((pool, _config)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Json(req): Json<AuthenticateBeginRequest>,
) -> impl IntoResponse {
    // TODO: Implement authentication begin logic
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(AuthenticateBeginResponse {
            success: false,
            challenge_id: None,
            options: None,
            error: Some("Not yet implemented".to_string()),
        }),
    )
}

pub async fn authenticate_verify(
    State((pool, _config)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Json(req): Json(AuthenticateVerifyRequest),
) -> impl IntoResponse {
    // TODO: Implement authentication verify logic
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(AuthenticateVerifyResponse {
            success: false,
            message: None,
            user: None,
            session_token: None,
            error: Some("Not yet implemented".to_string()),
        }),
    )
}

// Challenge management endpoints

pub async fn create_challenge_handler(
    State((pool, _)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Json(req): Json(ChallengeCreateRequest>,
) -> impl IntoResponse {
    match create_challenge(&pool, &req).await {
        Ok(challenge) => (
            StatusCode::OK,
            Json(ChallengeResponse {
                success: true,
                challenge: Some(challenge),
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ChallengeResponse {
                success: false,
                challenge: None,
                error: Some(e.to_string()),
            }),
        ),
    }
}

pub async fn get_challenge_handler(
    State((pool, _)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Path(challenge_id): Path<String>,
) -> impl IntoResponse {
    match get_challenge(&pool, &challenge_id).await {
        Ok(challenge) => (
            StatusCode::OK,
            Json(ChallengeResponse {
                success: true,
                challenge: Some(challenge),
                error: None,
            }),
        ),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(ChallengeResponse {
                success: false,
                challenge: None,
                error: Some("Challenge not found".to_string()),
            }),
        ),
    }
}

pub async fn delete_challenge_handler(
    State((pool, _)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Path(challenge_id): Path<String>,
) -> impl IntoResponse {
    match delete_challenge(&pool, &challenge_id).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "success": true })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "success": false, "error": e.to_string() })),
        ),
    }
}

// Credential management endpoints

pub async fn create_credential_handler(
    State((pool, _)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Json(req): Json<CredentialCreateRequest>,
) -> impl IntoResponse {
    match create_credential(&pool, &req).await {
        Ok(credential) => (
            StatusCode::OK,
            Json(CredentialResponse {
                success: true,
                credential: Some(credential),
                credentials: None,
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(CredentialResponse {
                success: false,
                credential: None,
                credentials: None,
                error: Some(e.to_string()),
            }),
        ),
    }
}

pub async fn get_credential_handler(
    State((pool, _)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Path(credential_id): Path<String>,
) -> impl IntoResponse {
    match get_credential(&pool, &credential_id).await {
        Ok(credential) => (
            StatusCode::OK,
            Json(CredentialResponse {
                success: true,
                credential: Some(credential),
                credentials: None,
                error: None,
            }),
        ),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(CredentialResponse {
                success: false,
                credential: None,
                credentials: None,
                error: Some("Credential not found".to_string()),
            }),
        ),
    }
}

pub async fn get_user_credentials_handler(
    State((pool, _)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Path(user_id): Path<Uuid>,
) -> impl IntoResponse {
    match get_credentials_by_user(&pool, user_id).await {
        Ok(credentials) => (
            StatusCode::OK,
            Json(CredentialResponse {
                success: true,
                credential: None,
                credentials: Some(credentials),
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(CredentialResponse {
                success: false,
                credential: None,
                credentials: None,
                error: Some(e.to_string()),
            }),
        ),
    }
}

pub async fn update_credential_counter_handler(
    State((pool, _)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Path(credential_id): Path<String>,
    Json(req): Json<CredentialCounterUpdateRequest>,
) -> impl IntoResponse {
    let last_used = req
        .last_used
        .and_then(|ts| chrono::DateTime::from_timestamp_millis(ts));

    match update_credential_counter(&pool, &credential_id, req.counter, last_used).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "success": true })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "success": false, "error": e.to_string() })),
        ),
    }
}

pub async fn delete_credential_handler(
    State((pool, _)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Path(credential_id): Path<String>,
) -> impl IntoResponse {
    match delete_credential(&pool, &credential_id).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "success": true })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "success": false, "error": e.to_string() })),
        ),
    }
}
