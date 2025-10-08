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
        let origin_url = Url::parse(rp_origin).unwrap();
        let builder = WebauthnBuilder::new(rp_id, &origin_url)?;
        let builder = builder.rp_name(rp_name);
        let webauthn = Arc::new(builder.build()?);

        Ok(Self { webauthn })
    }
}

// ============================================================================
// Database Models
// ============================================================================

#[derive(sqlx::FromRow, Clone, Debug, Serialize)]
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

#[derive(sqlx::FromRow, Clone, Debug, Serialize)]
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
    #[allow(dead_code)]
    pub label: Option<String>,
    #[serde(alias = "flow_id")]
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    let expires_at =
        chrono::DateTime::from_timestamp_millis(req.expires_at).unwrap_or_else(chrono::Utc::now);

    sqlx::query_as::<_, WebAuthnChallenge>(
        r#"
        INSERT INTO webauthn_challenges (id, challenge, user_id, challenge_type, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(&req.id)
    .bind(&req.challenge)
    .bind(req.user_id)
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
    .bind(req.user_id)
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
// Helper Functions
// ============================================================================

fn base64_url_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(data)
}

// ============================================================================
// Route Handlers
// ============================================================================

pub async fn register_begin(
    State((pool, config)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Json(req): Json<RegisterBeginRequest>,
) -> impl IntoResponse {
    // Generate registration options
    let user_name = req.email.clone();
    let user_display_name = req.display_name.unwrap_or_else(|| req.email.clone());

    // Get existing credentials to exclude them
    let exclude_credentials = match get_credentials_by_user(&pool, req.user_id).await {
        Ok(creds) => creds
            .iter()
            .filter_map(|c| {
                let bytes = base64_url_decode(&c.id).ok()?;
                Some(CredentialID::from(bytes))
            })
            .collect(),
        Err(_) => vec![],
    };

    let res = match config.webauthn.start_passkey_registration(
        req.user_id,
        &user_name,
        &user_display_name,
        Some(exclude_credentials),
    ) {
        Ok((ccr, reg_state)) => {
            // Store the challenge
            let challenge_id = Uuid::new_v4().to_string();
            let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

            let challenge_req = ChallengeCreateRequest {
                id: challenge_id.clone(),
                challenge: serde_json::to_string(&reg_state).unwrap_or_default(),
                user_id: Some(req.user_id),
                challenge_type: "registration".to_string(),
                expires_at: expires_at.timestamp_millis(),
            };

            match create_challenge(&pool, &challenge_req).await {
                Ok(_) => (
                    StatusCode::OK,
                    Json(RegisterBeginResponse {
                        success: true,
                        options: Some(ccr),
                        challenge_id: Some(challenge_id),
                        error: None,
                    }),
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RegisterBeginResponse {
                        success: false,
                        options: None,
                        challenge_id: None,
                        error: Some(format!("Failed to store challenge: {}", e)),
                    }),
                ),
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RegisterBeginResponse {
                success: false,
                options: None,
                challenge_id: None,
                error: Some(format!("Failed to generate registration options: {}", e)),
            }),
        ),
    };

    res
}

pub async fn register_verify(
    State((pool, config)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Json(req): Json<RegisterVerifyRequest>,
) -> impl IntoResponse {
    // Get the challenge from the database
    let challenge = match get_challenge(&pool, &req.challenge_id).await {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(RegisterVerifyResponse {
                    success: false,
                    credential_id: None,
                    error: Some("Challenge not found".to_string()),
                }),
            )
        }
    };

    // Check if challenge is expired
    if challenge.expires_at < chrono::Utc::now() {
        let _ = delete_challenge(&pool, &req.challenge_id).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterVerifyResponse {
                success: false,
                credential_id: None,
                error: Some("Challenge expired".to_string()),
            }),
        );
    }

    // Deserialize the registration state
    let reg_state: PasskeyRegistration = match serde_json::from_str(&challenge.challenge) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RegisterVerifyResponse {
                    success: false,
                    credential_id: None,
                    error: Some(format!("Invalid challenge state: {}", e)),
                }),
            )
        }
    };

    // Verify the registration response
    let passkey = match config
        .webauthn
        .finish_passkey_registration(&req.response, &reg_state)
    {
        Ok(pk) => pk,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RegisterVerifyResponse {
                    success: false,
                    credential_id: None,
                    error: Some(format!("Registration verification failed: {}", e)),
                }),
            )
        }
    };

    // Extract credential information
    let credential_id = base64_url_encode(passkey.cred_id().as_ref());

    // Serialize the entire passkey to store it
    let passkey_json = serde_json::to_string(&passkey).unwrap_or_default();
    let public_key_bytes = passkey_json.as_bytes().to_vec();

    // Store the credential
    let cred_req = CredentialCreateRequest {
        id: credential_id.clone(),
        user_id: challenge.user_id.unwrap_or_default(),
        public_key: public_key_bytes,
        counter: 0, // Initial counter
        transports: None,
        aaguid: None,
        credential_type: Some("public-key".to_string()),
        user_verified: None,
        credential_device_type: None,
        credential_backed_up: None,
        name: req.label,
    };

    match create_credential(&pool, &cred_req).await {
        Ok(_) => {
            // Clean up the challenge
            let _ = delete_challenge(&pool, &req.challenge_id).await;

            (
                StatusCode::OK,
                Json(RegisterVerifyResponse {
                    success: true,
                    credential_id: Some(credential_id),
                    error: None,
                }),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RegisterVerifyResponse {
                success: false,
                credential_id: None,
                error: Some(format!("Failed to store credential: {}", e)),
            }),
        ),
    }
}

pub async fn authenticate_begin(
    State((pool, config)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Json(_req): Json<AuthenticateBeginRequest>,
) -> impl IntoResponse {
    // Start discoverable authentication (passkey)
    // Empty credentials array allows any passkey to authenticate
    let empty_creds: Vec<Passkey> = vec![];

    let res = match config.webauthn.start_passkey_authentication(&empty_creds) {
        Ok((rcr, auth_state)) => {
            // Store the challenge
            let challenge_id = Uuid::new_v4().to_string();
            let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

            let challenge_req = ChallengeCreateRequest {
                id: challenge_id.clone(),
                challenge: serde_json::to_string(&auth_state).unwrap_or_default(),
                user_id: None, // No user ID for discoverable authentication
                challenge_type: "discoverable_authentication".to_string(),
                expires_at: expires_at.timestamp_millis(),
            };

            match create_challenge(&pool, &challenge_req).await {
                Ok(_) => (
                    StatusCode::OK,
                    Json(AuthenticateBeginResponse {
                        success: true,
                        challenge_id: Some(challenge_id),
                        options: Some(rcr),
                        error: None,
                    }),
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AuthenticateBeginResponse {
                        success: false,
                        challenge_id: None,
                        options: None,
                        error: Some(format!("Failed to store challenge: {}", e)),
                    }),
                ),
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthenticateBeginResponse {
                success: false,
                challenge_id: None,
                options: None,
                error: Some(format!("Failed to generate authentication options: {}", e)),
            }),
        ),
    };

    res
}

pub async fn authenticate_verify(
    State((pool, config)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Json(req): Json<AuthenticateVerifyRequest>,
) -> impl IntoResponse {
    // Get the challenge if provided
    let challenge_id = req.challenge_id.clone().unwrap_or_default();

    let challenge = match get_challenge(&pool, &challenge_id).await {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(AuthenticateVerifyResponse {
                    success: false,
                    message: None,
                    user: None,
                    session_token: None,
                    error: Some("Challenge not found".to_string()),
                }),
            )
        }
    };

    // Check if challenge is expired
    if challenge.expires_at < chrono::Utc::now() {
        let _ = delete_challenge(&pool, &challenge_id).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(AuthenticateVerifyResponse {
                success: false,
                message: None,
                user: None,
                session_token: None,
                error: Some("Challenge expired".to_string()),
            }),
        );
    }

    // Deserialize the authentication state
    let auth_state: PasskeyAuthentication = match serde_json::from_str(&challenge.challenge) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthenticateVerifyResponse {
                    success: false,
                    message: None,
                    user: None,
                    session_token: None,
                    error: Some(format!("Invalid challenge state: {}", e)),
                }),
            )
        }
    };

    // Get the credential ID from the response
    let credential_id = &req.response.id;

    // Fetch the credential from database
    let db_credential = match get_credential(&pool, credential_id).await {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(AuthenticateVerifyResponse {
                    success: false,
                    message: None,
                    user: None,
                    session_token: None,
                    error: Some("Credential not found".to_string()),
                }),
            )
        }
    };

    // Deserialize the stored passkey
    let passkey_json = String::from_utf8_lossy(&db_credential.public_key);
    let _passkey: Passkey = match serde_json::from_str(&passkey_json) {
        Ok(pk) => pk,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthenticateVerifyResponse {
                    success: false,
                    message: None,
                    user: None,
                    session_token: None,
                    error: Some(format!("Failed to deserialize passkey: {}", e)),
                }),
            )
        }
    };

    // Verify the authentication response using the passkey
    let _auth_result = match config
        .webauthn
        .finish_passkey_authentication(&req.response, &auth_state)
    {
        Ok(result) => result,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthenticateVerifyResponse {
                    success: false,
                    message: None,
                    user: None,
                    session_token: None,
                    error: Some(format!("Authentication verification failed: {}", e)),
                }),
            )
        }
    };

    // Update credential counter - increment from database value
    let new_counter = db_credential.counter + 1;
    let _ = update_credential_counter(&pool, credential_id, new_counter, Some(chrono::Utc::now()))
        .await;

    // Get user information
    let user = match crate::db::get_user_by_id(&pool, db_credential.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(AuthenticateVerifyResponse {
                    success: false,
                    message: None,
                    user: None,
                    session_token: None,
                    error: Some("User not found".to_string()),
                }),
            )
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthenticateVerifyResponse {
                    success: false,
                    message: None,
                    user: None,
                    session_token: None,
                    error: Some(format!("Failed to fetch user: {}", e)),
                }),
            )
        }
    };

    // Create a session
    let refresh_token = Uuid::new_v4().to_string();
    let _session = match crate::db::create_session(&pool, user.id, &refresh_token, 24 * 30).await {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthenticateVerifyResponse {
                    success: false,
                    message: None,
                    user: None,
                    session_token: None,
                    error: Some(format!("Failed to create session: {}", e)),
                }),
            )
        }
    };

    // Issue access token
    let access_token = match crate::auth::issue_access_token(&user) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthenticateVerifyResponse {
                    success: false,
                    message: None,
                    user: None,
                    session_token: None,
                    error: Some(format!("Failed to issue access token: {}", e)),
                }),
            )
        }
    };

    // Clean up the challenge
    let _ = delete_challenge(&pool, &challenge_id).await;

    // Return success with user and token
    (
        StatusCode::OK,
        Json(AuthenticateVerifyResponse {
            success: true,
            message: Some("Authentication successful".to_string()),
            user: Some(serde_json::to_value(&user).unwrap_or_default()),
            session_token: Some(access_token),
            error: None,
        }),
    )
}

// Challenge management endpoints

pub async fn create_challenge_handler(
    State((pool, _)): State<(PgPool, Arc<WebAuthnConfig>)>,
    Json(req): Json<ChallengeCreateRequest>,
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
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({ "success": true }))),
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
        .and_then(chrono::DateTime::from_timestamp_millis);

    match update_credential_counter(&pool, &credential_id, req.counter, last_used).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({ "success": true }))),
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
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({ "success": true }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "success": false, "error": e.to_string() })),
        ),
    }
}
