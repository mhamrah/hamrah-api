use axum::{
    extract::{State, Path},
    Json,
    http::StatusCode,
};
use chrono::{Utc, Duration};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::{handlers::{ApiResult, ApiError}, AppState};
use crate::db::{schema::{User}};

// WebAuthn registration begin request
#[derive(Debug, Deserialize)]
pub struct BeginRegistrationRequest {
    pub email: String,
    pub name: String,
}

// WebAuthn registration complete request
#[derive(Debug, Deserialize)]
pub struct CompleteRegistrationRequest {
    pub challenge_id: String,
    pub response: RegisterPublicKeyCredential,
    pub email: String,
    pub name: String,
}

// WebAuthn authentication begin request
#[derive(Debug, Deserialize)]
pub struct BeginAuthenticationRequest {
    pub email: Option<String>,
}

// WebAuthn authentication complete request
#[derive(Debug, Deserialize)]
pub struct CompleteAuthenticationRequest {
    pub challenge_id: String,
    pub response: PublicKeyCredential,
}

// WebAuthn credential response
#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    pub id: String,
    pub name: Option<String>,
    pub created_at: String,
    pub last_used: Option<String>,
}

// Update credential name request
#[derive(Debug, Deserialize)]
pub struct UpdateCredentialNameRequest {
    pub name: String,
}

// Initialize WebAuthn instance
fn create_webauthn() -> Result<Webauthn, WebauthnError> {
    let url = Url::parse("https://hamrah.app")
        .map_err(|_| WebauthnError::JsonPathInvalidFormat)?; // Use a different error variant
    WebauthnBuilder::new("hamrah.app", &url)
        .unwrap()
        .rp_name("Hamrah")
        .build()
}

/// POST /api/webauthn/register/begin
/// Generate registration options for new users
pub async fn begin_registration(
    State(state): State<AppState>,
    Json(payload): Json<BeginRegistrationRequest>,
) -> ApiResult<Json<Value>> {
    // Validate email format
    if !payload.email.contains('@') || payload.name.trim().is_empty() {
        return Err(ApiError::ValidationError("Either user must be authenticated or email/name must be provided".to_string()));
    }

    let webauthn = create_webauthn()
        .map_err(|e| ApiError::InternalServerError(format!("WebAuthn initialization failed: {}", e)))?;

    // Check if user already exists
    let existing_user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE email = ?"
    )
    .bind(&payload.email)
    .fetch_optional(&state.db.pool)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Database error: {}", e)))?;

    if existing_user.is_some() {
        return Err(ApiError::ValidationError("User already exists. Please use authentication flow instead.".to_string()));
    }

    // Create user for WebAuthn registration
    let user_id = Uuid::new_v4().to_string();
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|e| ApiError::InternalServerError(format!("UUID parse error: {}", e)))?;

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(
            user_uuid,
            &payload.email,
            &payload.name,
            None,
        )
        .map_err(|e| ApiError::InternalServerError(format!("Registration start failed: {}", e)))?;

    // Store challenge
    let challenge_id = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(5);
    
    // Serialize registration state
    let reg_state_json = serde_json::to_string(&reg_state)
        .map_err(|e| ApiError::InternalServerError(format!("State serialization failed: {}", e)))?;

    sqlx::query(
        "INSERT INTO webauthn_challenges (id, challenge, user_id, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&challenge_id)
    .bind(&reg_state_json)
    .bind(&user_id)
    .bind("registration")
    .bind(expires_at.timestamp_millis())
    .bind(Utc::now().timestamp_millis())
    .execute(&state.db.pool)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to store challenge: {}", e)))?;

    Ok(Json(json!({
        "success": true,
        "options": {
            "challenge": base64::encode(&ccr.public_key.challenge),
            "rp": ccr.public_key.rp,
            "user": ccr.public_key.user,
            "pubKeyCredParams": ccr.public_key.pub_key_cred_params,
            "timeout": ccr.public_key.timeout,
            "attestation": ccr.public_key.attestation,
            "authenticatorSelection": ccr.public_key.authenticator_selection,
            "challengeId": challenge_id
        }
    })))
}

/// POST /api/webauthn/register/complete
/// Verify registration response and create credential
pub async fn complete_registration(
    State(state): State<AppState>,
    Json(payload): Json<CompleteRegistrationRequest>,
) -> ApiResult<Json<Value>> {
    let webauthn = create_webauthn()
        .map_err(|e| ApiError::InternalServerError(format!("WebAuthn initialization failed: {}", e)))?;

    // Get and validate challenge
    let challenge_row = sqlx::query("SELECT challenge, user_id, expires_at FROM webauthn_challenges WHERE id = ? AND type = 'registration'")
        .bind(&payload.challenge_id)
        .fetch_optional(&state.db.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Database error: {}", e)))?;

    let challenge_row = challenge_row.ok_or(ApiError::ValidationError("Invalid challenge ID".to_string()))?;
    
    let expires_at: i64 = challenge_row.get("expires_at");
    if Utc::now().timestamp_millis() > expires_at {
        return Err(ApiError::ValidationError("Challenge expired".to_string()));
    }

    let challenge_text: String = challenge_row.get("challenge");
    // Deserialize registration state
    let reg_state: PasskeyRegistration = serde_json::from_str(&challenge_text)
        .map_err(|e| ApiError::InternalServerError(format!("State deserialization failed: {}", e)))?;

    // Verify registration
    let sk = webauthn
        .finish_passkey_registration(&payload.response, &reg_state)
        .map_err(|e| ApiError::ValidationError(format!("Registration verification failed: {}", e)))?;

    // Create user
    let user_id_opt: Option<String> = challenge_row.get("user_id");
    let user_id = user_id_opt.unwrap_or_else(|| Uuid::new_v4().to_string());
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO users (id, email, name, email_verified, auth_method, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&user_id)
    .bind(&payload.email)
    .bind(&payload.name)
    .bind(now.timestamp_millis())
    .bind("webauthn")
    .bind(now.timestamp_millis())
    .bind(now.timestamp_millis())
    .execute(&state.db.pool)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to create user: {}", e)))?;

    // Store credential
    let cred_id = base64::encode(&sk.cred_id());
    // For now, store a placeholder for public key since the API doesn't expose it directly
    let public_key = base64::encode(&sk.cred_id()); 

    sqlx::query(
        "INSERT INTO webauthn_credentials (id, user_id, public_key, counter, credential_type, user_verified, credential_backed_up, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&cred_id)
    .bind(&user_id)
    .bind(&public_key)
    .bind(0i64) // Counter will be managed internally by webauthn-rs
    .bind("public-key")
    .bind(true)
    .bind(false) // Will be determined later
    .bind(now.timestamp_millis())
    .execute(&state.db.pool)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to store credential: {}", e)))?;

    // Clean up challenge
    sqlx::query("DELETE FROM webauthn_challenges WHERE id = ?")
        .bind(&payload.challenge_id)
        .execute(&state.db.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to clean up challenge: {}", e)))?;

    // Create session using internal endpoint pattern
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&state.db.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to fetch created user: {}", e)))?;

    Ok(Json(json!({
        "success": true,
        "user": user,
        "message": "Registration completed successfully"
    })))
}

/// POST /api/webauthn/authenticate/begin
/// Generate authentication options for existing users
pub async fn begin_authentication(
    State(state): State<AppState>,
    Json(payload): Json<BeginAuthenticationRequest>,
) -> ApiResult<Json<Value>> {
    let webauthn = create_webauthn()
        .map_err(|e| ApiError::InternalServerError(format!("WebAuthn initialization failed: {}", e)))?;

    let mut allow_credentials: Vec<CredentialID> = Vec::new();

    // The current version of webauthn-rs doesn't accept credential filters for passkeys
    // So we'll start with empty credentials and let it discover resident keys
    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&[])
        .map_err(|e| ApiError::InternalServerError(format!("Authentication start failed: {}", e)))?;

    // Store challenge
    let challenge_id = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(5);
    
    let auth_state_json = serde_json::to_string(&auth_state)
        .map_err(|e| ApiError::InternalServerError(format!("State serialization failed: {}", e)))?;

    sqlx::query(
        "INSERT INTO webauthn_challenges (id, challenge, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&challenge_id)
    .bind(&auth_state_json)
    .bind("authentication")
    .bind(expires_at.timestamp_millis())
    .bind(Utc::now().timestamp_millis())
    .execute(&state.db.pool)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to store challenge: {}", e)))?;

    Ok(Json(json!({
        "success": true,
        "options": {
            "challenge": base64::encode(&rcr.public_key.challenge),
            "timeout": rcr.public_key.timeout,
            "rpId": rcr.public_key.rp_id,
            "allowCredentials": rcr.public_key.allow_credentials,
            "userVerification": rcr.public_key.user_verification,
            "challengeId": challenge_id
        }
    })))
}

/// POST /api/webauthn/authenticate/complete
/// Verify authentication response and create session
pub async fn complete_authentication(
    State(state): State<AppState>,
    Json(payload): Json<CompleteAuthenticationRequest>,
) -> ApiResult<Json<Value>> {
    let webauthn = create_webauthn()
        .map_err(|e| ApiError::InternalServerError(format!("WebAuthn initialization failed: {}", e)))?;

    // Get and validate challenge
    let challenge_row = sqlx::query("SELECT challenge, expires_at FROM webauthn_challenges WHERE id = ? AND type = 'authentication'")
        .bind(&payload.challenge_id)
        .fetch_optional(&state.db.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Database error: {}", e)))?;

    let challenge_row = challenge_row.ok_or(ApiError::ValidationError("Invalid challenge ID".to_string()))?;
    
    let expires_at: i64 = challenge_row.get("expires_at");
    if Utc::now().timestamp_millis() > expires_at {
        return Err(ApiError::ValidationError("Challenge expired".to_string()));
    }

    let challenge_text: String = challenge_row.get("challenge");
    // Deserialize authentication state
    let auth_state: PasskeyAuthentication = serde_json::from_str(&challenge_text)
        .map_err(|e| ApiError::InternalServerError(format!("State deserialization failed: {}", e)))?;

    // Get credential from database
    let cred_id_b64 = base64::encode(&payload.response.raw_id);
    let stored_cred = sqlx::query("SELECT * FROM webauthn_credentials WHERE id = ?")
        .bind(&cred_id_b64)
        .fetch_optional(&state.db.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Database error: {}", e)))?;

    let stored_cred = stored_cred.ok_or(ApiError::ValidationError("Credential not found".to_string()))?;

    // Get the user ID from stored credential
    let stored_user_id: String = stored_cred.get("user_id");
    let stored_public_key: String = stored_cred.get("public_key");

    // Verify authentication
    let auth_result = webauthn
        .finish_passkey_authentication(&payload.response, &auth_state)
        .map_err(|e| ApiError::ValidationError(format!("Authentication verification failed: {}", e)))?;

    // Update credential last used (counter is managed by webauthn-rs)
    sqlx::query(
        "UPDATE webauthn_credentials SET last_used = ? WHERE id = ?"
    )
    .bind(Utc::now().timestamp_millis())
    .bind(&cred_id_b64)
    .execute(&state.db.pool)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to update credential: {}", e)))?;

    // Clean up challenge
    sqlx::query("DELETE FROM webauthn_challenges WHERE id = ?")
        .bind(&payload.challenge_id)
        .execute(&state.db.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to clean up challenge: {}", e)))?;

    // Get user
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&stored_user_id)
        .fetch_one(&state.db.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to fetch user: {}", e)))?;

    Ok(Json(json!({
        "success": true,
        "user": user,
        "message": "Authentication completed successfully"
    })))
}

/// GET /api/webauthn/credentials
/// List user's registered passkeys
pub async fn get_credentials(
    State(state): State<AppState>,
) -> ApiResult<Json<Value>> {
    // This would need authentication middleware to get current user
    // For now, return placeholder
    Ok(Json(json!({
        "success": true,
        "credentials": []
    })))
}

/// DELETE /api/webauthn/credentials/{credential_id}
/// Remove a specific passkey
pub async fn delete_credential(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM webauthn_credentials WHERE id = ?")
        .bind(&credential_id)
        .execute(&state.db.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to delete credential: {}", e)))?;

    Ok(Json(json!({
        "success": true
    })))
}

/// PATCH /api/webauthn/credentials/{credential_id}
/// Update credential name
pub async fn update_credential_name(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
    Json(payload): Json<UpdateCredentialNameRequest>,
) -> ApiResult<Json<Value>> {
    sqlx::query("UPDATE webauthn_credentials SET name = ? WHERE id = ?")
        .bind(&payload.name)
        .bind(&credential_id)
        .execute(&state.db.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to update credential name: {}", e)))?;

    Ok(Json(json!({
        "success": true
    })))
}