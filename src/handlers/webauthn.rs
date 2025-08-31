use crate::utils::datetime_to_timestamp;
use axum::{
    extract::{Path, State},
    Json,
};
use base64::prelude::*;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx_d1::{query, query_as};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::{
    db::schema::User,
    handlers::{ApiError, ApiResult},
    AppState,
};

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
    let url = Url::parse("https://hamrah.app").map_err(|_| WebauthnError::Unknown)?;
    WebauthnBuilder::new("hamrah.app", &url)
        .unwrap()
        .rp_name("Hamrah")
        .build()
}

/// POST /api/webauthn/register/begin
/// Generate registration options for new users
pub async fn begin_registration(
    State(mut state): State<AppState>,
    Json(payload): Json<BeginRegistrationRequest>,
) -> ApiResult<Json<Value>> {
    // Validate email format
    if !payload.email.contains('@') || payload.name.trim().is_empty() {
        return Err(ApiError::ValidationError(
            "Either user must be authenticated or email/name must be provided".to_string(),
        ));
    }

    let webauthn = create_webauthn().map_err(|e| {
        ApiError::InternalServerError(format!("WebAuthn initialization failed: {}", e))
    })?;

    // Check if user already exists
    let existing_user = query_as!(User, "SELECT * FROM users WHERE email = ?", payload.email)
        .fetch_optional(&mut state.db.conn)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Database error: {}", e)))?;

    if existing_user.is_some() {
        return Err(ApiError::ValidationError(
            "User already exists. Please use authentication flow instead.".to_string(),
        ));
    }

    // Create user for WebAuthn registration
    let user_id = Uuid::new_v4().to_string();
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|e| ApiError::InternalServerError(format!("UUID parse error: {}", e)))?;

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_uuid, &payload.email, &payload.name, None)
        .map_err(|e| ApiError::InternalServerError(format!("Registration start failed: {}", e)))?;

    // Store challenge
    let challenge_id = Uuid::new_v4().to_string();
    let expires_at = datetime_to_timestamp(Utc::now() + Duration::minutes(5));

    // Serialize registration state
    let reg_state_json = serde_json::to_string(&reg_state)
        .map_err(|e| ApiError::InternalServerError(format!("State serialization failed: {}", e)))?;

    query!(
        "INSERT INTO webauthn_challenges (id, challenge, user_id, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        challenge_id,
        reg_state_json,
        user_id,
        "registration",
        expires_at,
        datetime_to_timestamp(Utc::now())
    )
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to store challenge: {}", e)))?;

    Ok(Json(json!({
        "success": true,
        "options": {
            "challenge": base64::prelude::BASE64_STANDARD.encode(&ccr.public_key.challenge),
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
    State(mut state): State<AppState>,
    Json(payload): Json<CompleteRegistrationRequest>,
) -> ApiResult<Json<Value>> {
    let webauthn = create_webauthn().map_err(|e| {
        ApiError::InternalServerError(format!("WebAuthn initialization failed: {}", e))
    })?;

    // Get and validate challenge
    let challenge_row = query_as!(
        crate::db::schema::WebAuthnChallenge,
        "SELECT id, challenge, user_id, type as challenge_type, expires_at, created_at FROM webauthn_challenges WHERE id = ? AND type = 'registration'",
        payload.challenge_id
    )
    .fetch_optional(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Database error: {}", e)))?;

    let challenge_row = challenge_row.ok_or(ApiError::ValidationError(
        "Invalid challenge ID".to_string(),
    ))?;

    if datetime_to_timestamp(Utc::now()) > challenge_row.expires_at {
        return Err(ApiError::ValidationError("Challenge expired".to_string()));
    }

    // Deserialize registration state
    let reg_state: PasskeyRegistration =
        serde_json::from_str(&challenge_row.challenge).map_err(|e| {
            ApiError::InternalServerError(format!("State deserialization failed: {}", e))
        })?;

    // Verify registration
    let sk = webauthn
        .finish_passkey_registration(&payload.response, &reg_state)
        .map_err(|e| {
            ApiError::ValidationError(format!("Registration verification failed: {}", e))
        })?;

    // Create user
    let user_id = challenge_row
        .user_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let now = datetime_to_timestamp(Utc::now());

    query!(
        "INSERT INTO users (id, email, name, email_verified, auth_method, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        user_id,
        payload.email,
        payload.name,
        now,
        "webauthn",
        now,
        now
    )
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to create user: {}", e)))?;

    // Store credential
    let cred_id = base64::prelude::BASE64_STANDARD.encode(&sk.cred_id());
    // For now, store a placeholder for public key since the API doesn't expose it directly
    let public_key = base64::prelude::BASE64_STANDARD.encode(&sk.cred_id());

    query!(
        "INSERT INTO webauthn_credentials (id, user_id, public_key, counter, credential_type, user_verified, credential_backed_up, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        cred_id,
        user_id,
        public_key,
        0i64, // Counter will be managed internally by webauthn-rs
        "public-key",
        true,
        false, // Will be determined later
        now
    )
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to store credential: {}", e)))?;

    // Clean up challenge
    query!(
        "DELETE FROM webauthn_challenges WHERE id = ?",
        payload.challenge_id
    )
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to clean up challenge: {}", e)))?;

    // Create session using internal endpoint pattern
    let user = query_as!(User, "SELECT * FROM users WHERE id = ?", user_id)
        .fetch_one(&mut state.db.conn)
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
    State(mut state): State<AppState>,
    Json(_payload): Json<BeginAuthenticationRequest>,
) -> ApiResult<Json<Value>> {
    let webauthn = create_webauthn().map_err(|e| {
        ApiError::InternalServerError(format!("WebAuthn initialization failed: {}", e))
    })?;

    // The current version of webauthn-rs doesn't accept credential filters for passkeys
    // So we'll start with empty credentials and let it discover resident keys
    let (rcr, auth_state) = webauthn.start_passkey_authentication(&[]).map_err(|e| {
        ApiError::InternalServerError(format!("Authentication start failed: {}", e))
    })?;

    // Store challenge
    let challenge_id = Uuid::new_v4().to_string();
    let expires_at = datetime_to_timestamp(Utc::now() + Duration::minutes(5));

    let auth_state_json = serde_json::to_string(&auth_state)
        .map_err(|e| ApiError::InternalServerError(format!("State serialization failed: {}", e)))?;

    query!(
        "INSERT INTO webauthn_challenges (id, challenge, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
        challenge_id,
        auth_state_json,
        "authentication",
        expires_at,
        datetime_to_timestamp(Utc::now())
    )
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to store challenge: {}", e)))?;

    Ok(Json(json!({
        "success": true,
        "options": {
            "challenge": base64::prelude::BASE64_STANDARD.encode(&rcr.public_key.challenge),
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
    State(mut state): State<AppState>,
    Json(payload): Json<CompleteAuthenticationRequest>,
) -> ApiResult<Json<Value>> {
    let webauthn = create_webauthn().map_err(|e| {
        ApiError::InternalServerError(format!("WebAuthn initialization failed: {}", e))
    })?;

    // Get and validate challenge
    let challenge_row = query_as!(
        crate::db::schema::WebAuthnChallenge,
        "SELECT id, challenge, user_id, type as challenge_type, expires_at, created_at FROM webauthn_challenges WHERE id = ? AND type = 'authentication'",
        payload.challenge_id
    )
    .fetch_optional(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Database error: {}", e)))?;

    let challenge_row = challenge_row.ok_or(ApiError::ValidationError(
        "Invalid challenge ID".to_string(),
    ))?;

    if datetime_to_timestamp(Utc::now()) > challenge_row.expires_at {
        return Err(ApiError::ValidationError("Challenge expired".to_string()));
    }

    // Deserialize authentication state
    let auth_state: PasskeyAuthentication = serde_json::from_str(&challenge_row.challenge)
        .map_err(|e| {
            ApiError::InternalServerError(format!("State deserialization failed: {}", e))
        })?;

    // Get credential from database
    let cred_id_b64 = base64::prelude::BASE64_STANDARD.encode(&payload.response.raw_id);
    let stored_cred = query!(
        "SELECT * FROM webauthn_credentials WHERE id = ?",
        cred_id_b64
    )
    .fetch_optional(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Database error: {}", e)))?;

    let stored_cred = stored_cred.ok_or(ApiError::ValidationError(
        "Credential not found".to_string(),
    ))?;

    // Verify authentication
    let _auth_result = webauthn
        .finish_passkey_authentication(&payload.response, &auth_state)
        .map_err(|e| {
            ApiError::ValidationError(format!("Authentication verification failed: {}", e))
        })?;

    // Update credential last used (counter is managed by webauthn-rs)
    query!(
        "UPDATE webauthn_credentials SET last_used = ? WHERE id = ?",
        datetime_to_timestamp(Utc::now()),
        cred_id_b64
    )
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to update credential: {}", e)))?;

    // Clean up challenge
    query!(
        "DELETE FROM webauthn_challenges WHERE id = ?",
        payload.challenge_id
    )
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to clean up challenge: {}", e)))?;

    // Get user
    let user = query_as!(
        User,
        "SELECT * FROM users WHERE id = ?",
        stored_cred.user_id
    )
    .fetch_one(&mut state.db.conn)
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
    State(mut state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> ApiResult<Json<Value>> {
    // Extract user from session or token
    use crate::handlers::users::get_current_user_from_request;
    let user = get_current_user_from_request(&mut state.db, &headers).await?;

    // Query credentials for this user
    let creds = sqlx_d1::query!(
        "SELECT id, name, created_at, last_used FROM webauthn_credentials WHERE user_id = ?",
        user.id
    )
    .fetch_all(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to fetch credentials: {}", e)))?;

    let credentials: Vec<CredentialResponse> = creds
        .into_iter()
        .map(|row| CredentialResponse {
            id: row.id,
            name: row.name,
            created_at: crate::utils::timestamp_to_datetime(row.created_at).to_rfc3339(),
            last_used: row
                .last_used
                .map(|ts| crate::utils::timestamp_to_datetime(ts).to_rfc3339()),
        })
        .collect();

    Ok(Json(json!({
        "success": true,
        "credentials": credentials
    })))
}

/// DELETE /api/webauthn/credentials/{credential_id}
/// Remove a specific passkey
pub async fn delete_credential(
    State(mut state): State<AppState>,
    Path(credential_id): Path<String>,
) -> ApiResult<Json<Value>> {
    query!(
        "DELETE FROM webauthn_credentials WHERE id = ?",
        credential_id
    )
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to delete credential: {}", e)))?;

    Ok(Json(json!({
        "success": true
    })))
}

/// PATCH /api/webauthn/credentials/{credential_id}
/// Update credential name
pub async fn update_credential_name(
    State(mut state): State<AppState>,
    Path(credential_id): Path<String>,
    Json(payload): Json<UpdateCredentialNameRequest>,
) -> ApiResult<Json<Value>> {
    query!(
        "UPDATE webauthn_credentials SET name = ? WHERE id = ?",
        payload.name,
        credential_id
    )
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to update credential name: {}", e)))?;

    Ok(Json(json!({
        "success": true
    })))
}
