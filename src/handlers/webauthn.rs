use crate::utils::datetime_to_timestamp;
use axum::{
    extract::{Path, State},
    Json,
};
use base64::prelude::*;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
// Conditional WebAuthn imports - only available for non-WASM targets
#[cfg(not(target_arch = "wasm32"))]
use webauthn_rs::prelude::*;

// WASM-compatible stub types for WebAuthn
#[cfg(target_arch = "wasm32")]
mod webauthn_stubs {
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Webauthn;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct WebauthnBuilder;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CreationChallengeResponse {
        pub public_key: PublicKeyCredentialCreationOptions,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RequestChallengeResponse {
        pub public_key: PublicKeyCredentialRequestOptions,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PublicKeyCredentialCreationOptions {
        pub challenge: Vec<u8>,
        pub rp: RelyingParty,
        pub user: User,
        pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
        pub timeout: Option<u32>,
        pub attestation: String,
        pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PublicKeyCredentialRequestOptions {
        pub challenge: Vec<u8>,
        pub timeout: Option<u32>,
        pub rp_id: Option<String>,
        pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
        pub user_verification: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RelyingParty {
        pub id: String,
        pub name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct User {
        pub id: Vec<u8>,
        pub name: String,
        pub display_name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PublicKeyCredentialParameters {
        #[serde(rename = "type")]
        pub type_: String,
        pub alg: i32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthenticatorSelectionCriteria;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PublicKeyCredentialDescriptor;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PasskeyRegistration;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PasskeyAuthentication;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Passkey {
        cred_id: Vec<u8>,
    }

    impl Passkey {
        pub fn cred_id(&self) -> &[u8] {
            &self.cred_id
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterPublicKeyCredential {
        pub raw_id: Vec<u8>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PublicKeyCredential {
        pub raw_id: Vec<u8>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Url;

    impl Url {
        #[allow(dead_code)] // WASM stub implementation
        pub fn parse(_: &str) -> Result<Self, Box<dyn std::error::Error>> {
            Err("WebAuthn not supported in WASM".into())
        }
    }

    impl WebauthnBuilder {
        #[allow(dead_code)] // WASM stub implementation
        pub fn new(_domain: &str, _url: &Url) -> Result<Self, Box<dyn std::error::Error>> {
            Err("WebAuthn not supported in WASM".into())
        }
    }

    impl Webauthn {
        pub fn start_passkey_registration(
            &self,
            _user_uuid: Uuid,
            _username: &str,
            _display_name: &str,
            _exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
        ) -> Result<(CreationChallengeResponse, PasskeyRegistration), Box<dyn std::error::Error>>
        {
            Err("WebAuthn not supported in WASM".into())
        }

        pub fn finish_passkey_registration(
            &self,
            _reg: &RegisterPublicKeyCredential,
            _state: &PasskeyRegistration,
        ) -> Result<Passkey, Box<dyn std::error::Error>> {
            Err("WebAuthn not supported in WASM".into())
        }

        pub fn start_passkey_authentication(
            &self,
            _creds: &[PublicKeyCredentialDescriptor],
        ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), Box<dyn std::error::Error>>
        {
            Err("WebAuthn not supported in WASM".into())
        }

        pub fn finish_passkey_authentication(
            &self,
            _cred: &PublicKeyCredential,
            _state: &PasskeyAuthentication,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Err("WebAuthn not supported in WASM".into())
        }
    }
}

use sqlx_d1::query_as;
#[cfg(target_arch = "wasm32")]
use webauthn_stubs::*;

// Conditional imports for FromRow trait
#[cfg(not(target_arch = "wasm32"))]
use sqlx::FromRow;

#[cfg(target_arch = "wasm32")]
use sqlx_d1::FromRow;

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
    #[allow(dead_code)] // May be used for email-based authentication flows
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

// Helper struct for credentials list query
#[derive(Debug, FromRow)]
pub struct CredentialListRow {
    pub id: String,
    pub name: Option<String>,
    pub created_at: i64,
    pub last_used: Option<i64>,
}

// Update credential name request
#[derive(Debug, Deserialize)]
pub struct UpdateCredentialNameRequest {
    pub name: String,
}

// Initialize WebAuthn instance - conditional implementation
#[cfg(not(target_arch = "wasm32"))]
fn create_webauthn() -> ApiResult<Webauthn> {
    let url = Url::parse("https://hamrah.app")
        .map_err(|err| ApiError::ValidationError(err.to_string()))?;
    WebauthnBuilder::new("hamrah.app", &url)
        .map_err(|e| {
            ApiError::InternalServerError(format!("WebAuthn initialization failed: {:?}", e))
        })?
        .rp_name("Hamrah")
        .build()
        .map_err(|e| ApiError::InternalServerError(format!("WebAuthn build failed: {:?}", e)))
}

// WASM stub implementation - returns error as WebAuthn is not supported in WASM
#[cfg(target_arch = "wasm32")]
fn create_webauthn() -> ApiResult<Webauthn> {
    Err(ApiError::InternalServerError("WebAuthn functionality is not available in WASM builds. Use native build for WebAuthn operations.".to_string()))
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
        ApiError::InternalServerError(format!("WebAuthn initialization failed: {:?}", e))
    })?;

    // Check if user already exists
    let existing_user = query_as::<User>("SELECT * FROM users WHERE email = ?")
        .bind(&payload.email)
        .fetch_optional(&mut state.db.conn)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Database error: {:?}", e)))?;

    if existing_user.is_some() {
        return Err(ApiError::ValidationError(
            "User already exists. Please use authentication flow instead.".to_string(),
        ));
    }

    // Create user for WebAuthn registration
    let user_id = Uuid::new_v4().to_string();
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|e| ApiError::InternalServerError(format!("UUID parse error: {:?}", e)))?;

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_uuid, &payload.email, &payload.name, None)
        .map_err(|e| {
            ApiError::InternalServerError(format!("Registration start failed: {:?}", e))
        })?;

    // Store challenge
    let challenge_id = Uuid::new_v4().to_string();
    let expires_at = datetime_to_timestamp(Utc::now() + Duration::minutes(5));

    // Serialize registration state
    let reg_state_json = serde_json::to_string(&reg_state).map_err(|e| {
        ApiError::InternalServerError(format!("State serialization failed: {:?}", e))
    })?;

    sqlx_d1::query("INSERT INTO webauthn_challenges (id, challenge, user_id, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&challenge_id)
        .bind(&reg_state_json)
        .bind(&user_id)
        .bind("registration")
        .bind(expires_at)
        .bind(datetime_to_timestamp(Utc::now()))
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to store challenge: {:?}", e)))?;

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
        ApiError::InternalServerError(format!("WebAuthn initialization failed: {:?}", e))
    })?;

    // Get and validate challenge
    let challenge_row = query_as::<crate::db::schema::WebAuthnChallenge>(
        "SELECT id, challenge, user_id, type as challenge_type, expires_at, created_at FROM webauthn_challenges WHERE id = ? AND type = 'registration'"
    )
    .bind(&payload.challenge_id)
    .fetch_optional(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Database error: {:?}", e)))?;

    let challenge_row = challenge_row.ok_or(ApiError::ValidationError(
        "Invalid challenge ID".to_string(),
    ))?;

    if datetime_to_timestamp(Utc::now()) > challenge_row.expires_at {
        return Err(ApiError::ValidationError("Challenge expired".to_string()));
    }

    // Deserialize registration state
    let reg_state: PasskeyRegistration =
        serde_json::from_str(&challenge_row.challenge).map_err(|e| {
            ApiError::InternalServerError(format!("State deserialization failed: {:?}", e))
        })?;

    // Verify registration
    let sk = webauthn
        .finish_passkey_registration(&payload.response, &reg_state)
        .map_err(|e| {
            ApiError::ValidationError(format!("Registration verification failed: {:?}", e))
        })?;

    // Create user
    let user_id = challenge_row
        .user_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let now = datetime_to_timestamp(Utc::now());

    sqlx_d1::query(
        "INSERT INTO users (id, email, name, email_verified, auth_method, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&user_id)
    .bind(&payload.email)
    .bind(&payload.name)
    .bind(now)
    .bind("webauthn")
    .bind(now)
    .bind(now)
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to create user: {:?}", e)))?;

    // Store credential
    let cred_id = base64::prelude::BASE64_STANDARD.encode(sk.cred_id());
    // For now, store a placeholder for public key since the API doesn't expose it directly
    let public_key = base64::prelude::BASE64_STANDARD.encode(sk.cred_id());

    sqlx_d1::query(
        "INSERT INTO webauthn_credentials (id, user_id, public_key, counter, credential_type, user_verified, credential_backed_up, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&cred_id)
    .bind(&user_id)
    .bind(&public_key)
    .bind(0i64) // Counter will be managed internally by webauthn-rs
    .bind("public-key")
    .bind(true)
    .bind(false) // Will be determined later
    .bind(now)
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to store credential: {:?}", e)))?;

    // Clean up challenge
    sqlx_d1::query("DELETE FROM webauthn_challenges WHERE id = ?")
        .bind(&payload.challenge_id)
        .execute(&mut state.db.conn)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to clean up challenge: {:?}", e)))?;

    // Create session using internal endpoint pattern
    let user = query_as::<User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&mut state.db.conn)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to fetch created user: {:?}", e)))?;

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
        ApiError::InternalServerError(format!("WebAuthn initialization failed: {:?}", e))
    })?;

    // The current version of webauthn-rs doesn't accept credential filters for passkeys
    // So we'll start with empty credentials and let it discover resident keys
    let (rcr, auth_state) = webauthn.start_passkey_authentication(&[]).map_err(|e| {
        ApiError::InternalServerError(format!("Authentication start failed: {:?}", e))
    })?;

    // Store challenge
    let challenge_id = Uuid::new_v4().to_string();
    let expires_at = datetime_to_timestamp(Utc::now() + Duration::minutes(5));

    let auth_state_json = serde_json::to_string(&auth_state).map_err(|e| {
        ApiError::InternalServerError(format!("State serialization failed: {:?}", e))
    })?;

    sqlx_d1::query(
        "INSERT INTO webauthn_challenges (id, challenge, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&challenge_id)
    .bind(&auth_state_json)
    .bind("authentication")
    .bind(expires_at)
    .bind(datetime_to_timestamp(Utc::now()))
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to store challenge: {:?}", e)))?;

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
        ApiError::InternalServerError(format!("WebAuthn initialization failed: {:?}", e))
    })?;

    // Get and validate challenge
    let challenge_row = query_as::<crate::db::schema::WebAuthnChallenge>(
        "SELECT id, challenge, user_id, type as challenge_type, expires_at, created_at FROM webauthn_challenges WHERE id = ? AND type = 'authentication'"
    )
    .bind(&payload.challenge_id)
    .fetch_optional(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Database error: {:?}", e)))?;

    let challenge_row = challenge_row.ok_or(ApiError::ValidationError(
        "Invalid challenge ID".to_string(),
    ))?;

    if datetime_to_timestamp(Utc::now()) > challenge_row.expires_at {
        return Err(ApiError::ValidationError("Challenge expired".to_string()));
    }

    // Deserialize authentication state
    let auth_state: PasskeyAuthentication = serde_json::from_str(&challenge_row.challenge)
        .map_err(|e| {
            ApiError::InternalServerError(format!("State deserialization failed: {:?}", e))
        })?;

    // Get credential from database
    let cred_id_b64 = base64::prelude::BASE64_STANDARD.encode(&payload.response.raw_id);
    let stored_cred = query_as::<crate::db::schema::WebAuthnCredential>(
        "SELECT * FROM webauthn_credentials WHERE id = ?",
    )
    .bind(&cred_id_b64)
    .fetch_optional(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Database error: {:?}", e)))?;

    let stored_cred = stored_cred.ok_or(ApiError::ValidationError(
        "Credential not found".to_string(),
    ))?;

    // Verify authentication
    let _auth_result = webauthn
        .finish_passkey_authentication(&payload.response, &auth_state)
        .map_err(|e| {
            ApiError::ValidationError(format!("Authentication verification failed: {:?}", e))
        })?;

    // Update credential last used (counter is managed by webauthn-rs)
    sqlx_d1::query("UPDATE webauthn_credentials SET last_used = ? WHERE id = ?")
        .bind(datetime_to_timestamp(Utc::now()))
        .bind(&cred_id_b64)
        .execute(&mut state.db.conn)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to update credential: {:?}", e)))?;

    // Clean up challenge
    sqlx_d1::query("DELETE FROM webauthn_challenges WHERE id = ?")
        .bind(&payload.challenge_id)
        .execute(&mut state.db.conn)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to clean up challenge: {:?}", e)))?;

    // Get user
    let user = query_as::<User>("SELECT * FROM users WHERE id = ?")
        .bind(&stored_cred.user_id)
        .fetch_one(&mut state.db.conn)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to fetch user: {:?}", e)))?;

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
    let creds = query_as::<CredentialListRow>(
        "SELECT id, name, created_at, last_used FROM webauthn_credentials WHERE user_id = ?",
    )
    .bind(&user.id)
    .fetch_all(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to fetch credentials: {:?}", e)))?;

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
    sqlx_d1::query("DELETE FROM webauthn_credentials WHERE id = ?")
        .bind(&credential_id)
        .execute(&mut state.db.conn)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to delete credential: {:?}", e)))?;

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
    sqlx_d1::query("UPDATE webauthn_credentials SET name = ? WHERE id = ?")
        .bind(&payload.name)
        .bind(&credential_id)
        .execute(&mut state.db.conn)
        .await
        .map_err(|e| {
            ApiError::DatabaseError(format!("Failed to update credential name: {:?}", e))
        })?;

    Ok(Json(json!({
        "success": true
    })))
}
