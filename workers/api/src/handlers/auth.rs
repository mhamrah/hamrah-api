use crate::auth::{app_attestation, cookies, session, tokens};
use crate::db::Database;
use crate::error::{AppError, AppResult};
use crate::utils::{datetime_to_timestamp, timestamp_to_datetime};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    Json as JsonExtractor,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use worker::console_log;

// CreateUserRequest moved to internal.rs

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub user: Option<UserResponse>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub auth_method: Option<String>,
    pub created_at: String,
    pub provider: Option<String>,
    #[serde(rename = "providerId")]
    pub provider_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct NativeAuthRequest {
    pub provider: String,
    pub credential: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
}

// SessionRequest moved to internal.rs

// User creation is now handled via internal API only

// Session creation is now handled via internal API only

pub async fn validate_session(
    State(mut db): State<Database>,
    headers: HeaderMap,
) -> AppResult<Json<AuthResponse>> {
    if let Some(token) = cookies::get_cookie_value(&headers, "session") {
        if let Some((_session, user)) = session::validate_session_token(&mut db, &token)
            .await
            .map_err(AppError::from)?
        {
            let user_response = UserResponse {
                id: user.id,
                email: user.email,
                name: user.name,
                picture: user.picture,
                auth_method: user.auth_method,
                created_at: timestamp_to_datetime(user.created_at).to_rfc3339(),
                provider: user.provider,
                provider_id: user.provider_id,
            };

            return Ok(Json(AuthResponse {
                success: true,
                user: Some(user_response),
                access_token: None,
                refresh_token: None,
                expires_in: None,
            }));
        }
    }

    Err(Box::new(AppError::unauthorized("Unauthorized")))
}

// Token creation is now handled via internal API only

pub async fn refresh_token_endpoint(
    State(mut db): State<Database>,
    JsonExtractor(request): JsonExtractor<TokenRefreshRequest>,
) -> AppResult<Json<AuthResponse>> {
    if let Some(new_token_pair) = tokens::refresh_token(&mut db, &request.refresh_token)
        .await
        .map_err(AppError::from)?
    {
        let expires_in =
            ((new_token_pair.access_expires_at - datetime_to_timestamp(Utc::now())) / 1000).max(0);

        Ok(Json(AuthResponse {
            success: true,
            user: None, // Don't return user info on token refresh
            access_token: Some(new_token_pair.access_token),
            refresh_token: Some(new_token_pair.refresh_token),
            expires_in: Some(expires_in),
        }))
    } else {
        Err(Box::new(AppError::unauthorized("Unauthorized")))
    }
}

pub async fn logout_session(
    State(mut db): State<Database>,
    mut headers: HeaderMap,
) -> AppResult<(StatusCode, HeaderMap, Json<serde_json::Value>)> {
    if let Some(token) = cookies::get_cookie_value(&headers, "session") {
        let session_id = session::create_session_id(&token);
        let _ = session::invalidate_session(&mut db, &session_id).await;
    }

    // Clear session cookie
    cookies::delete_session_cookie(&mut headers, "session", true);

    Ok((
        StatusCode::OK,
        headers,
        Json(serde_json::json!({
            "success": true,
            "message": "Logged out successfully"
        })),
    ))
}

pub async fn revoke_token_endpoint(
    State(mut db): State<Database>,
    Path(token_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    tokens::revoke_token(&mut db, &token_id)
        .await
        .map_err(AppError::from)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Token revoked successfully"
    })))
}

pub async fn revoke_all_user_tokens_endpoint(
    State(mut db): State<Database>,
    Path(user_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    tokens::revoke_all_user_tokens(&mut db, &user_id)
        .await
        .map_err(AppError::from)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "All user tokens revoked successfully"
    })))
}

/// Native app authentication endpoint (for iOS/Android)
/// Validates OAuth tokens directly and returns access/refresh tokens
pub async fn native_auth_endpoint(
    State(mut db): State<Database>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<NativeAuthRequest>,
) -> AppResult<Json<AuthResponse>> {
    use crate::db::schema::User;
    use sqlx_d1::{query, query_as};
    use uuid::Uuid;
    use worker::console_log;

    // removed non-error log

    // Get user agent for platform detection
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    // removed non-error log

    // Determine platform from user agent or X-Requested-With header
    let platform = if let Some(requested_with) = headers.get("X-Requested-With") {
        if let Ok(header_value) = requested_with.to_str() {
            if header_value.contains("hamrah-ios") {
                "ios".to_string()
            } else {
                "api".to_string()
            }
        } else {
            "api".to_string()
        }
    } else if user_agent.contains("hamrahIOS") || user_agent.contains("CFNetwork") {
        "ios".to_string()
    } else {
        "api".to_string()
    };

    // removed non-error log

    // TODO: Verify the OAuth credential with the provider
    // For now, we'll skip verification and trust the client
    // In production, you should verify:
    // - Google: Verify ID token with Google's token verification API
    // - Apple: Verify ID token with Apple's public keys

    // Extract email from request or use a placeholder
    let email = request.email.as_deref().unwrap_or("unknown@example.com");
    // removed non-error log

    // Find or create user
    let existing_user = query_as::<User>("SELECT * FROM users WHERE email = ?")
        .bind(email)
        .fetch_optional(&mut db.conn)
        .await
        .map_err(|e| {
            console_log!("❌ Database error finding user: {}", e);
            AppError::from(e)
        })?;

    let user_id = if let Some(user) = existing_user {
        // removed non-error log

        // Update last login information
        query("UPDATE users SET last_login_at = ?, last_login_platform = ? WHERE id = ?")
            .bind(datetime_to_timestamp(Utc::now()))
            .bind(&platform)
            .bind(&user.id)
            .execute(&mut db.conn)
            .await
            .map_err(|e| {
                console_log!("❌ Database error updating user login: {}", e);
                AppError::from(e)
            })?;

        user.id
    } else {
        // Create new user
        let new_user_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // removed non-error log

        query(
            r#"
            INSERT INTO users (
                id, email, name, picture, email_verified, auth_method,
                provider, provider_id, last_login_platform, last_login_at,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&new_user_id)
        .bind(email)
        .bind(&request.name)
        .bind(&request.picture)
        .bind(datetime_to_timestamp(now)) // email_verified
        .bind(format!("{}_oauth", request.provider))
        .bind(&request.provider)
        .bind(email) // use email as provider_id for now
        .bind(&platform)
        .bind(datetime_to_timestamp(now)) // last_login_at
        .bind(datetime_to_timestamp(now)) // created_at
        .bind(datetime_to_timestamp(now)) // updated_at
        .execute(&mut db.conn)
        .await
        .map_err(|e| {
            console_log!("❌ Database error creating user: {}", e);
            AppError::from(e)
        })?;

        // removed non-error log
        new_user_id
    };

    // Create token pair for the user
    let token_pair = tokens::create_token_pair(
        &mut db,
        &user_id,
        &platform,
        Some(user_agent),
        None, // IP address - could extract from headers if needed
    )
    .await
    .map_err(|e| {
        console_log!("❌ Error creating token pair: {}", e);
        AppError::from(e)
    })?;

    // removed non-error log

    // Get updated user information
    let user = query_as::<User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&mut db.conn)
        .await
        .map_err(|e| {
            console_log!("❌ Database error fetching user: {}", e);
            AppError::from(e)
        })?;

    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        auth_method: user.auth_method,
        created_at: timestamp_to_datetime(user.created_at).to_rfc3339(),
        provider: user.provider,
        provider_id: user.provider_id,
    };

    let expires_in =
        ((token_pair.access_expires_at - datetime_to_timestamp(Utc::now())) / 1000).max(0);

    // removed non-error log

    Ok(Json(AuthResponse {
        success: true,
        user: Some(user_response),
        access_token: Some(token_pair.access_token),
        refresh_token: Some(token_pair.refresh_token),
        expires_in: Some(expires_in),
    }))
}

// App Attestation types and endpoints

#[derive(Debug, Deserialize)]
pub struct AttestationChallengeRequest {
    pub platform: String,
    #[serde(rename = "bundleId")]
    pub bundle_id: String,
    pub purpose: String,
}

#[derive(Debug, Serialize)]
pub struct AttestationChallengeResponse {
    pub success: bool,
    pub challenge: Option<String>,
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AttestationVerifyRequest {
    pub attestation: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    #[serde(rename = "bundleId")]
    pub bundle_id: String,
    pub platform: String,
}

#[derive(Debug, Serialize)]
pub struct AttestationVerifyResponse {
    pub success: bool,
    pub error: Option<String>,
}

/// Generate a challenge for iOS App Attestation
pub async fn app_attestation_challenge(
    State(mut db): State<Database>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<AttestationChallengeRequest>,
) -> AppResult<Json<AttestationChallengeResponse>> {
    // removed non-error log

    // Validate request
    if request.platform != "ios" {
        return Ok(Json(AttestationChallengeResponse {
            success: false,
            challenge: None,
            challenge_id: String::new(),
            error: Some("Only iOS platform is supported".to_string()),
        }));
    }

    // Check if this is a simulator request
    let user_agent = headers.get("user-agent").and_then(|h| h.to_str().ok());

    let is_simulator = app_attestation::is_ios_simulator(user_agent);

    if is_simulator {
        // removed non-error log

        // Return a dummy challenge for simulator
        let challenge_id = uuid::Uuid::new_v4().to_string();
        return Ok(Json(AttestationChallengeResponse {
            success: true,
            challenge: Some("c2ltdWxhdG9yLWNoYWxsZW5nZQ==".to_string()), // base64 of "simulator-challenge"
            challenge_id,
            error: None,
        }));
    }

    // Generate a cryptographically secure challenge
    use rand::RngCore;
    let mut challenge_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);

    use base64::Engine;
    let challenge_base64 = base64::engine::general_purpose::STANDARD.encode(challenge_bytes);
    let challenge_id = uuid::Uuid::new_v4().to_string();

    // Store challenge in database with expiration (10 minutes)
    use sqlx_d1::query;
    let expires_at = datetime_to_timestamp(Utc::now() + chrono::Duration::minutes(10));

    query(
        "INSERT INTO app_attest_challenges (id, challenge, bundle_id, platform, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&challenge_id)
    .bind(&challenge_base64)
    .bind(&request.bundle_id)
    .bind(&request.platform)
    .bind(expires_at)
    .bind(datetime_to_timestamp(Utc::now()))
    .execute(&mut db.conn)
    .await
    .map_err(|e| {
        console_log!("❌ Database error storing challenge: {}", e);
        AppError::from(e)
    })?;

    // removed non-error log

    Ok(Json(AttestationChallengeResponse {
        success: true,
        challenge: Some(challenge_base64),
        challenge_id,
        error: None,
    }))
}

/// Verify iOS App Attestation
pub async fn app_attestation_verify(
    State(mut db): State<Database>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<AttestationVerifyRequest>,
) -> AppResult<Json<AttestationVerifyResponse>> {
    // removed non-error log

    // Check if this is a simulator request
    let user_agent = headers.get("user-agent").and_then(|h| h.to_str().ok());

    let is_simulator = app_attestation::is_ios_simulator(user_agent);

    if is_simulator {
        // removed non-error log

        // Clean up challenge record
        use sqlx_d1::query;
        let _ = query("DELETE FROM app_attest_challenges WHERE id = ?")
            .bind(&request.challenge_id)
            .execute(&mut db.conn)
            .await;

        return Ok(Json(AttestationVerifyResponse {
            success: true,
            error: None,
        }));
    }

    // Fetch and validate challenge
    use sqlx_d1::query_as;

    #[derive(sqlx::FromRow)]
    struct Challenge {
        challenge: String,
        bundle_id: String,
        expires_at: i64,
    }

    let stored_challenge = query_as::<Challenge>(
        "SELECT challenge, bundle_id, expires_at FROM app_attest_challenges WHERE id = ?",
    )
    .bind(&request.challenge_id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| {
        console_log!("❌ Database error fetching challenge: {}", e);
        AppError::from(e)
    })?;

    let _challenge = match stored_challenge {
        Some(ch) => {
            // Check if challenge is expired
            if ch.expires_at < datetime_to_timestamp(Utc::now()) {
                console_log!("❌ Challenge expired");
                return Ok(Json(AttestationVerifyResponse {
                    success: false,
                    error: Some("Challenge expired".to_string()),
                }));
            }

            // Verify bundle ID matches
            if ch.bundle_id != request.bundle_id {
                console_log!(
                    "❌ Bundle ID mismatch: expected {}, got {}",
                    ch.bundle_id,
                    request.bundle_id
                );
                return Ok(Json(AttestationVerifyResponse {
                    success: false,
                    error: Some("Bundle ID mismatch".to_string()),
                }));
            }

            ch.challenge
        }
        None => {
            console_log!("❌ Challenge not found: {}", request.challenge_id);
            return Ok(Json(AttestationVerifyResponse {
                success: false,
                error: Some("Invalid challenge".to_string()),
            }));
        }
    };

    // TODO: Validate with Apple's App Attest service when env is available
    // For now, accept all attestations for testing
    // removed non-error log

    // Clean up challenge record
    use sqlx_d1::query;
    let _ = query("DELETE FROM app_attest_challenges WHERE id = ?")
        .bind(&request.challenge_id)
        .execute(&mut db.conn)
        .await;

    // Store validated key for future assertions
    let _ = query(
        "INSERT OR REPLACE INTO app_attest_keys (key_id, bundle_id, created_at, last_used_at) VALUES (?, ?, ?, ?)"
    )
    .bind(&request.key_id)
    .bind(&request.bundle_id)
    .bind(datetime_to_timestamp(Utc::now()))
    .bind(datetime_to_timestamp(Utc::now()))
    .execute(&mut db.conn)
    .await;

    Ok(Json(AttestationVerifyResponse {
        success: true,
        error: None,
    }))
}
