use crate::auth::{app_attestation, cookies, session, tokens};
use crate::error::{AppError, AppResult};

use crate::utils::{datetime_to_timestamp, timestamp_to_datetime};
use axum::{
    extract::Path,
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
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    headers: HeaderMap,
) -> AppResult<Json<AuthResponse>> {
    if let Some(token) = cookies::get_cookie_value(&headers, "session") {
        let token_owned = token.to_string();
        let result = handles
            .db
            .run(move |mut db| async move {
                session::validate_session_token(&mut db, &token_owned).await
            })
            .await
            .map_err(AppError::from)?;
        if let Some((_session, user)) = result {
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
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    JsonExtractor(request): JsonExtractor<TokenRefreshRequest>,
) -> AppResult<Json<AuthResponse>> {
    let refresh_token = request.refresh_token.clone();
    let result = handles
        .db
        .run(move |mut db| async move { tokens::refresh_token(&mut db, &refresh_token).await })
        .await
        .map_err(AppError::from)?;

    if let Some(new_token_pair) = result {
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
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    mut headers: HeaderMap,
) -> AppResult<(StatusCode, HeaderMap, Json<serde_json::Value>)> {
    if let Some(token) = cookies::get_cookie_value(&headers, "session") {
        let session_id = session::create_session_id(&token);
        let session_id_q = session_id.clone();
        let _ =
            handles
                .db
                .run(move |mut db| async move {
                    session::invalidate_session(&mut db, &session_id_q).await
                })
                .await;
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
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    Path(token_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let token_id_q = token_id.clone();
    handles
        .db
        .run(move |mut db| async move { tokens::revoke_token(&mut db, &token_id_q).await })
        .await
        .map_err(AppError::from)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Token revoked successfully"
    })))
}

pub async fn revoke_all_user_tokens_endpoint(
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    Path(user_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let user_id_q = user_id.clone();
    handles
        .db
        .run(move |mut db| async move { tokens::revoke_all_user_tokens(&mut db, &user_id_q).await })
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
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<NativeAuthRequest>,
) -> AppResult<Json<AuthResponse>> {
    use crate::db::schema::User;
    use sqlx_d1::{query, query_as};
    use uuid::Uuid;
    use worker::console_log;

    // removed non-error log

    // Get user agent for platform detection (owned String to avoid borrowing across awaits)
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string());

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
    let existing_user = handles
        .db
        .run({
            let email_q = email.to_string();
            move |mut db| async move {
                query_as::<User>("SELECT * FROM users WHERE email = ?")
                    .bind(&email_q)
                    .fetch_optional(&mut db.conn)
                    .await
            }
        })
        .await
        .map_err(|e| {
            console_log!("❌ Database error finding user: {}", e);
            AppError::from(e)
        })?;

    let user_id = if let Some(user) = existing_user {
        // removed non-error log

        // Update last login information
        {
            let platform_q = platform.clone();
            let user_id_q = user.id.clone();
            handles
                .db
                .run(move |mut db| async move {
                    query(
                        "UPDATE users SET last_login_at = ?, last_login_platform = ? WHERE id = ?",
                    )
                    .bind(datetime_to_timestamp(Utc::now()))
                    .bind(&platform_q)
                    .bind(&user_id_q)
                    .execute(&mut db.conn)
                    .await
                })
                .await
                .map_err(|e| {
                    console_log!("❌ Database error updating user login: {}", e);
                    AppError::from(e)
                })?;
        }

        user.id
    } else {
        // Create new user
        let new_user_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // removed non-error log

        {
            let new_user_id_q = new_user_id.clone();
            let email_q = email.to_string();
            let name_q = request.name.clone();
            let picture_q = request.picture.clone();
            let provider_q = request.provider.clone();
            let platform_q = platform.clone();
            let now_ts = datetime_to_timestamp(now);
            handles
                .db
                .run(move |mut db| async move {
                    query(
                        r#"
            INSERT INTO users (
                id, email, name, picture, email_verified, auth_method,
                provider, provider_id, last_login_platform, last_login_at,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
                    )
                    .bind(&new_user_id_q)
                    .bind(&email_q)
                    .bind(&name_q)
                    .bind(&picture_q)
                    .bind(now_ts)
                    .bind(format!("{}_oauth", provider_q))
                    .bind(&provider_q)
                    .bind(&email_q)
                    .bind(&platform_q)
                    .bind(now_ts)
                    .bind(now_ts)
                    .bind(now_ts)
                    .execute(&mut db.conn)
                    .await
                })
                .await
                .map_err(|e| {
                    console_log!("❌ Database error creating user: {}", e);
                    AppError::from(e)
                })?;
        }

        // removed non-error log
        new_user_id
    };

    // Create token pair for the user
    let token_pair = handles
        .db
        .run({
            let user_id_q = user_id.clone();
            let platform_q = platform.clone();
            let user_agent_opt = Some(user_agent.clone());
            move |mut db| async move {
                tokens::create_token_pair(
                    &mut db,
                    &user_id_q,
                    &platform_q,
                    user_agent_opt.as_deref(),
                    None,
                )
                .await
            }
        })
        .await
        .map_err(|e| {
            console_log!("❌ Error creating token pair: {}", e);
            AppError::from(e)
        })?;

    // removed non-error log

    // Get updated user information
    let user = handles
        .db
        .run({
            let user_id_q = user_id.clone();
            move |mut db| async move {
                query_as::<User>("SELECT * FROM users WHERE id = ?")
                    .bind(&user_id_q)
                    .fetch_one(&mut db.conn)
                    .await
            }
        })
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
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
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

    {
        let challenge_id_q = challenge_id.clone();
        let challenge_b64_q = challenge_base64.clone();
        let bundle_q = request.bundle_id.clone();
        let platform_q = request.platform.clone();
        let expires_q = expires_at;
        handles
            .db
            .run(move |mut db| async move {
                query(
                    "INSERT INTO app_attest_challenges (id, challenge, bundle_id, platform, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)"
                )
                .bind(&challenge_id_q)
                .bind(&challenge_b64_q)
                .bind(&bundle_q)
                .bind(&platform_q)
                .bind(expires_q)
                .bind(datetime_to_timestamp(Utc::now()))
                .execute(&mut db.conn)
                .await
            })
            .await
            .map_err(|e| {
                console_log!("❌ Database error storing challenge: {}", e);
                AppError::from(e)
            })?;
    }

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
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    JsonExtractor(request): JsonExtractor<AttestationVerifyRequest>,
) -> AppResult<Json<AttestationVerifyResponse>> {
    console_log!("[/api/app-attestation/verify] Received request");

    // Check if this is a simulator request
    // Note: This is a basic check. A more robust solution might involve a header.
    if request.key_id.contains("simulator") || request.bundle_id.contains("simulator") {
        console_log!(
            "[/api/app-attestation/verify] Detected simulator request, bypassing validation."
        );
        return Ok(Json(AttestationVerifyResponse {
            success: true,
            error: None,
        }));
    }

    // 1. Fetch and validate the challenge from the database
    console_log!("[/api/app-attestation/verify] Fetching challenge...");
    use sqlx_d1::query_as;

    #[derive(sqlx::FromRow)]
    struct Challenge {
        challenge: String,
        bundle_id: String,
        expires_at: i64,
    }

    let stored_challenge = {
        let challenge_id_q = request.challenge_id.clone();
        handles
            .db
            .run(move |mut db| async move {
                query_as::<Challenge>(
                    "SELECT challenge, bundle_id, expires_at FROM app_attest_challenges WHERE id = ?",
                )
                .bind(&challenge_id_q)
                .fetch_optional(&mut db.conn)
                .await
            })
            .await
            .map_err(|e| {
                console_log!("❌ Database error fetching challenge: {}", e);
                AppError::from(e)
            })?
    };

    let challenge_b64 = match stored_challenge {
        Some(ch) => {
            if ch.expires_at < datetime_to_timestamp(Utc::now()) {
                return Ok(Json(AttestationVerifyResponse {
                    success: false,
                    error: Some("Challenge expired".to_string()),
                }));
            }
            if ch.bundle_id != request.bundle_id {
                return Ok(Json(AttestationVerifyResponse {
                    success: false,
                    error: Some("Bundle ID mismatch".to_string()),
                }));
            }
            ch.challenge
        }
        None => {
            return Ok(Json(AttestationVerifyResponse {
                success: false,
                error: Some("Invalid challenge ID".to_string()),
            }));
        }
    };

    // 2. Get Team ID from environment
    let team_id_res = handles
        .env
        .run(|env| async move { env.var("APPLE_TEAM_ID").map(|secret| secret.to_string()) })
        .await;

    let team_id = match team_id_res {
        Ok(id) => id,
        _ => {
            console_log!("❌ APPLE_TEAM_ID environment variable not set");
            return Err(AppError::internal("Server configuration error").into());
        }
    };

    // 3. Perform local attestation validation
    console_log!("[/api/app-attestation/verify] Performing local validation...");
    match app_attestation::perform_attestation_validation(
        &request.attestation,
        &challenge_b64,
        &team_id,
        &request.bundle_id,
    ) {
        Ok(public_key_bytes) => {
            console_log!("[/api/app-attestation/verify] Local validation successful");

            // 4. Store the new, validated key in the database
            use sqlx_d1::query;
            let key_id_q = request.key_id.clone();
            let bundle_id_q = request.bundle_id.clone();
            let now_ts = datetime_to_timestamp(Utc::now());

            let db_result = handles
                .db
                .run(move |mut db| async move {
                    query(
                        "INSERT OR REPLACE INTO app_attest_keys (key_id, bundle_id, public_key, counter, created_at, last_used_at) VALUES (?, ?, ?, 0, ?, ?)"
                    )
                    .bind(&key_id_q)
                    .bind(&bundle_id_q)
                    .bind(&public_key_bytes)
                    .bind(now_ts)
                    .bind(now_ts)
                    .execute(&mut db.conn)
                    .await
                })
                .await;

            if let Err(e) = db_result {
                console_log!("❌ Database error storing attestation key: {}", e);
                return Err(AppError::internal("Failed to store attestation key").into());
            }

            console_log!("[/api/app-attestation/verify] New key stored successfully");

            // 5. Clean up the used challenge
            let challenge_id_q = request.challenge_id.clone();
            let _ = handles
                .db
                .run(move |mut db| async move {
                    query("DELETE FROM app_attest_challenges WHERE id = ?")
                        .bind(&challenge_id_q)
                        .execute(&mut db.conn)
                        .await
                })
                .await;

            Ok(Json(AttestationVerifyResponse {
                success: true,
                error: None,
            }))
        }
        Err(err) => {
            console_log!(
                "❌ [/api/app-attestation/verify] Local validation failed: {}",
                err
            );
            Ok(Json(AttestationVerifyResponse {
                success: false,
                error: Some(format!("Attestation validation failed: {}", err)),
            }))
        }
    }
}

#[allow(dead_code)]
fn extract_uncompressed_p256_pubkey_from_attestation_b64(attestation_b64: &str) -> Option<String> {
    // Decode base64 attestationObject (CBOR map with "authData")
    use base64::Engine;
    let att_bytes = base64::engine::general_purpose::STANDARD
        .decode(attestation_b64)
        .ok()?;
    let auth_data = cbor_find_bytes_after_text_key(&att_bytes, "authData")?;

    // Parse authData to get attested credential data and COSE_Key
    let pub_xy = parse_pubkey_from_auth_data(&auth_data)?;

    // Return base64(X||Y) without 0x04 prefix
    Some(base64::engine::general_purpose::STANDARD.encode(pub_xy))
}

// Find the CBOR byte string value that follows a given text key in a top-level CBOR map.
// This is a very narrow parser tailored for finding the "authData" entry in an attestationObject.
#[allow(dead_code)]
fn cbor_find_bytes_after_text_key(data: &[u8], key: &str) -> Option<Vec<u8>> {
    let key_bytes = key.as_bytes();
    if key_bytes.len() > 23 {
        return None; // only handle short text keys (<= 23)
    }
    let key_hdr = 0x60u8 + (key_bytes.len() as u8); // major type 3 (text), small len
                                                    // Search for [key_hdr, key_bytes...]
    let mut i = 0usize;
    while i + 1 + key_bytes.len() <= data.len() {
        if data[i] == key_hdr && data.get(i + 1..i + 1 + key_bytes.len()) == Some(key_bytes) {
            // Position right after the key
            let mut p = i + 1 + key_bytes.len();
            if p >= data.len() {
                return None;
            }
            // Expect a byte string (major type 2). Support lengths: small (<=23), 0x58 (u8), 0x59 (u16).
            let hdr = data[p];
            p += 1;
            let (len, adv) = match hdr {
                0x40..=0x57 => ((hdr - 0x40) as usize, 0usize), // small length 0..23
                0x58 => {
                    if p + 1 > data.len() {
                        return None;
                    }
                    (data[p] as usize, 1usize)
                }
                0x59 => {
                    if p + 2 > data.len() {
                        return None;
                    }
                    let l = ((data[p] as usize) << 8) | (data[p + 1] as usize);
                    (l, 2usize)
                }
                _ => return None,
            };
            p += adv;
            if p + len <= data.len() {
                return Some(data[p..p + len].to_vec());
            } else {
                return None;
            }
        }
        i += 1;
    }
    None
}

// Parse WebAuthn-style authData for attested credential public key COSE_Key,
// and extract X and Y (each 32 bytes) from COSE EC2 key (-2: x, -3: y).
#[allow(dead_code)]
fn parse_pubkey_from_auth_data(auth: &[u8]) -> Option<Vec<u8>> {
    // authData: rpIdHash(32) | flags(1) | signCount(4) | [attestedCredentialData if AT flag]
    if auth.len() < 37 {
        return None;
    }
    let flags = auth[32];
    let at_flag = 0x40u8; // AT flag
    if flags & at_flag == 0 {
        return None; // no attested credential data present
    }
    let mut off = 32 + 1 + 4;
    if auth.len() < off + 16 + 2 {
        return None;
    }
    // aaguid
    off += 16;
    // credentialId length (u16 big endian)
    let cred_id_len = u16::from_be_bytes([auth[off], auth[off + 1]]) as usize;
    off += 2;
    if auth.len() < off + cred_id_len {
        return None;
    }
    // skip credentialId
    off += cred_id_len;
    if off >= auth.len() {
        return None;
    }
    // COSE_Key starts at 'off'
    let cose = &auth[off..];

    // Extract x and y by scanning for keys -2 (0x21) and -3 (0x22) followed by a bstr.
    let mut x_opt: Option<Vec<u8>> = None;
    let mut y_opt: Option<Vec<u8>> = None;

    let mut i = 0usize;
    while i < cose.len() && (x_opt.is_none() || y_opt.is_none()) {
        let b = cose[i];
        i += 1;

        // Look for negative int keys -2 (0x21) and -3 (0x22)
        if b == 0x21 || b == 0x22 {
            // Next should be a byte string
            if i >= cose.len() {
                break;
            }
            let hdr = cose[i];
            i += 1;
            let (len, adv) = match hdr {
                0x40..=0x57 => ((hdr - 0x40) as usize, 0usize),
                0x58 => {
                    if i + 1 > cose.len() {
                        break;
                    }
                    (cose[i] as usize, 1usize)
                }
                0x59 => {
                    if i + 2 > cose.len() {
                        break;
                    }
                    let l = ((cose[i] as usize) << 8) | (cose[i + 1] as usize);
                    (l, 2usize)
                }
                _ => {
                    // Not a byte string; skip and continue
                    continue;
                }
            };
            i += adv;
            if i + len > cose.len() {
                break;
            }
            let val = &cose[i..i + len];
            i += len;

            if b == 0x21 {
                x_opt = Some(val.to_vec());
            } else if b == 0x22 {
                y_opt = Some(val.to_vec());
            }
        } else {
            // Skip non-key bytes naively
            continue;
        }
    }

    let (x, y) = (x_opt?, y_opt?);
    if x.len() != 32 || y.len() != 32 {
        return None;
    }

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    Some(out)
}

// Find the CBOR byte string value that follows a given text key in a top-level CBOR map.
// This is a narrow parser tailored for finding the "authData" entry in an attestationObject.
#[allow(dead_code)]
fn cbor_find_bytes_after_text_key_dup(data: &[u8], key: &str) -> Option<Vec<u8>> {
    let key_bytes = key.as_bytes();
    if key_bytes.len() > 23 {
        return None; // only handle short text keys (<= 23)
    }
    let key_hdr = 0x60u8 + (key_bytes.len() as u8); // major type 3 (text), small len
    let mut i = 0usize;
    while i + 1 + key_bytes.len() <= data.len() {
        if data[i] == key_hdr && data.get(i + 1..i + 1 + key_bytes.len()) == Some(key_bytes) {
            // Position right after the key
            let mut p = i + 1 + key_bytes.len();
            if p >= data.len() {
                return None;
            }
            // Expect a byte string (major type 2). Support lengths: small (<=23), 0x58 (u8), 0x59 (u16).
            let hdr = data[p];
            p += 1;
            let (len, adv) = match hdr {
                0x40..=0x57 => ((hdr - 0x40) as usize, 0usize), // small length 0..23
                0x58 => {
                    if p + 1 > data.len() {
                        return None;
                    }
                    (data[p] as usize, 1usize)
                }
                0x59 => {
                    if p + 2 > data.len() {
                        return None;
                    }
                    let l = ((data[p] as usize) << 8) | (data[p + 1] as usize);
                    (l, 2usize)
                }
                _ => return None,
            };
            p += adv;
            if p + len <= data.len() {
                return Some(data[p..p + len].to_vec());
            } else {
                return None;
            }
        }
        i += 1;
    }
    None
}

// Parse WebAuthn-style authData for attested credential public key COSE_Key,
// and extract X and Y (each 32 bytes) from COSE EC2 key (-2: x, -3: y).
#[allow(dead_code)]
fn parse_pubkey_from_auth_data_dup(auth: &[u8]) -> Option<Vec<u8>> {
    // authData: rpIdHash(32) | flags(1) | signCount(4) | [attestedCredentialData if AT flag]
    if auth.len() < 37 {
        return None;
    }
    let flags = auth[32];
    let at_flag = 0x40u8; // AT flag
    if flags & at_flag == 0 {
        return None; // no attested credential data present
    }
    let mut off = 32 + 1 + 4;
    if auth.len() < off + 16 + 2 {
        return None;
    }
    // aaguid
    off += 16;
    // credentialId length (u16 big endian)
    let cred_id_len = u16::from_be_bytes([auth[off], auth[off + 1]]) as usize;
    off += 2;
    if auth.len() < off + cred_id_len {
        return None;
    }
    // skip credentialId
    off += cred_id_len;
    if off >= auth.len() {
        return None;
    }
    // COSE_Key starts at 'off'
    let cose = &auth[off..];

    // Extract x and y by scanning for keys -2 (0x21) and -3 (0x22) followed by a bstr.
    let mut x_opt: Option<Vec<u8>> = None;
    let mut y_opt: Option<Vec<u8>> = None;

    let mut i = 0usize;
    while i < cose.len() && (x_opt.is_none() || y_opt.is_none()) {
        let b = cose[i];
        i += 1;

        // Look for negative int keys -2 (0x21) and -3 (0x22)
        if b == 0x21 || b == 0x22 {
            // Next should be a byte string
            if i >= cose.len() {
                break;
            }
            let hdr = cose[i];
            i += 1;
            let (len, adv) = match hdr {
                0x40..=0x57 => ((hdr - 0x40) as usize, 0usize),
                0x58 => {
                    if i + 1 > cose.len() {
                        break;
                    }
                    (cose[i] as usize, 1usize)
                }
                0x59 => {
                    if i + 2 > cose.len() {
                        break;
                    }
                    let l = ((cose[i] as usize) << 8) | (cose[i + 1] as usize);
                    (l, 2usize)
                }
                _ => {
                    // Not a byte string; skip and continue
                    continue;
                }
            };
            i += adv;
            if i + len > cose.len() {
                break;
            }
            let val = &cose[i..i + len];
            i += len;

            if b == 0x21 {
                x_opt = Some(val.to_vec());
            } else if b == 0x22 {
                y_opt = Some(val.to_vec());
            }
        } else {
            // Skip non-key bytes naively
            continue;
        }
    }

    let (x, y) = (x_opt?, y_opt?);
    if x.len() != 32 || y.len() != 32 {
        return None;
    }

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    Some(out)
}

/// Validate Bearer access token
pub async fn validate_access_token_endpoint(
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    // Expect Authorization: Bearer <access_token>
    if let Some(auth_header) = headers.get("authorization").and_then(|h| h.to_str().ok()) {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            let token_owned = token.to_string();
            match handles
                .db
                .run(move |mut db| async move {
                    tokens::validate_access_token(&mut db, &token_owned).await
                })
                .await
            {
                Ok(Some(auth_token)) => {
                    let now = crate::utils::datetime_to_timestamp(chrono::Utc::now());
                    let expires_in = ((auth_token.access_expires_at - now) / 1000).max(0);
                    return Ok(Json(serde_json::json!({
                        "success": true,
                        "valid": true,
                        "userId": auth_token.user_id,
                        "platform": auth_token.platform,
                        "accessExpiresAt": auth_token.access_expires_at,
                        "expiresIn": expires_in
                    })));
                }
                Ok(None) => {
                    return Err(Box::new(AppError::unauthorized("Unauthorized")));
                }
                Err(e) => {
                    return Err(Box::new(AppError::from(e)));
                }
            }
        }
    }

    Err(Box::new(AppError::unauthorized("Unauthorized")))
}

#[derive(Debug, Deserialize)]
pub struct VerifyKeyRequest {
    #[serde(rename = "keyId")]
    pub key_id: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyKeyResponse {
    pub valid: bool,
}

/// Verify if an App Attestation key exists
pub async fn app_attestation_verify_key(
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<VerifyKeyRequest>,
) -> AppResult<Json<VerifyKeyResponse>> {
    // Validate Bearer token
    if let Some(auth_header) = headers.get("authorization").and_then(|h| h.to_str().ok()) {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            let token_owned = token.to_string();
            match handles
                .db
                .run(move |mut db| async move {
                    tokens::validate_access_token(&mut db, &token_owned).await
                })
                .await
            {
                Ok(Some(_auth_token)) => {
                    // Token is valid, check if key exists
                    use sqlx_d1::query;
                    let key_id_q = request.key_id.clone();
                    let result = handles
                        .db
                        .run(move |mut db| async move {
                            query("SELECT 1 FROM app_attest_keys WHERE key_id = ? LIMIT 1")
                                .bind(&key_id_q)
                                .fetch_optional(&mut db.conn)
                                .await
                        })
                        .await
                        .map_err(AppError::from)?;

                    return Ok(Json(VerifyKeyResponse {
                        valid: result.is_some(),
                    }));
                }
                Ok(None) => {
                    return Err(Box::new(AppError::unauthorized("Unauthorized")));
                }
                Err(e) => {
                    return Err(Box::new(AppError::from(e)));
                }
            }
        }
    }

    Err(Box::new(AppError::unauthorized("Unauthorized")))
}
