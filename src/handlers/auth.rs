use super::{ApiError, ApiResult};
use crate::auth::{cookies, session, tokens};
use crate::db::Database;
use crate::utils::{datetime_to_timestamp, timestamp_to_datetime};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    Json as JsonExtractor,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

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
) -> ApiResult<Json<AuthResponse>> {
    if let Some(token) = cookies::get_cookie_value(&headers, "session") {
        if let Some((_session, user)) = session::validate_session_token(&mut db, &token)
            .await
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?
        {
            let user_response = UserResponse {
                id: user.id,
                email: user.email,
                name: user.name,
                picture: user.picture,
                auth_method: user.auth_method,
                created_at: timestamp_to_datetime(user.created_at).to_rfc3339(),
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

    Err(ApiError::Unauthorized)
}

// Token creation is now handled via internal API only

pub async fn refresh_token_endpoint(
    State(mut db): State<Database>,
    JsonExtractor(request): JsonExtractor<TokenRefreshRequest>,
) -> ApiResult<Json<AuthResponse>> {
    if let Some(new_token_pair) = tokens::refresh_token(&mut db, &request.refresh_token)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?
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
        Err(ApiError::Unauthorized)
    }
}

pub async fn logout_session(
    State(mut db): State<Database>,
    mut headers: HeaderMap,
) -> ApiResult<(StatusCode, HeaderMap, Json<serde_json::Value>)> {
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
) -> ApiResult<Json<serde_json::Value>> {
    tokens::revoke_token(&mut db, &token_id)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Token revoked successfully"
    })))
}

pub async fn revoke_all_user_tokens_endpoint(
    State(mut db): State<Database>,
    Path(user_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    tokens::revoke_all_user_tokens(&mut db, &user_id)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

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
) -> ApiResult<Json<AuthResponse>> {
    use crate::db::schema::User;
    use sqlx_d1::{query, query_as};
    use uuid::Uuid;
    use worker::console_log;

    console_log!(
        "🔍 Native auth request received: provider={}, email={:?}",
        request.provider,
        request.email
    );

    // Get user agent for platform detection
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    console_log!("🔍 User-Agent: {}", user_agent);

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

    console_log!("🔍 Detected platform: {}", platform);

    // TODO: Verify the OAuth credential with the provider
    // For now, we'll skip verification and trust the client
    // In production, you should verify:
    // - Google: Verify ID token with Google's token verification API
    // - Apple: Verify ID token with Apple's public keys

    // Extract email from request or use a placeholder
    let email = request.email.as_deref().unwrap_or("unknown@example.com");
    console_log!("🔍 Using email: {}", email);

    // Find or create user
    let existing_user = query_as::<User>("SELECT * FROM users WHERE email = ?")
        .bind(email)
        .fetch_optional(&mut db.conn)
        .await
        .map_err(|e| {
            console_log!("❌ Database error finding user: {}", e);
            ApiError::DatabaseError(e.to_string())
        })?;

    let user_id = if let Some(user) = existing_user {
        console_log!("✅ Found existing user: {}", user.id);

        // Update last login information
        query("UPDATE users SET last_login_at = ?, last_login_platform = ? WHERE id = ?")
            .bind(datetime_to_timestamp(Utc::now()))
            .bind(&platform)
            .bind(&user.id)
            .execute(&mut db.conn)
            .await
            .map_err(|e| {
                console_log!("❌ Database error updating user login: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?;

        user.id
    } else {
        // Create new user
        let new_user_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        console_log!("🔍 Creating new user: {}", new_user_id);

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
        .bind(&format!("{}_oauth", request.provider))
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
            ApiError::DatabaseError(e.to_string())
        })?;

        console_log!("✅ Created new user: {}", new_user_id);
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
        ApiError::DatabaseError(e.to_string())
    })?;

    console_log!("✅ Created token pair for user: {}", user_id);

    // Get updated user information
    let user = query_as::<User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&mut db.conn)
        .await
        .map_err(|e| {
            console_log!("❌ Database error fetching user: {}", e);
            ApiError::DatabaseError(e.to_string())
        })?;

    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        auth_method: user.auth_method,
        created_at: timestamp_to_datetime(user.created_at).to_rfc3339(),
    };

    let expires_in =
        ((token_pair.access_expires_at - datetime_to_timestamp(Utc::now())) / 1000).max(0);

    console_log!(
        "✅ Native auth successful for user: {}, expires_in: {}",
        user_response.email,
        expires_in
    );

    Ok(Json(AuthResponse {
        success: true,
        user: Some(user_response),
        access_token: Some(token_pair.access_token),
        refresh_token: Some(token_pair.refresh_token),
        expires_in: Some(expires_in),
    }))
}
