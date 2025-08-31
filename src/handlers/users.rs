use super::{ApiError, ApiResult};
use crate::auth::{session, tokens};
use crate::db::{schema::User, Database};
use crate::handlers::auth::UserResponse;
use crate::utils::{datetime_to_timestamp, timestamp_to_datetime};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Json,
    Json as JsonExtractor,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx_d1::{query, query_as};

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub picture: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserTokensResponse {
    pub success: bool,
    pub tokens: Vec<UserTokenInfo>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UserTokenInfo {
    pub id: String,
    pub platform: String,
    pub user_agent: Option<String>,
    pub last_used: Option<i64>,
    pub created_at: i64,
    pub access_expires_at: i64,
}

// Middleware to extract user from session or token
pub async fn get_current_user_from_request(
    db: &mut Database,
    headers: &HeaderMap,
) -> ApiResult<User> {
    // First try session cookie
    if let Some(session_token) = crate::auth::cookies::get_cookie_value(headers, "session") {
        if let Some((_session, user)) = session::validate_session_token(db, &session_token)
            .await
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?
        {
            return Ok(user);
        }
    }

    // Then try Bearer token
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if let Some(auth_token) = tokens::validate_access_token(db, token)
                    .await
                    .map_err(|e| ApiError::DatabaseError(e.to_string()))?
                {
                    // Get user from token
                    let user =
                        query_as!(User, "SELECT * FROM users WHERE id = ?", auth_token.user_id)
                            .fetch_one(&mut db.conn)
                            .await?;

                    return Ok(user);
                }
            }
        }
    }

    Err(ApiError::Unauthorized)
}

pub async fn get_current_user(
    State(mut db): State<Database>,
    headers: HeaderMap,
) -> ApiResult<Json<UserResponse>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        auth_method: user.auth_method,
        created_at: timestamp_to_datetime(user.created_at).to_rfc3339(),
    };

    Ok(Json(user_response))
}

pub async fn get_user_by_id(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> ApiResult<Json<UserResponse>> {
    // Verify the requesting user has permission (for now, users can only get their own info)
    let current_user = get_current_user_from_request(&mut db, &headers).await?;

    if current_user.id != user_id {
        return Err(ApiError::Forbidden);
    }

    let user_response = UserResponse {
        id: current_user.id,
        email: current_user.email,
        name: current_user.name,
        picture: current_user.picture,
        auth_method: current_user.auth_method,
        created_at: timestamp_to_datetime(current_user.created_at).to_rfc3339(),
    };

    Ok(Json(user_response))
}

pub async fn update_current_user(
    State(mut db): State<Database>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<UpdateUserRequest>,
) -> ApiResult<Json<UserResponse>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    let now = datetime_to_timestamp(Utc::now());

    // Update user fields
    query!(
        r#"
        UPDATE users
        SET name = CASE WHEN ? IS NOT NULL THEN ? ELSE name END,
            picture = CASE WHEN ? IS NOT NULL THEN ? ELSE picture END,
            updated_at = ?
        WHERE id = ?
    "#,
        request.name,
        request.name,
        request.picture,
        request.picture,
        now,
        user.id
    )
    .execute(&mut db.conn)
    .await?;

    // Fetch updated user
    let updated_user = query_as!(User, "SELECT * FROM users WHERE id = ?", user.id)
        .fetch_one(&mut db.conn)
        .await?;

    let user_response = UserResponse {
        id: updated_user.id,
        email: updated_user.email,
        name: updated_user.name,
        picture: updated_user.picture,
        auth_method: updated_user.auth_method,
        created_at: timestamp_to_datetime(updated_user.created_at).to_rfc3339(),
    };

    Ok(Json(user_response))
}

pub async fn get_user_tokens(
    State(mut db): State<Database>,
    headers: HeaderMap,
) -> ApiResult<Json<UserTokensResponse>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    let now = datetime_to_timestamp(Utc::now());
    let results = query_as!(
        UserTokenInfo,
        r#"
        SELECT id, platform, user_agent, last_used, created_at, access_expires_at
        FROM auth_tokens
        WHERE user_id = ? AND revoked = 0 AND access_expires_at > ?
        ORDER BY last_used DESC, created_at DESC
    "#,
        user.id,
        now
    )
    .fetch_all(&mut db.conn)
    .await?;

    Ok(Json(UserTokensResponse {
        success: true,
        tokens: results,
    }))
}

pub async fn delete_user_account(
    State(mut db): State<Database>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Delete user (cascading deletes will handle sessions, tokens, etc.)
    query!("DELETE FROM users WHERE id = ?", user.id)
        .execute(&mut db.conn)
        .await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "User account deleted successfully"
    })))
}
