use super::{ApiResult, ApiError};
use crate::auth::{session, tokens};
use crate::db::{Database, schema::User};
use crate::handlers::auth::UserResponse;
use axum::{
    extract::{State, Path},
    http::HeaderMap,
    response::Json,
    Json as JsonExtractor,
};
use serde::{Deserialize, Serialize};
use chrono::Utc;

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

#[derive(Debug, Serialize)]
pub struct UserTokenInfo {
    pub id: String,
    pub platform: String,
    pub user_agent: Option<String>,
    pub last_used: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

// Middleware to extract user from session or token
pub async fn get_current_user_from_request(
    db: &Database,
    headers: &HeaderMap,
) -> ApiResult<User> {
    // First try session cookie
    if let Some(session_token) = crate::auth::cookies::get_cookie_value(headers, "session") {
        if let Some((_session, user)) = session::validate_session_token(db, &session_token).await
            .map_err(|e| ApiError::DatabaseError(e.to_string()))? {
            return Ok(user);
        }
    }
    
    // Then try Bearer token
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if let Some(auth_token) = tokens::validate_access_token(db, token).await
                    .map_err(|e| ApiError::DatabaseError(e.to_string()))? {
                    
                    // Get user from token
                    let user_sql = r#"
                        SELECT id, email, name, picture, email_verified, auth_method, 
                               provider, provider_id, last_login_platform, last_login_at, 
                               created_at, updated_at
                        FROM users WHERE id = ?
                    "#;
                    
                    let user_result = db.d1.prepare(user_sql)
                        .bind(&[auth_token.user_id.into()])?
                        .first::<serde_json::Value>(None)
                        .await?;
                    
                    if let Some(user_row) = user_result {
                        let user = User {
                            id: user_row["id"].as_str().unwrap_or("").to_string(),
                            email: user_row["email"].as_str().unwrap_or("").to_string(),
                            name: user_row["name"].as_str().map(|s| s.to_string()),
                            picture: user_row["picture"].as_str().map(|s| s.to_string()),
                            email_verified: user_row["email_verified"].as_i64()
                                .and_then(|ts| chrono::DateTime::from_timestamp_millis(ts)),
                            auth_method: user_row["auth_method"].as_str().map(|s| s.to_string()),
                            provider: user_row["provider"].as_str().map(|s| s.to_string()),
                            provider_id: user_row["provider_id"].as_str().map(|s| s.to_string()),
                            last_login_platform: user_row["last_login_platform"].as_str().map(|s| s.to_string()),
                            last_login_at: user_row["last_login_at"].as_i64()
                                .and_then(|ts| chrono::DateTime::from_timestamp_millis(ts)),
                            created_at: chrono::DateTime::from_timestamp_millis(
                                user_row["created_at"].as_i64().unwrap_or(0)
                            ).unwrap_or_else(|| Utc::now()),
                            updated_at: chrono::DateTime::from_timestamp_millis(
                                user_row["updated_at"].as_i64().unwrap_or(0)
                            ).unwrap_or_else(|| Utc::now()),
                        };
                        
                        return Ok(user);
                    }
                }
            }
        }
    }
    
    Err(ApiError::Unauthorized)
}

pub async fn get_current_user(
    State(db): State<Database>,
    headers: HeaderMap,
) -> ApiResult<Json<UserResponse>> {
    let user = get_current_user_from_request(&db, &headers).await?;
    
    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        auth_method: user.auth_method,
        created_at: user.created_at.to_rfc3339(),
    };
    
    Ok(Json(user_response))
}

pub async fn get_user_by_id(
    State(db): State<Database>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> ApiResult<Json<UserResponse>> {
    // Verify the requesting user has permission (for now, users can only get their own info)
    let current_user = get_current_user_from_request(&db, &headers).await?;
    
    if current_user.id != user_id {
        return Err(ApiError::Forbidden);
    }
    
    let user_response = UserResponse {
        id: current_user.id,
        email: current_user.email,
        name: current_user.name,
        picture: current_user.picture,
        auth_method: current_user.auth_method,
        created_at: current_user.created_at.to_rfc3339(),
    };
    
    Ok(Json(user_response))
}

pub async fn update_current_user(
    State(db): State<Database>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<UpdateUserRequest>,
) -> ApiResult<Json<UserResponse>> {
    let user = get_current_user_from_request(&db, &headers).await?;
    
    let now = Utc::now();
    let sql = r#"
        UPDATE users 
        SET name = COALESCE(?, name), 
            picture = COALESCE(?, picture), 
            updated_at = ?
        WHERE id = ?
        RETURNING id, email, name, picture, auth_method, created_at
    "#;
    
    let result = db.d1.prepare(sql)
        .bind(&[
            request.name.unwrap_or_default().into(),
            request.picture.unwrap_or_default().into(),
            now.timestamp_millis().into(),
            user.id.into(),
        ])?
        .first::<serde_json::Value>(None)
        .await?;
    
    if let Some(user_row) = result {
        let user_response = UserResponse {
            id: user_row["id"].as_str().unwrap_or("").to_string(),
            email: user_row["email"].as_str().unwrap_or("").to_string(),
            name: user_row["name"].as_str().map(|s| s.to_string()),
            picture: user_row["picture"].as_str().map(|s| s.to_string()),
            auth_method: user_row["auth_method"].as_str().map(|s| s.to_string()),
            created_at: user_row["created_at"].as_str().unwrap_or("").to_string(),
        };
        
        Ok(Json(user_response))
    } else {
        Err(ApiError::NotFound)
    }
}

pub async fn get_user_tokens(
    State(db): State<Database>,
    headers: HeaderMap,
) -> ApiResult<Json<UserTokensResponse>> {
    let user = get_current_user_from_request(&db, &headers).await?;
    
    let sql = r#"
        SELECT id, platform, user_agent, last_used, created_at, access_expires_at
        FROM auth_tokens 
        WHERE user_id = ? AND revoked = 0 AND access_expires_at > ?
        ORDER BY last_used DESC, created_at DESC
    "#;
    
    let now = Utc::now().timestamp_millis();
    let results = db.d1.prepare(sql)
        .bind(&[user.id.into(), now.into()])?
        .all()
        .await?;
    
    let mut tokens = Vec::new();
    if let Ok(rows) = results.results::<serde_json::Value>() {
        for row in rows {
            let token_info = UserTokenInfo {
                id: row["id"].as_str().unwrap_or("").to_string(),
                platform: row["platform"].as_str().unwrap_or("").to_string(),
                user_agent: row["user_agent"].as_str().map(|s| s.to_string()),
                last_used: row["last_used"].as_i64()
                    .and_then(|ts| chrono::DateTime::from_timestamp_millis(ts))
                    .map(|dt| dt.to_rfc3339()),
                created_at: chrono::DateTime::from_timestamp_millis(
                    row["created_at"].as_i64().unwrap_or(0)
                ).unwrap_or_else(|| Utc::now()).to_rfc3339(),
                expires_at: chrono::DateTime::from_timestamp_millis(
                    row["access_expires_at"].as_i64().unwrap_or(0)
                ).unwrap_or_else(|| Utc::now()).to_rfc3339(),
            };
            tokens.push(token_info);
        }
    }
    
    Ok(Json(UserTokensResponse {
        success: true,
        tokens,
    }))
}

pub async fn delete_user_account(
    State(db): State<Database>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&db, &headers).await?;
    
    // Delete user (cascading deletes will handle sessions, tokens, etc.)
    let sql = "DELETE FROM users WHERE id = ?";
    db.d1.prepare(sql)
        .bind(&[user.id.into()])?
        .run()
        .await?;
    
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "User account deleted successfully"
    })))
}