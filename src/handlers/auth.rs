use super::{ApiResult, ApiError};
use crate::auth::{session, tokens, cookies, PLATFORM_API, PLATFORM_WEB};
use crate::db::{Database, schema::{User, NewUser}};
use axum::{
    extract::{State, Path},
    http::{HeaderMap, StatusCode},
    response::Json,
    Json as JsonExtractor,
};
use serde::{Deserialize, Serialize};
use chrono::Utc;
use uuid::Uuid;

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

// SessionRequest moved to internal.rs

// User creation is now handled via internal API only

// Session creation is now handled via internal API only

pub async fn validate_session(
    State(db): State<Database>,
    headers: HeaderMap,
) -> ApiResult<Json<AuthResponse>> {
    if let Some(token) = cookies::get_cookie_value(&headers, "session") {
        if let Some((session, user)) = session::validate_session_token(&db, &token).await
            .map_err(|e| ApiError::DatabaseError(e.to_string()))? {
            
            let user_response = UserResponse {
                id: user.id,
                email: user.email,
                name: user.name,
                picture: user.picture,
                auth_method: user.auth_method,
                created_at: user.created_at.to_rfc3339(),
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
    State(db): State<Database>,
    JsonExtractor(request): JsonExtractor<TokenRefreshRequest>,
) -> ApiResult<Json<AuthResponse>> {
    if let Some(new_token_pair) = tokens::refresh_token(&db, &request.refresh_token).await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))? {
        
        let expires_in = (new_token_pair.access_expires_at.timestamp() - Utc::now().timestamp()).max(0);
        
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
    State(db): State<Database>,
    mut headers: HeaderMap,
) -> ApiResult<(StatusCode, HeaderMap, Json<serde_json::Value>)> {
    if let Some(token) = cookies::get_cookie_value(&headers, "session") {
        let session_id = session::create_session_id(&token);
        let _ = session::invalidate_session(&db, &session_id).await;
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
    State(db): State<Database>,
    Path(token_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    tokens::revoke_token(&db, &token_id).await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
    
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Token revoked successfully"
    })))
}

pub async fn revoke_all_user_tokens_endpoint(
    State(db): State<Database>,
    Path(user_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    tokens::revoke_all_user_tokens(&db, &user_id).await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
    
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "All user tokens revoked successfully"
    })))
}