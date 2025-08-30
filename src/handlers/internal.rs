use super::{ApiResult, ApiError};
use crate::auth::{session, tokens};
use crate::db::{Database, schema::{User, NewUser}};
use axum::{
    extract::{State, Path},
    http::HeaderMap,
    response::Json,
    Json as JsonExtractor,
};
use serde::{Deserialize, Serialize};
use chrono::Utc;
use uuid::Uuid;
use worker::Env;

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub auth_method: String,
    pub provider: String,
    pub provider_id: String,
    pub platform: String,
    pub user_agent: Option<String>,
    pub client_attestation: Option<String>, // For iOS App Attestation
}

#[derive(Debug, Deserialize)]
pub struct SessionRequest {
    pub user_id: String,
    pub platform: String,
}

#[derive(Debug, Deserialize)]
pub struct SessionValidationRequest {
    pub session_token: String,
}

#[derive(Debug, Serialize)]
pub struct InternalAuthResponse {
    pub success: bool,
    pub user: Option<UserResponse>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub error: Option<String>,
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

/// Middleware to validate internal service calls
pub async fn validate_internal_service(
    headers: &HeaderMap,
    env: &Env,
) -> Result<(), ApiError> {
    let internal_service = headers.get("x-internal-service")
        .and_then(|h| h.to_str().ok());
    
    let internal_key = headers.get("x-internal-key")
        .and_then(|h| h.to_str().ok());
    
    let expected_key = env.var("INTERNAL_API_KEY")
        .map_err(|_| ApiError::InternalServerError("Internal API key not configured".to_string()))?;
    
    if internal_service != Some("hamrah-app") {
        return Err(ApiError::Unauthorized);
    }
    
    if internal_key != Some(&expected_key.to_string()) {
        return Err(ApiError::Unauthorized);
    }
    
    Ok(())
}

/// Validate platform and client attestation
pub async fn validate_client_platform(
    platform: &str,
    user_agent: Option<&str>,
    client_attestation: Option<&str>,
) -> Result<(), ApiError> {
    match platform {
        "web" => {
            // Web platform is validated by the internal service call itself
            Ok(())
        },
        "ios" => {
            // Validate iOS user agent
            let ua = user_agent.unwrap_or("");
            if !ua.contains("CFNetwork") && !ua.contains("hamrahIOS") {
                return Err(ApiError::ValidationError("Invalid iOS client".to_string()));
            }
            
            // Require App Attestation for iOS
            if client_attestation.is_none() {
                return Err(ApiError::ValidationError("iOS App Attestation required".to_string()));
            }
            
            // TODO: Implement actual App Attestation verification
            // This would verify against Apple's App Attest service
            
            Ok(())
        },
        _ => Err(ApiError::ValidationError("Unsupported platform".to_string())),
    }
}

/// Internal endpoint to create users (only from hamrah-app)
pub async fn create_user_internal(
    State(db): State<Database>,
    State(env): State<Env>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<CreateUserRequest>,
) -> ApiResult<Json<InternalAuthResponse>> {
    // Validate internal service call
    validate_internal_service(&headers, &env).await?;
    
    // Validate platform and attestation
    validate_client_platform(
        &request.platform,
        request.user_agent.as_deref(),
        request.client_attestation.as_deref(),
    ).await?;
    
    let user_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    
    // Check if user already exists
    let existing_user_sql = "SELECT id FROM users WHERE email = ?";
    let existing = sqlx::query(existing_user_sql)
        .bind(&request.email)
        .fetch_optional(&db.pool)
        .await?;
    
    if existing.is_some() {
        return Err(ApiError::ValidationError("User already exists".to_string()));
    }
    
    // Create new user
    let create_sql = r#"
        INSERT INTO users (
            id, email, name, picture, email_verified, auth_method,
            provider, provider_id, last_login_platform, last_login_at,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    "#;
    
    sqlx::query(create_sql)
        .bind(&user_id)
        .bind(&request.email)
        .bind(&request.name)
        .bind(&request.picture)
        .bind(now) // email_verified
        .bind(&request.auth_method)
        .bind(&request.provider)
        .bind(&request.provider_id)
        .bind(&request.platform)
        .bind(now) // last_login_at
        .bind(now) // created_at
        .bind(now) // updated_at
        .execute(&db.pool)
        .await?;
    
    let user_response = UserResponse {
        id: user_id,
        email: request.email,
        name: request.name,
        picture: request.picture,
        auth_method: Some(request.auth_method),
        created_at: now.to_rfc3339(),
    };
    
    Ok(Json(InternalAuthResponse {
        success: true,
        user: Some(user_response),
        access_token: None,
        refresh_token: None,
        expires_in: None,
        error: None,
    }))
}

/// Internal endpoint to create web sessions
pub async fn create_session_internal(
    State(db): State<Database>,
    State(env): State<Env>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<SessionRequest>,
) -> ApiResult<Json<InternalAuthResponse>> {
    // Validate internal service call
    validate_internal_service(&headers, &env).await?;
    
    // Generate session token and create session
    let token = session::generate_session_token();
    let session = session::create_session(&db, &token, &request.user_id).await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
    
    // Get user details
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&request.user_id)
        .fetch_optional(&db.pool)
        .await?;
    
    if let Some(user) = user {
        let user_response = UserResponse {
            id: user.id,
            email: user.email,
            name: user.name,
            picture: user.picture,
            auth_method: user.auth_method,
            created_at: user.created_at.to_rfc3339(),
        };
        
        Ok(Json(InternalAuthResponse {
            success: true,
            user: Some(user_response),
            access_token: Some(token), // Return session token for cookie setting
            refresh_token: None,
            expires_in: Some((session.expires_at.timestamp() - Utc::now().timestamp()).max(0)),
            error: None,
        }))
    } else {
        Err(ApiError::NotFound)
    }
}

/// Internal endpoint to create API tokens
pub async fn create_tokens_internal(
    State(db): State<Database>,
    State(env): State<Env>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<CreateUserRequest>,
) -> ApiResult<Json<InternalAuthResponse>> {
    // Validate internal service call
    validate_internal_service(&headers, &env).await?;
    
    // Validate platform and attestation
    validate_client_platform(
        &request.platform,
        request.user_agent.as_deref(),
        request.client_attestation.as_deref(),
    ).await?;
    
    // Find or create user first
    let user_sql = "SELECT * FROM users WHERE email = ?";
    let user = sqlx::query_as::<_, User>(user_sql)
        .bind(&request.email)
        .fetch_optional(&db.pool)
        .await?;
    
    let user_id = if let Some(user) = user {
        user.id
    } else {
        // Create new user
        let new_user_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let create_sql = r#"
            INSERT INTO users (
                id, email, name, picture, email_verified, auth_method,
                provider, provider_id, last_login_platform, last_login_at,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#;
        
        sqlx::query(create_sql)
            .bind(&new_user_id)
            .bind(&request.email)
            .bind(&request.name)
            .bind(&request.picture)
            .bind(now)
            .bind(&request.auth_method)
            .bind(&request.provider)
            .bind(&request.provider_id)
            .bind(&request.platform)
            .bind(now)
            .bind(now)
            .bind(now)
            .execute(&db.pool)
            .await?;
        
        new_user_id
    };
    
    // Create token pair
    let token_pair = tokens::create_token_pair(
        &db,
        &user_id,
        &request.platform,
        request.user_agent.as_deref(),
        None, // IP address handled by web layer
    ).await.map_err(|e| ApiError::DatabaseError(e.to_string()))?;
    
    // Get updated user
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&db.pool)
        .await?;
    
    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        auth_method: user.auth_method,
        created_at: user.created_at.to_rfc3339(),
    };
    
    let expires_in = (token_pair.access_expires_at.timestamp() - Utc::now().timestamp()).max(0);
    
    Ok(Json(InternalAuthResponse {
        success: true,
        user: Some(user_response),
        access_token: Some(token_pair.access_token),
        refresh_token: Some(token_pair.refresh_token),
        expires_in: Some(expires_in),
        error: None,
    }))
}

/// Internal session validation
pub async fn validate_session_internal(
    State(db): State<Database>,
    State(env): State<Env>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<SessionValidationRequest>,
) -> ApiResult<Json<InternalAuthResponse>> {
    // Validate internal service call
    validate_internal_service(&headers, &env).await?;
    
    if let Some((session, user)) = session::validate_session_token(&db, &request.session_token).await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))? {
        
        let user_response = UserResponse {
            id: user.id,
            email: user.email,
            name: user.name,
            picture: user.picture,
            auth_method: user.auth_method,
            created_at: user.created_at.to_rfc3339(),
        };
        
        Ok(Json(InternalAuthResponse {
            success: true,
            user: Some(user_response),
            access_token: None,
            refresh_token: None,
            expires_in: None,
            error: None,
        }))
    } else {
        Err(ApiError::Unauthorized)
    }
}