use super::{ApiError, ApiResult};
use crate::auth::{session, tokens};
use crate::db::{schema::User, Database};
use crate::utils::{datetime_to_timestamp, timestamp_to_datetime};
use axum::{extract::State, http::HeaderMap, response::Json, Json as JsonExtractor};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx_d1::{query, query_as};
use uuid::Uuid;
use worker::{console_log, Env};

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

/// Middleware to validate internal service calls via service bindings
/// Service bindings provide automatic authentication - we just log the call
pub async fn validate_internal_service(headers: &HeaderMap, _env: &Env) -> Result<(), ApiError> {
    let service_name = headers
        .get("x-service-name")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("no-id");

    // Log the service binding call for debugging and tracing
    console_log!(
        "Service binding call from: {} (Request ID: {})",
        service_name,
        request_id
    );

    // Service bindings automatically authenticate - no manual validation needed
    // The call can only reach us if it's via a valid service binding
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
        }
        "ios" => {
            // Validate iOS user agent
            let ua = user_agent.unwrap_or("");
            if !ua.contains("CFNetwork") && !ua.contains("hamrahIOS") {
                return Err(ApiError::ValidationError("Invalid iOS client".to_string()));
            }

            // Require App Attestation for iOS
            if client_attestation.is_none() {
                return Err(ApiError::ValidationError(
                    "iOS App Attestation required".to_string(),
                ));
            }

            // TODO: Implement actual App Attestation verification
            // This would verify against Apple's App Attest service

            Ok(())
        }
        _ => Err(ApiError::ValidationError(
            "Unsupported platform".to_string(),
        )),
    }
}

/// Internal endpoint to create users (only from hamrah-app)
pub async fn create_user_internal(
    State(mut db): State<Database>,
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
    )
    .await?;

    let user_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Check if user already exists
    let existing = query!("SELECT id FROM users WHERE email = ?", request.email)
        .fetch_optional(&mut db.conn)
        .await?;

    if existing.is_some() {
        return Err(ApiError::ValidationError("User already exists".to_string()));
    }

    // Create new user
    query!(
        r#"
        INSERT INTO users (
            id, email, name, picture, email_verified, auth_method,
            provider, provider_id, last_login_platform, last_login_at,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    "#,
        user_id,
        request.email,
        request.name,
        request.picture,
        datetime_to_timestamp(now), // email_verified
        request.auth_method,
        request.provider,
        request.provider_id,
        request.platform,
        datetime_to_timestamp(now), // last_login_at
        datetime_to_timestamp(now), // created_at
        datetime_to_timestamp(now), // updated_at
    )
    .execute(&mut db.conn)
    .await?;

    let user_response = UserResponse {
        id: user_id,
        email: request.email,
        name: request.name,
        picture: request.picture,
        auth_method: Some(request.auth_method),
        created_at: timestamp_to_datetime(datetime_to_timestamp(now)).to_rfc3339(),
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
    State(mut db): State<Database>,
    State(env): State<Env>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<SessionRequest>,
) -> ApiResult<Json<InternalAuthResponse>> {
    // Validate internal service call
    validate_internal_service(&headers, &env).await?;

    // Generate session token and create session
    let token = session::generate_session_token();
    let session = session::create_session(&mut db, &token, &request.user_id)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    // Get user details
    let user = query_as!(User, "SELECT * FROM users WHERE id = ?", request.user_id)
        .fetch_optional(&mut db.conn)
        .await?;

    if let Some(user) = user {
        let user_response = UserResponse {
            id: user.id,
            email: user.email,
            name: user.name,
            picture: user.picture,
            auth_method: user.auth_method,
            created_at: timestamp_to_datetime(user.created_at).to_rfc3339(),
        };

        Ok(Json(InternalAuthResponse {
            success: true,
            user: Some(user_response),
            access_token: Some(token), // Return session token for cookie setting
            refresh_token: None,
            expires_in: Some(
                ((session.expires_at - datetime_to_timestamp(Utc::now())) / 1000).max(0),
            ),
            error: None,
        }))
    } else {
        Err(ApiError::NotFound)
    }
}

/// Internal endpoint to create API tokens
pub async fn create_tokens_internal(
    State(mut db): State<Database>,
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
    )
    .await?;

    // Find or create user first
    let user = query_as!(User, "SELECT * FROM users WHERE email = ?", request.email)
        .fetch_optional(&mut db.conn)
        .await?;

    let user_id = if let Some(user) = user {
        user.id
    } else {
        // Create new user
        let new_user_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        query!(
            r#"
            INSERT INTO users (
                id, email, name, picture, email_verified, auth_method,
                provider, provider_id, last_login_platform, last_login_at,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
            new_user_id,
            request.email,
            request.name,
            request.picture,
            datetime_to_timestamp(now),
            request.auth_method,
            request.provider,
            request.provider_id,
            request.platform,
            datetime_to_timestamp(now),
            datetime_to_timestamp(now),
            datetime_to_timestamp(now),
        )
        .execute(&mut db.conn)
        .await?;

        new_user_id
    };

    // Create token pair
    let token_pair = tokens::create_token_pair(
        &mut db,
        &user_id,
        &request.platform,
        request.user_agent.as_deref(),
        None, // IP address handled by web layer
    )
    .await
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    // Get updated user
    let user = query_as!(User, "SELECT * FROM users WHERE id = ?", &user_id)
        .fetch_one(&mut db.conn)
        .await?;

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
    State(mut db): State<Database>,
    State(env): State<Env>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<SessionValidationRequest>,
) -> ApiResult<Json<InternalAuthResponse>> {
    // Validate internal service call
    validate_internal_service(&headers, &env).await?;

    if let Some((_session, user)) = session::validate_session_token(&mut db, &request.session_token)
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
