use crate::auth::{app_attestation, session};
use crate::db::schema::User;
use crate::error::{AppError, AppResult};
use crate::shared_handles::SharedHandles;
use crate::utils::{datetime_to_timestamp, timestamp_to_datetime};
use axum::{extract::Extension, http::HeaderMap, response::Json, Json as JsonExtractor};
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
    #[allow(dead_code)] // May be used in future platform-specific logic
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
pub async fn validate_internal_service(_headers: &HeaderMap) -> AppResult<()> {
    // Log the service binding call for debugging and tracing

    // Service bindings automatically authenticate - no manual validation needed
    // The call can only reach us if it's via a valid service binding
    Ok(())
}

/// Validate platform and client attestation
pub async fn validate_client_platform(
    platform: &str,
    user_agent: Option<&str>,
    client_attestation: Option<&str>,
    env: &Env,
) -> Result<(), String> {
    match platform {
        "web" => {
            // Web platform is validated by the internal service call itself
            Ok(())
        }
        "ios" => {
            // Validate iOS user agent
            let ua = user_agent.unwrap_or("");
            if !ua.contains("CFNetwork") && !ua.contains("hamrahIOS") {
                return Err("Invalid iOS client".to_string());
            }

            // Check if request is from iOS Simulator
            if app_attestation::is_ios_simulator(user_agent) {
                return Ok(());
            }

            // For real devices, require App Attestation
            let attestation_token =
                client_attestation.ok_or_else(|| "iOS App Attestation required".to_string())?;

            // Validate the attestation token
            app_attestation::validate_app_attestation(attestation_token, env)
                .await
                .map_err(|e| e.to_string())?;

            Ok(())
        }
        _ => Err("Unsupported platform".to_string()),
    }
}

/// Internal endpoint to create users (only from hamrah-app)
pub async fn create_user_internal(
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<CreateUserRequest>,
) -> AppResult<Json<InternalAuthResponse>> {
    // DB is accessed via SharedHandles executor; no direct clone here
    // Validate internal service call
    validate_internal_service(&headers).await?;

    // Validate platform and attestation
    match request.platform.as_str() {
        "web" => {
            // Web platform is validated by the internal service call itself
            // Nothing additional needed
        }
        "ios" => {
            // Validate iOS user agent
            let ua = request.user_agent.as_deref().unwrap_or("");
            if !ua.contains("CFNetwork") && !ua.contains("hamrahIOS") {
                return Err("Invalid iOS client".to_string().into());
            }

            // Check if request is from iOS Simulator
            if app_attestation::is_ios_simulator(request.user_agent.as_deref()) {

                // Simulator validation passes
            } else {
                // For real devices, require App Attestation
                let attestation_token = request
                    .client_attestation
                    .as_deref()
                    .ok_or_else(|| "iOS App Attestation required".to_string())?;

                // Validate the attestation token against Apple via Env handle
                {
                    let token_owned = attestation_token.to_string();
                    handles
                        .env
                        .run(move |env| async move {
                            app_attestation::validate_app_attestation(&token_owned, &env).await
                        })
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        _ => {
            return Err(Box::new(AppError::bad_request("Unsupported platform")));
        }
    }

    // Log the incoming request for debugging

    // Validate email is present and not empty
    if request.email.trim().is_empty() {
        console_log!(
            "create_user_internal: Email is empty for provider={}",
            request.provider
        );
        return Err(Box::new(AppError::bad_request(
            "Email is required for authentication",
        )));
    }

    let now = Utc::now();

    // Find or create user by email
    let email_q = request.email.clone();
    let user = handles
        .db
        .run(move |mut db| async move {
            query_as::<User>("SELECT * FROM users WHERE email = ?")
                .bind(&email_q)
                .fetch_optional(&mut db.conn)
                .await
        })
        .await
        .map_err(AppError::from)?;

    let user_id = if let Some(existing_user) = user {
        // User exists - update their auth info and login time
        let name_q = request.name.clone();
        let picture_q = request.picture.clone();
        let auth_method_q = request.auth_method.clone();
        let provider_q = request.provider.clone();
        let provider_id_q = request.provider_id.clone();
        let platform_q = request.platform.clone();
        let existing_id_q = existing_user.id.clone();
        let now_ts = datetime_to_timestamp(now);
        handles
            .db
            .run(move |mut db| async move {
                query(
                    r#"
            UPDATE users SET
                name = COALESCE(?, name),
                picture = COALESCE(?, picture),
                auth_method = ?,
                provider = ?,
                provider_id = ?,
                last_login_platform = ?,
                last_login_at = ?,
                updated_at = ?
            WHERE id = ?
            "#,
                )
                .bind(&name_q)
                .bind(&picture_q)
                .bind(&auth_method_q)
                .bind(&provider_q)
                .bind(&provider_id_q)
                .bind(&platform_q)
                .bind(now_ts)
                .bind(now_ts)
                .bind(&existing_id_q)
                .execute(&mut db.conn)
                .await
            })
            .await
            .map_err(AppError::from)?;
        existing_user.id
    } else {
        let new_user_id = Uuid::new_v4().to_string();
        let new_user_id_q = new_user_id.clone();
        let email_q2 = request.email.clone();
        let name_q = request.name.clone();
        let picture_q = request.picture.clone();
        let auth_method_q = request.auth_method.clone();
        let provider_q = request.provider.clone();
        let provider_id_q = request.provider_id.clone();
        let platform_q = request.platform.clone();
        let now_ts = datetime_to_timestamp(now);
        handles
            .db
            .run(move |mut db| async move {
                query(
                    r#"
            INSERT INTO users (
                id, email, name, picture, auth_method, provider, provider_id,
                last_login_platform, last_login_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
                )
                .bind(&new_user_id_q)
                .bind(&email_q2)
                .bind(&name_q)
                .bind(&picture_q)
                .bind(&auth_method_q)
                .bind(&provider_q)
                .bind(&provider_id_q)
                .bind(&platform_q)
                .bind(now_ts)
                .bind(now_ts)
                .bind(now_ts)
                .execute(&mut db.conn)
                .await
            })
            .await
            .map_err(AppError::from)?;
        new_user_id
    };

    // Get the final user data
    let user_id_q = user_id.clone();
    let final_user = handles
        .db
        .run(move |mut db| async move {
            query_as::<User>("SELECT * FROM users WHERE id = ?")
                .bind(&user_id_q)
                .fetch_one(&mut db.conn)
                .await
        })
        .await
        .map_err(AppError::from)?;

    let user_response = UserResponse {
        id: final_user.id,
        email: final_user.email,
        name: final_user.name,
        picture: final_user.picture,
        auth_method: final_user.auth_method,
        created_at: timestamp_to_datetime(final_user.created_at).to_rfc3339(),
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
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<SessionRequest>,
) -> AppResult<Json<InternalAuthResponse>> {
    // Validate internal service call
    validate_internal_service(&headers).await?;

    // Generate session token and create session
    let token = session::generate_session_token();
    let token_q = token.clone();
    let user_id_q = request.user_id.clone();
    let session =
        handles
            .db
            .run(move |mut db| async move {
                session::create_session(&mut db, &token_q, &user_id_q).await
            })
            .await
            .map_err(AppError::from)?;

    // Get user details
    let user_id_q2 = request.user_id.clone();
    let user = handles
        .db
        .run(move |mut db| async move {
            query_as::<User>("SELECT * FROM users WHERE id = ?")
                .bind(&user_id_q2)
                .fetch_optional(&mut db.conn)
                .await
        })
        .await
        .map_err(AppError::from)?;

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
        Err("NotFound".to_string().into())
    }
}

/// Internal endpoint to create API tokens (deprecated)
pub async fn create_tokens_internal(
    Extension(_handles): Extension<SharedHandles>,
    headers: HeaderMap,
    JsonExtractor(_request): JsonExtractor<CreateUserRequest>,
) -> AppResult<Json<InternalAuthResponse>> {
    // Validate internal service call
    validate_internal_service(&headers).await?;

    Err(Box::new(AppError::bad_request(
        "create_tokens_internal is deprecated",
    )))
}

/// Internal session validation
pub async fn validate_session_internal(
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<SessionValidationRequest>,
) -> AppResult<Json<InternalAuthResponse>> {
    // Validate internal service call
    validate_internal_service(&headers).await?;

    let token_q = request.session_token.clone();
    if let Some((_session, user)) = handles
        .db
        .run(move |mut db| async move { session::validate_session_token(&mut db, &token_q).await })
        .await
        .map_err(|e| e.to_string())?
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
        Err(Box::new(AppError::unauthorized("Unauthorized")))
    }
}

/// Internal endpoint to check if a user exists by email (service-to-service only)
pub async fn check_user_by_email_internal(
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<serde_json::Value>,
) -> AppResult<Json<serde_json::Value>> {
    // Validate internal service call
    validate_internal_service(&headers).await?;

    let email = request
        .get("email")
        .and_then(|e| e.as_str())
        .ok_or_else(|| "Email is required".to_string())?;

    let email_q = email.to_string();
    let user = handles
        .db
        .run(move |mut db| async move {
            query_as::<User>("SELECT * FROM users WHERE email = ?")
                .bind(&email_q)
                .fetch_optional(&mut db.conn)
                .await
        })
        .await
        .map_err(AppError::from)?;

    let exists = user.is_some();

    Ok(Json(serde_json::json!({ "exists": exists })))
}
