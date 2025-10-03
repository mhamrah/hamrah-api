use crate::auth::{session, tokens};
use crate::db::{schema::User, Database};
use crate::error::{AppError, AppResult};
use crate::handlers::auth::UserResponse;

use crate::utils::{datetime_to_timestamp, timestamp_to_datetime};
use axum::{extract::Path, http::HeaderMap, response::Json, Json as JsonExtractor};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx_d1::{query_as, FromRow};

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

#[derive(Debug, Serialize, FromRow)]
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
) -> AppResult<User> {
    worker::console_log!("🔐 AUTH: Starting authentication check");

    // Log all headers for debugging
    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str() {
            // Mask sensitive values but show their presence
            let masked_value = if name.as_str().to_lowercase().contains("auth")
                || name.as_str().to_lowercase().contains("cookie")
                || name.as_str().to_lowercase().contains("session")
            {
                format!(
                    "{}...{}",
                    &value_str[..std::cmp::min(8, value_str.len())],
                    if value_str.len() > 8 {
                        &value_str[value_str.len() - 4..]
                    } else {
                        ""
                    }
                )
            } else {
                value_str.to_string()
            };
            worker::console_log!("🔐 AUTH: Header {}: {}", name.as_str(), masked_value);
        }
    }

    // First try session cookie
    if let Some(session_token) = crate::auth::cookies::get_cookie_value(headers, "session") {
        worker::console_log!(
            "🔐 AUTH: Found session cookie, length: {}",
            session_token.len()
        );

        match session::validate_session_token(db, &session_token).await {
            Ok(Some((_session, user))) => {
                worker::console_log!(
                    "🔐 AUTH: ✅ Session validated successfully for user: {}",
                    user.id
                );
                return Ok(user);
            }
            Ok(None) => {
                worker::console_log!(
                    "🔐 AUTH: ❌ Session validation returned None (invalid/expired)"
                );
            }
            Err(e) => {
                worker::console_log!("🔐 AUTH: ❌ Session validation error: {}", e.to_string());
                return Err(e.to_string().into());
            }
        }
    } else {
        worker::console_log!("🔐 AUTH: No session cookie found");
    }

    // Then try Bearer token
    if let Some(auth_header) = headers.get("authorization") {
        worker::console_log!("🔐 AUTH: Found Authorization header");

        if let Ok(auth_str) = auth_header.to_str() {
            worker::console_log!(
                "🔐 AUTH: Auth header format: {}...",
                &auth_str[..std::cmp::min(20, auth_str.len())]
            );

            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                worker::console_log!("🔐 AUTH: Extracted Bearer token, length: {}", token.len());

                match tokens::validate_access_token(db, token).await {
                    Ok(Some(auth_token)) => {
                        worker::console_log!(
                            "🔐 AUTH: ✅ Bearer token validated for user: {}",
                            auth_token.user_id
                        );

                        // Get user from token
                        match query_as::<User>("SELECT * FROM users WHERE id = ?")
                            .bind(&auth_token.user_id)
                            .fetch_one(&mut db.conn)
                            .await
                        {
                            Ok(user) => {
                                worker::console_log!(
                                    "🔐 AUTH: ✅ User fetched successfully: {}",
                                    user.id
                                );
                                return Ok(user);
                            }
                            Err(e) => {
                                worker::console_log!(
                                    "🔐 AUTH: ❌ Failed to fetch user for token: {}",
                                    e.to_string()
                                );
                                return Err(Box::new(AppError::from(e)));
                            }
                        }
                    }
                    Ok(None) => {
                        worker::console_log!(
                            "🔐 AUTH: ❌ Bearer token validation returned None (invalid/expired)"
                        );
                    }
                    Err(e) => {
                        worker::console_log!(
                            "🔐 AUTH: ❌ Bearer token validation error: {}",
                            e.to_string()
                        );
                        return Err(Box::new(AppError::from(e)));
                    }
                }
            } else {
                worker::console_log!("🔐 AUTH: ❌ Authorization header missing 'Bearer ' prefix");
            }
        } else {
            worker::console_log!("🔐 AUTH: ❌ Authorization header not valid UTF-8");
        }
    } else {
        worker::console_log!("🔐 AUTH: No Authorization header found");
    }

    worker::console_log!("🔐 AUTH: ❌ No valid authentication found - returning Unauthorized");
    Err(Box::new(AppError::unauthorized("Unauthorized")))
}

pub async fn get_current_user(
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    headers: HeaderMap,
) -> AppResult<Json<UserResponse>> {
    let headers_clone = headers.clone();
    let user =
        handles
            .db
            .run(move |mut db| async move {
                get_current_user_from_request(&mut db, &headers_clone).await
            })
            .await?;

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

    Ok(Json(user_response))
}

pub async fn get_user_by_id(
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> AppResult<Json<UserResponse>> {
    let headers_clone = headers.clone();
    let current_user =
        handles
            .db
            .run(move |mut db| async move {
                get_current_user_from_request(&mut db, &headers_clone).await
            })
            .await?;

    if current_user.id != user_id {
        return Err(Box::new(AppError::forbidden("Forbidden")));
    }

    let user_response = UserResponse {
        id: current_user.id,
        email: current_user.email,
        name: current_user.name,
        picture: current_user.picture,
        auth_method: current_user.auth_method,
        created_at: timestamp_to_datetime(current_user.created_at).to_rfc3339(),
        provider: current_user.provider,
        provider_id: current_user.provider_id,
    };

    Ok(Json(user_response))
}

pub async fn update_current_user(
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    headers: HeaderMap,
    JsonExtractor(request): JsonExtractor<UpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    let headers_clone = headers.clone();
    let user =
        handles
            .db
            .run(move |mut db| async move {
                get_current_user_from_request(&mut db, &headers_clone).await
            })
            .await?;

    let now = datetime_to_timestamp(Utc::now());

    {
        let user_id_q = user.id.clone();
        let name_q = request.name.clone();
        let picture_q = request.picture.clone();
        let now_q = now;
        handles
            .db
            .run(move |mut db| async move {
                sqlx_d1::query(
                    r#"
        UPDATE users
        SET name = CASE WHEN ? IS NOT NULL THEN ? ELSE name END,
            picture = CASE WHEN ? IS NOT NULL THEN ? ELSE picture END,
            updated_at = ?
        WHERE id = ?
        "#,
                )
                .bind(name_q.as_ref())
                .bind(name_q.as_ref())
                .bind(picture_q.as_ref())
                .bind(picture_q.as_ref())
                .bind(now_q)
                .bind(&user_id_q)
                .execute(&mut db.conn)
                .await
            })
            .await
            .map_err(AppError::from)?;
    }

    let updated_user = {
        let user_id_q = user.id.clone();
        handles
            .db
            .run(move |mut db| async move {
                query_as::<User>("SELECT * FROM users WHERE id = ?")
                    .bind(&user_id_q)
                    .fetch_one(&mut db.conn)
                    .await
            })
            .await
            .map_err(AppError::from)?
    };

    let user_response = UserResponse {
        id: updated_user.id,
        email: updated_user.email,
        name: updated_user.name,
        picture: updated_user.picture,
        auth_method: updated_user.auth_method,
        created_at: timestamp_to_datetime(updated_user.created_at).to_rfc3339(),
        provider: updated_user.provider,
        provider_id: updated_user.provider_id,
    };

    Ok(Json(user_response))
}

pub async fn get_user_tokens(
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    headers: HeaderMap,
) -> AppResult<Json<UserTokensResponse>> {
    let headers_clone = headers.clone();
    let user =
        handles
            .db
            .run(move |mut db| async move {
                get_current_user_from_request(&mut db, &headers_clone).await
            })
            .await?;

    // Using INTEGER timestamps (milliseconds) across auth_tokens and responses
    let now = datetime_to_timestamp(Utc::now());
    let results = {
        let user_id_q = user.id.clone();
        let now_q = now;
        handles
            .db
            .run(move |mut db| async move {
                query_as::<UserTokenInfo>(
                    r#"
        SELECT id, platform, user_agent, last_used, created_at, access_expires_at
        FROM auth_tokens
        WHERE user_id = ? AND revoked = 0 AND access_expires_at > ?
        ORDER BY last_used DESC, created_at DESC
        "#,
                )
                .bind(&user_id_q)
                .bind(now_q)
                .fetch_all(&mut db.conn)
                .await
            })
            .await
            .map_err(AppError::from)?
    };

    Ok(Json(UserTokensResponse {
        success: true,
        tokens: results,
    }))
}

pub async fn delete_user_account(
    axum::extract::Extension(handles): axum::extract::Extension<
        crate::shared_handles::SharedHandles,
    >,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let headers_clone = headers.clone();
    let user =
        handles
            .db
            .run(move |mut db| async move {
                get_current_user_from_request(&mut db, &headers_clone).await
            })
            .await?;

    // Delete user (cascading deletes will handle sessions, tokens, etc.)
    {
        let user_id_q = user.id.clone();
        handles
            .db
            .run(move |mut db| async move {
                sqlx_d1::query("DELETE FROM users WHERE id = ?")
                    .bind(&user_id_q)
                    .execute(&mut db.conn)
                    .await
            })
            .await
            .map_err(AppError::from)?;
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "User account deleted successfully"
    })))
}
