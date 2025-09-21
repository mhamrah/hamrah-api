use crate::db::Database;
use crate::error::{AppError, AppResult};
use crate::handlers::common::PushRegisterRequest;
use crate::handlers::users::get_current_user_from_request;
use axum::{
    extract::State,
    http::HeaderMap,
    response::Json,
    Json as JsonExtractor,
};
use chrono::Utc;
use serde_json::json;
use sqlx_d1::{query, query_as};
use uuid::Uuid;

/// POST /v1/push/register - register/update a device token for push
pub async fn post_push_register(
    State(mut db): State<Database>,
    headers: HeaderMap,
    JsonExtractor(req): JsonExtractor<PushRegisterRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Validate platform
    if !["ios", "android", "web"].contains(&req.platform.as_str()) {
        return Err(Box::new(AppError::bad_request("Invalid platform")));
    }

    let now = Utc::now().to_rfc3339();

    // Check if token already exists for this user/platform combination
    let existing = query_as::<(String,)>(
        "SELECT id FROM push_tokens WHERE user_id = ? AND platform = ? AND device_token = ?"
    )
    .bind(&user.id)
    .bind(&req.platform)
    .bind(&req.device_token)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    if existing.is_some() {
        // Token already exists, update last_seen
        query(
            "UPDATE push_tokens SET last_seen = ? WHERE user_id = ? AND platform = ? AND device_token = ?"
        )
        .bind(&now)
        .bind(&user.id)
        .bind(&req.platform)
        .bind(&req.device_token)
        .execute(&mut db.conn)
        .await
        .map_err(|e| AppError::from(e))?;

        return Ok(Json(json!({
            "success": true,
            "message": "Device token updated"
        })));
    }

    // Insert new token
    let token_id = Uuid::new_v4().to_string();
    query(
        r#"
        INSERT INTO push_tokens (id, user_id, device_token, platform, created_at, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&token_id)
    .bind(&user.id)
    .bind(&req.device_token)
    .bind(&req.platform)
    .bind(&now)
    .bind(&now)
    .execute(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    Ok(Json(json!({
        "success": true,
        "message": "Device token registered",
        "token_id": token_id
    })))
}