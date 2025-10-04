use crate::error::{AppError, AppResult};
use crate::handlers::common::PushRegisterRequest;
use crate::handlers::users::get_current_user_from_request;
use crate::shared_handles::SharedHandles;
use crate::utils::datetime_to_timestamp;
use axum::{http::HeaderMap, response::Json, Json as JsonExtractor};
use chrono::Utc;
use serde_json::json;
use sqlx_d1::{query, query_as};
use uuid::Uuid;

/// POST /v1/push/register - register/update a device token for push
pub async fn post_push_register(
    axum::extract::Extension(handles): axum::extract::Extension<SharedHandles>,
    headers: HeaderMap,
    JsonExtractor(req): JsonExtractor<PushRegisterRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Authenticate current user through executor using owned headers
    let header_pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();
    let user = handles
        .db
        .run(move |mut db| async move {
            let mut hdrs = HeaderMap::new();
            for (k, v) in header_pairs {
                if let (Ok(name), Ok(value)) = (
                    axum::http::header::HeaderName::from_bytes(k.as_bytes()),
                    axum::http::HeaderValue::from_str(&v),
                ) {
                    hdrs.insert(name, value);
                }
            }
            get_current_user_from_request(&mut db, &hdrs).await
        })
        .await?;

    // Validate platform
    if !["ios", "android", "web"].contains(&req.platform.as_str()) {
        return Err(Box::new(AppError::bad_request("Invalid platform")));
    }

    let now = datetime_to_timestamp(Utc::now());

    // Check if token already exists for this user/platform combination
    let _user_id_q = user.id.clone();
    let _platform_q = req.platform.clone();
    let device_token_q = req.device_token.clone();
    let existing = handles
        .db
        .run(move |mut db| async move {
            query_as::<(String,)>("SELECT id FROM push_tokens WHERE device_token = ?")
                .bind(&device_token_q)
                .fetch_optional(&mut db.conn)
                .await
        })
        .await
        .map_err(AppError::from)?;

    if existing.is_some() {
        // Token already exists, update last_seen
        let now_q = now;
        let user_id_q2 = user.id.clone();
        let platform_q2 = req.platform.clone();
        let device_token_q2 = req.device_token.clone();
        handles
            .db
            .run(move |mut db| async move {
                query(
                    "UPDATE push_tokens SET user_id = ?, platform = ?, last_seen = ? WHERE device_token = ?",
                )
                .bind(&user_id_q2)
                .bind(&platform_q2)
                .bind(now_q)
                .bind(&device_token_q2)
                .execute(&mut db.conn)
                .await
            })
            .await
            .map_err(AppError::from)?;

        return Ok(Json(json!({
            "success": true,
            "message": "Device token updated"
        })));
    }

    // Insert new token
    let token_id = Uuid::new_v4().to_string();
    let token_id_q = token_id.clone();
    let user_id_q3 = user.id.clone();
    let device_token_q3 = req.device_token.clone();
    let platform_q3 = req.platform.clone();
    let now_q = now;
    handles
        .db
        .run(move |mut db| async move {
            query(
                r#"
        INSERT INTO push_tokens (id, user_id, device_token, platform, created_at, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_token) DO UPDATE SET
            user_id = excluded.user_id,
            platform = excluded.platform,
            last_seen = excluded.last_seen
        "#,
            )
            .bind(&token_id_q)
            .bind(&user_id_q3)
            .bind(&device_token_q3)
            .bind(&platform_q3)
            .bind(now_q)
            .bind(now_q)
            .execute(&mut db.conn)
            .await
        })
        .await
        .map_err(AppError::from)?;

    Ok(Json(json!({
        "success": true,
        "message": "Device token registered",
        "token_id": token_id
    })))
}
