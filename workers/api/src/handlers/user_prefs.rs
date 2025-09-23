use crate::error::{AppError, AppResult};
use crate::handlers::common::{UserPrefsRequest, UserPrefsRow};
use crate::handlers::users::get_current_user_from_request;
use crate::shared_handles::SharedHandles;
use axum::{extract::Extension, http::HeaderMap, response::Json, Json as JsonExtractor};
use chrono::Utc;
use serde_json::json;
use sqlx_d1::{query, query_as};

/// GET /v1/user/prefs
pub async fn get_user_prefs(
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    // Build owned header pairs to pass into executor
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

    // Fetch prefs
    let user_id_q = user.id.clone();
    let prefs = handles
        .db
        .run(move |mut db| async move {
            query_as::<UserPrefsRow>(
                r#"
        SELECT user_id, preferred_models, summary_models, summary_prompt_override,
               created_at, updated_at
        FROM user_prefs
        WHERE user_id = ?
        "#,
            )
            .bind(&user_id_q)
            .fetch_optional(&mut db.conn)
            .await
        })
        .await
        .map_err(AppError::from)?;

    match prefs {
        Some(row) => Ok(Json(json!({
            "user_id": row.user_id,
            "preferred_models": row.preferred_models,
            "summary_models": row.summary_models,
            "summary_prompt_override": row.summary_prompt_override,
            "created_at": row.created_at,
            "updated_at": row.updated_at
        }))),
        None => Ok(Json(json!({
            "user_id": user.id,
            "preferred_models": null,
            "summary_models": null,
            "summary_prompt_override": null,
            "created_at": null,
            "updated_at": null
        }))),
    }
}

/// PUT /v1/user/prefs
pub async fn put_user_prefs(
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
    JsonExtractor(req): JsonExtractor<UserPrefsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Get current user through executor
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

    let now = Utc::now().to_rfc3339();

    // Check if preferences already exist
    let user_id_q = user.id.clone();
    let exists = handles
        .db
        .run(move |mut db| async move {
            query_as::<(String,)>("SELECT user_id FROM user_prefs WHERE user_id = ?")
                .bind(&user_id_q)
                .fetch_optional(&mut db.conn)
                .await
        })
        .await
        .map_err(AppError::from)?;

    if exists.is_some() {
        // Update existing preferences
        let user_id_q2 = user.id.clone();
        let preferred_q = req.preferred_models.clone();
        let summary_q = req.summary_models.clone();
        let override_q = req.summary_prompt_override.clone();
        let now_q = now.clone();
        handles
            .db
            .run(move |mut db| async move {
                query(
                    r#"
            UPDATE user_prefs
            SET preferred_models = ?, summary_models = ?, summary_prompt_override = ?, updated_at = ?
            WHERE user_id = ?
            "#
                )
                .bind(&preferred_q)
                .bind(&summary_q)
                .bind(&override_q)
                .bind(&now_q)
                .bind(&user_id_q2)
                .execute(&mut db.conn)
                .await
            })
            .await
            .map_err(AppError::from)?;
    } else {
        // Insert new preferences
        let user_id_q3 = user.id.clone();
        let preferred_q = req.preferred_models.clone();
        let summary_q = req.summary_models.clone();
        let override_q = req.summary_prompt_override.clone();
        let now_q = now.clone();
        handles
            .db
            .run(move |mut db| async move {
                query(
                    r#"
            INSERT INTO user_prefs (user_id, preferred_models, summary_models, summary_prompt_override, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#
                )
                .bind(&user_id_q3)
                .bind(&preferred_q)
                .bind(&summary_q)
                .bind(&override_q)
                .bind(&now_q)
                .bind(&now_q)
                .execute(&mut db.conn)
                .await
            })
            .await
            .map_err(AppError::from)?;
    }

    // Return updated preferences
    let user_id_q4 = user.id.clone();
    let updated_prefs = handles
        .db
        .run(move |mut db| async move {
            query_as::<UserPrefsRow>(
                r#"
        SELECT user_id, preferred_models, summary_models, summary_prompt_override,
               created_at, updated_at
        FROM user_prefs
        WHERE user_id = ?
        "#,
            )
            .bind(&user_id_q4)
            .fetch_one(&mut db.conn)
            .await
        })
        .await
        .map_err(AppError::from)?;

    Ok(Json(json!({
        "user_id": updated_prefs.user_id,
        "preferred_models": updated_prefs.preferred_models,
        "summary_models": updated_prefs.summary_models,
        "summary_prompt_override": updated_prefs.summary_prompt_override,
        "created_at": updated_prefs.created_at,
        "updated_at": updated_prefs.updated_at
    })))
}
