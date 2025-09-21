use crate::db::Database;
use crate::error::{AppError, AppResult};
use crate::handlers::common::{UserPrefsRequest, UserPrefsRow};
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

/// GET /v1/user/prefs
pub async fn get_user_prefs(
    State(mut db): State<Database>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    let prefs = query_as::<UserPrefsRow>(
        r#"
        SELECT user_id, preferred_models, summary_models, summary_prompt_override,
               created_at, updated_at
        FROM user_prefs
        WHERE user_id = ?
        "#,
    )
    .bind(&user.id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    match prefs {
        Some(row) => Ok(Json(json!({
            "user_id": row.user_id,
            "preferred_models": row.preferred_models,
            "summary_models": row.summary_models,
            "summary_prompt_override": row.summary_prompt_override,
            "created_at": row.created_at,
            "updated_at": row.updated_at
        }))),
        None => {
            // Return default preferences
            Ok(Json(json!({
                "user_id": user.id,
                "preferred_models": null,
                "summary_models": null,
                "summary_prompt_override": null,
                "created_at": null,
                "updated_at": null
            })))
        }
    }
}

/// PUT /v1/user/prefs
pub async fn put_user_prefs(
    State(mut db): State<Database>,
    headers: HeaderMap,
    JsonExtractor(req): JsonExtractor<UserPrefsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    let now = Utc::now().to_rfc3339();

    // Check if preferences already exist
    let exists = query_as::<(String,)>("SELECT user_id FROM user_prefs WHERE user_id = ?")
        .bind(&user.id)
        .fetch_optional(&mut db.conn)
        .await
        .map_err(|e| AppError::from(e))?;

    if exists.is_some() {
        // Update existing preferences
        query(
            r#"
            UPDATE user_prefs
            SET preferred_models = ?, summary_models = ?, summary_prompt_override = ?, updated_at = ?
            WHERE user_id = ?
            "#,
        )
        .bind(&req.preferred_models)
        .bind(&req.summary_models)
        .bind(&req.summary_prompt_override)
        .bind(&now)
        .bind(&user.id)
        .execute(&mut db.conn)
        .await
        .map_err(|e| AppError::from(e))?;
    } else {
        // Insert new preferences
        query(
            r#"
            INSERT INTO user_prefs (user_id, preferred_models, summary_models, summary_prompt_override, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&user.id)
        .bind(&req.preferred_models)
        .bind(&req.summary_models)
        .bind(&req.summary_prompt_override)
        .bind(&now)
        .bind(&now)
        .execute(&mut db.conn)
        .await
        .map_err(|e| AppError::from(e))?;
    }

    // Return updated preferences
    let updated_prefs = query_as::<UserPrefsRow>(
        r#"
        SELECT user_id, preferred_models, summary_models, summary_prompt_override,
               created_at, updated_at
        FROM user_prefs
        WHERE user_id = ?
        "#,
    )
    .bind(&user.id)
    .fetch_one(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    Ok(Json(json!({
        "user_id": updated_prefs.user_id,
        "preferred_models": updated_prefs.preferred_models,
        "summary_models": updated_prefs.summary_models,
        "summary_prompt_override": updated_prefs.summary_prompt_override,
        "created_at": updated_prefs.created_at,
        "updated_at": updated_prefs.updated_at
    })))
}