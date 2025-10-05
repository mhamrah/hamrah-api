pub mod auth;
pub mod internal;
pub mod links;
pub mod links_detail;
pub mod links_list;
pub mod models;
pub mod push;
pub mod tags;
pub mod user_prefs;
pub mod users;

pub mod common;

// Functions defined in this file are available directly

use crate::error::AppResult;
use axum::{response::IntoResponse, Json};
use serde_json::json;

// POST /v1/links handler moved to links.rs

// GET /v1/links handler moved to links_list.rs

// GET /v1/links/compact handler moved to links_list.rs

// GET /v1/links/{id} handler moved to links_detail.rs

// PATCH /v1/links/{id} handler moved to links_detail.rs

// DELETE /v1/links/{id} handler moved to links_detail.rs

// POST /v1/links/{id}/refresh handler can stay in main mod.rs for now

// Note: This handler uses both Database and Env state, keeping here temporarily
use crate::error::AppError;
use crate::handlers::users::get_current_user_from_request;
use crate::shared_handles::SharedHandles;
use axum::{extract::Path, http::HeaderMap};
use chrono::Utc;
use sqlx_d1::query;
use worker::console_log;

pub async fn post_link_refresh(
    axum::extract::Extension(handles): axum::extract::Extension<SharedHandles>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    // Authenticate current user via executor
    let headers_clone = headers.clone();
    let user =
        handles
            .db
            .run(move |mut db| async move {
                get_current_user_from_request(&mut db, &headers_clone).await
            })
            .await?;
    console_log!(
        "POST /v1/links/{}/refresh: user authenticated user_id={}",
        id,
        user.id
    );

    let now_ts = crate::utils::datetime_to_timestamp(Utc::now());

    // Ensure link belongs to user
    let id_q = id.clone();
    let user_id_q = user.id.clone();
    let exists = handles
        .db
        .run(move |mut db| async move {
            query("SELECT 1 FROM links WHERE id = ? AND user_id = ? AND deleted_at IS NULL")
                .bind(&id_q)
                .bind(&user_id_q)
                .fetch_optional(&mut db.conn)
                .await
        })
        .await
        .map_err(|e| e.to_string())?
        .is_some();

    if !exists {
        console_log!(
            "POST /v1/links/{}/refresh: link not found for user_id={}",
            id,
            user.id
        );
        return Err(Box::new(AppError::not_found("Link not found")));
    }

    // Touch link to trigger refresh (no state change)
    let id_q2 = id.clone();
    let user_id_q2 = user.id.clone();
    let now_ts_q = now_ts;
    console_log!(
        "POST /v1/links/{}/refresh: updating timestamp user_id={}",
        id,
        user.id
    );
    handles
        .db
        .run(move |mut db| async move {
            query("UPDATE links SET updated_at = ? WHERE id = ? AND user_id = ? AND deleted_at IS NULL")
                .bind(now_ts_q)
                .bind(&id_q2)
                .bind(&user_id_q2)
                .execute(&mut db.conn)
                .await
        })
        .await
        .map_err(|e| {
            console_log!("POST /v1/links/{}/refresh: DB update failed user_id={} reason={}", id, user.id, e);
            e.to_string()
        })?;

    // Trigger pipeline worker now (fire-and-forget)
    {
        let id2 = id.clone();
        let user_id2 = user.id.clone();
        console_log!(
            "POST /v1/links/{}/refresh: dispatching pipeline trigger user_id={}",
            id,
            user.id
        );
        let _ = handles
            .env
            .run(move |env| async move {
                crate::pipeline_shim::try_trigger_pipeline_for_link(&env, &id2, &user_id2).await;
                Ok::<(), ()>(())
            })
            .await;
        console_log!(
            "POST /v1/links/{}/refresh: pipeline trigger dispatched user_id={}",
            id,
            user.id
        );
    }

    Ok(Json(json!({ "success": true })))
}

// POST /v1/push/register handler moved to push.rs

// GET /v1/user/prefs handler moved to user_prefs.rs

// PUT /v1/user/prefs handler moved to user_prefs.rs

/// GET /v1/summary/config
pub async fn get_summary_config() -> impl IntoResponse {
    // Static config for clients; can be moved to DB or Env later
    Json(json!({
        "models": [
            "claude-3.5-sonnet",
            "gpt-4o-mini",
            "llama-3.1-70b"
        ],
        "defaultModel": "claude-3.5-sonnet",
        "maxTokensShort": 1200,
        "maxTokensLong": 4096
    }))
}

// GET /v1/links/{id}/tags handler moved to tags.rs

// GET /v1/users/me/tags handler moved to tags.rs
