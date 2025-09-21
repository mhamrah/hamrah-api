pub mod auth;
pub mod internal;
pub mod links;
pub mod links_archive;
pub mod links_detail;
pub mod links_list;
pub mod models;
pub mod push;
pub mod tags;
pub mod user_prefs;
pub mod users;
pub mod webauthn_data;

pub mod common;

// Functions defined in this file are available directly

use crate::error::AppResult;
use axum::{
    response::IntoResponse,
    Json,
};
use serde_json::json;

// POST /v1/links handler moved to links.rs

// GET /v1/links handler moved to links_list.rs

// GET /v1/links/compact handler moved to links_list.rs

// GET /v1/links/{id} handler moved to links_detail.rs

// PATCH /v1/links/{id} handler moved to links_detail.rs

// DELETE /v1/links/{id} handler moved to links_detail.rs

// HEAD /v1/links/{id}/archive handler moved to links_archive.rs

// GET /v1/links/{id}/archive handler moved to links_archive.rs

// POST /v1/links/{id}/refresh handler can stay in main mod.rs for now

// Note: This handler uses both Database and Env state, keeping here temporarily
use crate::db::Database;
use crate::handlers::users::get_current_user_from_request;
use crate::error::AppError;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
};
use chrono::Utc;
use sqlx_d1::query;
use worker::Env;

pub async fn post_link_refresh(
    State(mut db): State<Database>,
    State(env): State<Env>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;
    let now_iso = Utc::now().to_rfc3339();

    // Ensure link belongs to user
    let exists = query("SELECT 1 FROM links WHERE id = ? AND user_id = ? AND deleted_at IS NULL")
        .bind(&id)
        .bind(&user.id)
        .fetch_optional(&mut db.conn)
        .await
        .map_err(|e| e.to_string())?
        .is_some();

    if !exists {
        return Err(Box::new(AppError::not_found("Link not found")));
    }

    // Update link state to pending
    query("UPDATE links SET state = 'pending', updated_at = ? WHERE id = ? AND user_id = ? AND deleted_at IS NULL")
        .bind(&now_iso)
        .bind(&id)
        .bind(&user.id)
        .execute(&mut db.conn)
        .await
        .map_err(|e| e.to_string())?;

    // Trigger pipeline worker now (fire-and-forget)
    crate::pipeline_shim::try_trigger_pipeline_for_link(&env, &id, &user.id).await;

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
