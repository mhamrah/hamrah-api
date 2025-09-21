pub mod auth;
pub mod internal;
pub mod users;
pub mod webauthn_data;

use crate::error::{AppError, AppResult};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx_d1::{query, query_as};

use crate::db::Database;
use crate::handlers::users::get_current_user_from_request;
use crate::utils::{url_canonicalize, url_is_valid_public_http};
use worker::Env;

#[derive(Debug, Deserialize)]
pub struct PostLinkItem {
    url: String,
    #[serde(rename = "clientId")]
    client_id: Option<String>,
    #[serde(rename = "sourceApp")]
    source_app: Option<String>,
    #[serde(rename = "sharedText")]
    shared_text: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PostLinksBody {
    Single(PostLinkItem),
    Batch { links: Vec<PostLinkItem> },
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct LinkListItem {
    id: String,
    canonical_url: String,
    original_url: String,
    state: String,
    save_count: i64,
    created_at: String,
    updated_at: String,
    title: Option<String>,
    description: Option<String>,
    site_name: Option<String>,
    image_url: Option<String>,
    favicon_url: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct LinkCompactItem {
    id: String,
    canonical_url: String,
    updated_at: String,
    state: String,
}

#[derive(Debug, Deserialize)]
pub struct UserPrefsRequest {
    preferred_models: Option<String>,
    summary_models: Option<String>,
    summary_prompt_override: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct UserPrefsRow {
    user_id: String,
    preferred_models: Option<String>,
    summary_models: Option<String>,
    summary_prompt_override: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct PushRegisterRequest {
    device_token: String,
    platform: String,
}

/// POST /v1/links - create or upsert links for current user
pub async fn post_links(
    State(mut db): State<Database>,
    State(env): State<Env>,
    headers: HeaderMap,
    Json(body): Json<PostLinksBody>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Idempotency: if Idempotency-Key present and stored, return stored response
    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    if let Some(ref key) = idempotency_key {
        #[derive(sqlx::FromRow)]
        struct IdemRow {
            response_body: Option<Vec<u8>>,
            status: Option<i64>,
        }

        if let Some(stored) = query_as::<IdemRow>(
            "SELECT response_body, status FROM idempotency_keys WHERE key = ? AND user_id = ?",
        )
        .bind(key)
        .bind(&user.id)
        .fetch_optional(&mut db.conn)
        .await
        .map_err(|e| e.to_string())?
        {
            if stored.status.unwrap_or(200) == 200 {
                if let Some(body) = stored.response_body {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&body) {
                        return Ok(Json(val));
                    }
                }
            }
        }
    }

    let items: Vec<PostLinkItem> = match body {
        PostLinksBody::Single(item) => vec![item],
        PostLinksBody::Batch { links } => links,
    };

    let mut results = Vec::with_capacity(items.len());
    for item in items {
        // Validate and canonicalize URL
        if !url_is_valid_public_http(&item.url) {
            results.push(json!({
                "url": item.url,
                "error": "Invalid or unsupported URL"
            }));
            continue;
        }

        let (canonical_url, host) = match url_canonicalize(&item.url) {
            Some((canon, host)) => (canon, host),
            None => {
                results.push(json!({
                    "url": item.url,
                    "error": "Failed to canonicalize URL"
                }));
                continue;
            }
        };

        // Check for existing link for this user and canonical URL
        let existing = query_as::<LinkCompactItem>(
            r#"
            SELECT id, canonical_url, updated_at, state
            FROM links
            WHERE user_id = ? AND canonical_url = ?
            "#,
        )
        .bind(&user.id)
        .bind(&canonical_url)
        .fetch_optional(&mut db.conn)
        .await
        .map_err(|e| e.to_string())?;

        let now_iso = Utc::now().to_rfc3339();
        let link_id = if let Some(row) = existing {
            // Increment save_count and update timestamp
            query(
                r#"
                UPDATE links
                SET save_count = save_count + 1,
                    updated_at = ?
                WHERE id = ?
                "#,
            )
            .bind(&now_iso)
            .bind(&row.id)
            .execute(&mut db.conn)
            .await
            .map_err(|e| e.to_string())?;
            row.id
        } else {
            // Create new link
            let new_id = uuid::Uuid::new_v4().to_string();
            query(
                r#"
                INSERT INTO links (
                    id, user_id, client_id, original_url, canonical_url, host,
                    state, save_count, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'pending', 1, ?, ?)
                "#,
            )
            .bind(&new_id)
            .bind(&user.id)
            .bind(&item.client_id)
            .bind(&item.url)
            .bind(&canonical_url)
            .bind(&host)
            .bind(&now_iso)
            .bind(&now_iso)
            .execute(&mut db.conn)
            .await
            .map_err(|e| e.to_string())?;

            // (jobs removed; pipeline is triggered directly via service binding)

            new_id
        };

        // Record the save
        let save_id = uuid::Uuid::new_v4().to_string();
        query(
            r#"
            INSERT INTO link_saves (
                id, link_id, user_id, source_app, shared_text, shared_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&save_id)
        .bind(&link_id)
        .bind(&user.id)
        .bind(&item.source_app)
        .bind(&item.shared_text)
        .bind::<Option<String>>(None)
        .bind(&now_iso)
        .execute(&mut db.conn)
        .await
        .map_err(|e| e.to_string())?;

        // Return the current link state
        let link = query_as::<LinkListItem>(
            r#"
            SELECT id, canonical_url, original_url, state, save_count,
                   created_at, updated_at, title, description, site_name, image_url, favicon_url
            FROM links WHERE id = ?
            "#,
        )
        .bind(&link_id)
        .fetch_one(&mut db.conn)
        .await
        .map_err(|e| e.to_string())?;

        results.push(serde_json::to_value(link).unwrap());
        // Trigger background processing via pipeline worker (fire-and-forget)
        crate::pipeline_shim::try_trigger_pipeline_for_link(&env, &link_id, &user.id).await;
        // Best-effort trigger pipeline worker via service binding
    }

    // Build response and store idempotency record if applicable
    let response_json = json!({
        "success": true,
        "links": results
    });

    if let Some(ref key) = idempotency_key {
        let now_iso = Utc::now().to_rfc3339();
        let _ = query(
            "INSERT OR REPLACE INTO idempotency_keys (key, user_id, response_body, status, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(key)
        .bind(&user.id)
        .bind(serde_json::to_vec(&response_json).ok())
        .bind(200i64)
        .bind(&now_iso)
        .execute(&mut db.conn)
        .await;
    }

    Ok(Json(response_json))
}

/// GET /v1/links - list full link records (most recent first)
pub async fn get_links(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> AppResult<(StatusCode, HeaderMap, Json<serde_json::Value>)> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Parse query params
    let since = params.get("since").cloned();
    let mut limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100);
    limit = limit.clamp(1, 500);
    let include_deleted = params
        .get("includeDeleted")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let only_deleted = params
        .get("onlyDeleted")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // Build ETag from latest updated_at and count
    #[derive(sqlx::FromRow)]
    struct AggRow {
        latest: Option<String>,
        cnt: i64,
    }

    let deleted_filter = if only_deleted {
        " AND deleted_at IS NOT NULL "
    } else if include_deleted {
        ""
    } else {
        " AND deleted_at IS NULL "
    };
    let agg = if let Some(ref s) = since {
        let sql = format!(
            "SELECT MAX(updated_at) AS latest, COUNT(*) AS cnt FROM links WHERE user_id = ? {} AND updated_at > ?",
            deleted_filter
        );
        query_as::<AggRow>(&sql)
            .bind(&user.id)
            .bind(s)
            .fetch_one(&mut db.conn)
            .await
            .map_err(|e| e.to_string())?
    } else {
        let sql = format!(
            "SELECT MAX(updated_at) AS latest, COUNT(*) AS cnt FROM links WHERE user_id = ? {}",
            deleted_filter
        );
        query_as::<AggRow>(&sql)
            .bind(&user.id)
            .fetch_one(&mut db.conn)
            .await
            .map_err(|e| e.to_string())?
    };

    let etag = format!(
        "W/\"{}:{}:{}\"",
        agg.latest.clone().unwrap_or_default(),
        agg.cnt,
        since.clone().unwrap_or_default()
    );

    if let Some(inm) = headers.get("if-none-match").and_then(|h| h.to_str().ok()) {
        if inm == etag {
            let mut h = HeaderMap::new();
            if let Ok(hv) = HeaderValue::from_str(&etag) {
                h.insert("ETag", hv);
            }
            return Ok((StatusCode::NOT_MODIFIED, h, Json(json!({}))));
        }
    }

    let rows = if let Some(ref s) = since {
        let sql = format!(
            r#"
            SELECT id, canonical_url, original_url, state, save_count,
                   created_at, updated_at, title, description, site_name, image_url, favicon_url
            FROM links
            WHERE user_id = ? {} AND updated_at > ?
            ORDER BY updated_at DESC
            LIMIT ?
            "#,
            deleted_filter
        );
        query_as::<LinkListItem>(&sql)
            .bind(&user.id)
            .bind(s)
            .bind(limit)
            .fetch_all(&mut db.conn)
            .await
            .map_err(|e| e.to_string())?
    } else {
        let sql = format!(
            r#"
            SELECT id, canonical_url, original_url, state, save_count,
                   created_at, updated_at, title, description, site_name, image_url, favicon_url
            FROM links
            WHERE user_id = ? {}
            ORDER BY updated_at DESC
            LIMIT ?
            "#,
            deleted_filter
        );
        query_as::<LinkListItem>(&sql)
            .bind(&user.id)
            .bind(limit)
            .fetch_all(&mut db.conn)
            .await
            .map_err(|e| e.to_string())?
    };

    let mut h = HeaderMap::new();
    if let Ok(hv) = HeaderValue::from_str(&etag) {
        h.insert("ETag", hv);
    }
    Ok((
        StatusCode::OK,
        h,
        Json(json!({ "links": rows, "etag": etag })),
    ))
}

/// GET /v1/links/compact - list compact records (id, canonical_url, updated_at, state)
pub async fn get_links_compact(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> AppResult<(StatusCode, HeaderMap, Json<serde_json::Value>)> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Parse query params
    let since = params.get("since").cloned();
    let mut limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(200);
    limit = limit.clamp(1, 1000);
    let include_deleted = params
        .get("includeDeleted")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let only_deleted = params
        .get("onlyDeleted")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // Build ETag
    #[derive(sqlx::FromRow)]
    struct AggRow {
        latest: Option<String>,
        cnt: i64,
    }

    let deleted_filter = if only_deleted {
        " AND deleted_at IS NOT NULL "
    } else if include_deleted {
        ""
    } else {
        " AND deleted_at IS NULL "
    };
    let agg = if let Some(ref s) = since {
        let sql = format!(
            "SELECT MAX(updated_at) AS latest, COUNT(*) AS cnt FROM links WHERE user_id = ? {} AND updated_at > ?",
            deleted_filter
        );
        query_as::<AggRow>(&sql)
            .bind(&user.id)
            .bind(s)
            .fetch_one(&mut db.conn)
            .await
            .map_err(|e| e.to_string())?
    } else {
        let sql = format!(
            "SELECT MAX(updated_at) AS latest, COUNT(*) AS cnt FROM links WHERE user_id = ? {}",
            deleted_filter
        );
        query_as::<AggRow>(&sql)
            .bind(&user.id)
            .fetch_one(&mut db.conn)
            .await
            .map_err(|e| e.to_string())?
    };

    let etag = format!(
        "W/\"{}:{}:{}\"",
        agg.latest.clone().unwrap_or_default(),
        agg.cnt,
        since.clone().unwrap_or_default()
    );

    if let Some(inm) = headers.get("if-none-match").and_then(|h| h.to_str().ok()) {
        if inm == etag {
            let mut h = HeaderMap::new();
            if let Ok(hv) = HeaderValue::from_str(&etag) {
                h.insert("ETag", hv);
            }
            return Ok((StatusCode::NOT_MODIFIED, h, Json(json!({}))));
        }
    }

    let rows = if let Some(ref s) = since {
        let sql = format!(
            r#"
            SELECT id, canonical_url, updated_at, state
            FROM links
            WHERE user_id = ? {} AND updated_at > ?
            ORDER BY updated_at DESC
            LIMIT ?
            "#,
            deleted_filter
        );
        query_as::<LinkCompactItem>(&sql)
            .bind(&user.id)
            .bind(s)
            .bind(limit)
            .fetch_all(&mut db.conn)
            .await
            .map_err(|e| e.to_string())?
    } else {
        let sql = format!(
            r#"
            SELECT id, canonical_url, updated_at, state
            FROM links
            WHERE user_id = ? {}
            ORDER BY updated_at DESC
            LIMIT ?
            "#,
            deleted_filter
        );
        query_as::<LinkCompactItem>(&sql)
            .bind(&user.id)
            .bind(limit)
            .fetch_all(&mut db.conn)
            .await
            .map_err(|e| e.to_string())?
    };

    let mut h = HeaderMap::new();
    if let Ok(hv) = HeaderValue::from_str(&etag) {
        h.insert("ETag", hv);
    }
    Ok((
        StatusCode::OK,
        h,
        Json(json!({ "links": rows, "etag": etag })),
    ))
}

/// GET /v1/links/{id}
pub async fn get_link_by_id(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    let row = query_as::<LinkListItem>(
        r#"
        SELECT id, canonical_url, original_url, state, save_count,
               created_at, updated_at, title, description, site_name, image_url, favicon_url
        FROM links
        WHERE id = ? AND user_id = ? AND deleted_at IS NULL
        "#,
    )
    .bind(&id)
    .bind(&user.id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| e.to_string())?;

    if let Some(link) = row {
        Ok(Json(json!({ "link": link })))
    } else {
        Err(Box::new(crate::error::AppError::not_found(
            "Archive not found",
        )))
    }
}

/// PATCH /v1/links/{id} - update metadata fields
#[derive(Debug, Deserialize)]
pub struct LinkPatchRequest {
    title: Option<String>,
    description: Option<String>,
    site_name: Option<String>,
    image_url: Option<String>,
    favicon_url: Option<String>,
    state: Option<String>,
}
pub async fn patch_link_by_id(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<LinkPatchRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;
    let now_iso = Utc::now().to_rfc3339();

    // Update only provided fields
    query(
        r#"
        UPDATE links
        SET title = CASE WHEN ? IS NOT NULL THEN ? ELSE title END,
            description = CASE WHEN ? IS NOT NULL THEN ? ELSE description END,
            site_name = CASE WHEN ? IS NOT NULL THEN ? ELSE site_name END,
            image_url = CASE WHEN ? IS NOT NULL THEN ? ELSE image_url END,
            favicon_url = CASE WHEN ? IS NOT NULL THEN ? ELSE favicon_url END,
            state = CASE WHEN ? IS NOT NULL THEN ? ELSE state END,
            updated_at = ?
        WHERE id = ? AND user_id = ? AND deleted_at IS NULL
        "#,
    )
    .bind(body.title.as_ref())
    .bind(body.title.as_ref())
    .bind(body.description.as_ref())
    .bind(body.description.as_ref())
    .bind(body.site_name.as_ref())
    .bind(body.site_name.as_ref())
    .bind(body.image_url.as_ref())
    .bind(body.image_url.as_ref())
    .bind(body.favicon_url.as_ref())
    .bind(body.favicon_url.as_ref())
    .bind(body.state.as_ref())
    .bind(body.state.as_ref())
    .bind(&now_iso)
    .bind(&id)
    .bind(&user.id)
    .execute(&mut db.conn)
    .await
    .map_err(|e| e.to_string())?;

    // Return updated link
    let link = query_as::<LinkListItem>(
        r#"
        SELECT id, canonical_url, original_url, state, save_count,
               created_at, updated_at, title, description, site_name, image_url, favicon_url
        FROM links
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&id)
    .bind(&user.id)
    .fetch_one(&mut db.conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(Json(json!({ "link": link })))
}

/// DELETE /v1/links/{id}
pub async fn delete_link_by_id(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> crate::error::AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Soft delete link and bump updated_at
    let now_iso = Utc::now().to_rfc3339();
    query("UPDATE links SET deleted_at = ?, updated_at = ? WHERE id = ? AND user_id = ? AND deleted_at IS NULL")
        .bind(&now_iso)
        .bind(&now_iso)
        .bind(&id)
        .bind(&user.id)
        .execute(&mut db.conn)
        .await
        .map_err(|e| e.to_string())?;

    Ok(Json(json!({ "success": true })))
}

/// HEAD /v1/links/{id}/archive
pub async fn head_link_archive(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<(StatusCode, HeaderMap)> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    #[derive(sqlx::FromRow)]
    struct ArchiveInfo {
        state: String,
        archive_bytes: Option<i64>,
    }

    let info = query_as::<ArchiveInfo>(
        "SELECT state, archive_bytes FROM links WHERE id = ? AND user_id = ? AND deleted_at IS NULL",
    )
    .bind(&id)
    .bind(&user.id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| e.to_string())?;

    let mut hdrs = HeaderMap::new();
    if let Some(i) = info {
        hdrs.insert(
            "X-Archive-State",
            HeaderValue::from_str(&i.state).unwrap_or(HeaderValue::from_static("unknown")),
        );
        if let Some(bytes) = i.archive_bytes {
            hdrs.insert(
                "X-Archive-Bytes",
                HeaderValue::from_str(&bytes.to_string()).unwrap_or(HeaderValue::from_static("0")),
            );
        }
        Ok((StatusCode::OK, hdrs))
    } else {
        Ok((StatusCode::NOT_FOUND, hdrs))
    }
}

/// GET /v1/links/{id}/archive
pub async fn get_link_archive(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> crate::error::AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    #[derive(sqlx::FromRow, Serialize)]
    struct ArchiveRow {
        id: String,
        state: String,
        archive_r2_key: Option<String>,
        archive_etag: Option<String>,
        archive_bytes: Option<i64>,
        updated_at: String,
    }

    let row = query_as::<ArchiveRow>(
        r#"
        SELECT id, state, archive_r2_key, archive_etag, archive_bytes, updated_at
        FROM links
        WHERE id = ? AND user_id = ? AND deleted_at IS NULL
        "#,
    )
    .bind(&id)
    .bind(&user.id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| e.to_string())?;

    if let Some(a) = row {
        Ok(Json(json!({ "archive": a })))
    } else {
        Err(Box::new(crate::error::AppError::not_found(
            "Link not found",
        )))
    }
}

/// POST /v1/links/{id}/refresh - enqueue a refresh job
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

    // Best-effort trigger pipeline worker via service binding

    // Trigger pipeline worker now (fire-and-forget)
    crate::pipeline_shim::try_trigger_pipeline_for_link(&env, &id, &user.id).await;

    Ok(Json(serde_json::json!({ "success": true })))
}

/// POST /v1/push/register - register/update a device token for push
pub async fn post_push_register(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Json(req): Json<PushRegisterRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;
    let now_iso = Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();

    // Upsert by device_token
    query(
        r#"
        INSERT INTO push_tokens (id, user_id, device_token, platform, created_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(device_token) DO UPDATE SET
            user_id = excluded.user_id,
            platform = excluded.platform
        "#,
    )
    .bind(&id)
    .bind(&user.id)
    .bind(&req.device_token)
    .bind(&req.platform)
    .bind(&now_iso)
    .execute(&mut db.conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(Json(json!({ "success": true })))
}

/// GET /v1/user/prefs
pub async fn get_user_prefs(
    State(mut db): State<Database>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    let prefs = query_as::<UserPrefsRow>(
        r#"
        SELECT user_id, preferred_models, summary_models, summary_prompt_override, created_at, updated_at
        FROM user_prefs
        WHERE user_id = ?
        "#,
    )
    .bind(&user.id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(Json(json!({
        "userId": user.id,
        "preferredModels": prefs.as_ref().and_then(|p| p.preferred_models.clone()),
        "summaryModels": prefs.as_ref().and_then(|p| p.summary_models.clone()),
        "summaryPromptOverride": prefs.as_ref().and_then(|p| p.summary_prompt_override.clone()),
    })))
}

/// PUT /v1/user/prefs
pub async fn put_user_prefs(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Json(req): Json<UserPrefsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;
    let now_iso = Utc::now().to_rfc3339();

    query(
        r#"
        INSERT INTO user_prefs (
            user_id, preferred_models, summary_models, summary_prompt_override,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            preferred_models = excluded.preferred_models,
            summary_models = excluded.summary_models,
            summary_prompt_override = excluded.summary_prompt_override,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&user.id)
    .bind(&req.preferred_models)
    .bind(&req.summary_models)
    .bind(&req.summary_prompt_override)
    .bind(&now_iso)
    .bind(&now_iso)
    .execute(&mut db.conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(Json(json!({ "success": true })))
}

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

/// GET /v1/links/{id}/tags - list tags for a specific link (owned by current user)
pub async fn get_link_tags(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> crate::error::AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    #[derive(Debug, Serialize, sqlx::FromRow)]
    struct LinkTagView {
        tag: String,
        confidence: Option<f64>,
    }

    let rows = query_as::<LinkTagView>(
        r#"
        SELECT t.name AS tag, lt.confidence AS confidence
        FROM link_tags lt
        JOIN tags t ON t.id = lt.tag_id
        JOIN links l ON l.id = lt.link_id
        WHERE lt.link_id = ? AND l.user_id = ? AND l.deleted_at IS NULL
        ORDER BY COALESCE(lt.confidence, 0.0) DESC, t.name ASC
        "#,
    )
    .bind(&id)
    .bind(&user.id)
    .fetch_all(&mut db.conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(Json(json!({ "tags": rows })))
}

/// GET /v1/users/me/tags - aggregate tag counts across user's non-deleted links
pub async fn get_user_tags(
    State(mut db): State<Database>,
    headers: HeaderMap,
) -> crate::error::AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    #[derive(Debug, Serialize, sqlx::FromRow)]
    struct TagSummary {
        tag: String,
        count: i64,
    }

    let rows = query_as::<TagSummary>(
        r#"
        SELECT t.name AS tag, COUNT(*) AS count
        FROM link_tags lt
        JOIN tags t ON t.id = lt.tag_id
        JOIN links l ON l.id = lt.link_id
        WHERE l.user_id = ? AND l.deleted_at IS NULL
        GROUP BY t.name
        ORDER BY count DESC, tag ASC
        "#,
    )
    .bind(&user.id)
    .fetch_all(&mut db.conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(Json(json!({ "tags": rows })))
}
