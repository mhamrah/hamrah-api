use crate::db::Database;
use crate::error::{AppError, AppResult};
use crate::handlers::users::get_current_user_from_request;
use crate::utils::{url_canonicalize, url_is_valid_public_http};
use axum::{extract::State, http::HeaderMap, response::Json, Json as JsonExtractor};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx_d1::{query, query_as};
use uuid::Uuid;

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
struct LinkCompactItem {
    id: String,
    canonical_url: String,
    updated_at: String,
    state: String,
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

/// POST /v1/links - create or upsert links for current user
pub async fn post_links(
    State(mut db): State<Database>,
    headers: HeaderMap,
    JsonExtractor(body): JsonExtractor<PostLinksBody>,
) -> AppResult<Json<serde_json::Value>> {
    // Get current user from auth headers
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Convert body to items array
    let items: Vec<PostLinkItem> = match body {
        PostLinksBody::Single(item) => vec![item],
        PostLinksBody::Batch { links } => links,
    };

    // Validate inputs
    if items.is_empty() {
        return Err(Box::new(AppError::bad_request("No links provided")));
    }

    let mut results = Vec::new();
    let now_iso = Utc::now().to_rfc3339();

    for item in items {
        // Validate URL
        if !url_is_valid_public_http(&item.url) {
            results.push(json!({
                "url": item.url,
                "error": "Invalid or unsupported URL"
            }));
            continue;
        }

        // Canonicalize URL
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

        // Check for existing link
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
        .map_err(|e| AppError::from(e))?;

        let link_id = if let Some(row) = existing {
            // Update existing link
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
            .map_err(|e| AppError::from(e))?;

            row.id
        } else {
            // Create new link
            let new_id = Uuid::new_v4().to_string();
            query(
                r#"
                INSERT INTO links (
                    id, user_id, original_url, canonical_url, host,
                    state, save_count, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'new', 1, ?, ?)
                "#,
            )
            .bind(&new_id)
            .bind(&user.id)
            .bind(&item.url)
            .bind(&canonical_url)
            .bind(&host)
            .bind(&now_iso)
            .bind(&now_iso)
            .execute(&mut db.conn)
            .await
            .map_err(|e| AppError::from(e))?;

            new_id
        };

        // Record the save
        let save_id = Uuid::new_v4().to_string();
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
        .map_err(|e| AppError::from(e))?;

        // Get the current link state for response
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
        .map_err(|e| AppError::from(e))?;

        results.push(serde_json::to_value(link).unwrap());

        // TODO: Trigger background processing when env is available
        // let _ = crate::pipeline_shim::try_trigger_pipeline_for_link(&env, &link_id, &user.id).await;
    }

    Ok(Json(json!({
        "success": true,
        "links": results
    })))
}