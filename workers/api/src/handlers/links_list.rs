use crate::db::Database;
use crate::error::AppResult;
use crate::handlers::common::{LinkListItem, LinkCompactItem};
use crate::handlers::users::get_current_user_from_request;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde_json::json;
use sqlx_d1::{query_as};
use std::collections::HashMap;

/// GET /v1/links - list full link records (most recent first)
pub async fn get_links(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> AppResult<(StatusCode, HeaderMap, Json<serde_json::Value>)> {
    let user = get_current_user_from_request(&mut db, &headers).await?;
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .min(100);

    let offset = params
        .get("offset")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);

    let tag = params.get("tag");
    let state = params.get("state");

    // Build query with filters
    let mut query_str = String::from(
        r#"
        SELECT id, canonical_url, original_url, state, save_count,
               created_at, updated_at, title, description, site_name, image_url, favicon_url
        FROM links
        WHERE user_id = ? AND state != 'deleted'
        "#,
    );

    let mut bindings = vec![user.id.clone()];

    if let Some(tag_filter) = tag {
        query_str.push_str(" AND id IN (SELECT link_id FROM link_tags WHERE tag_name = ?)");
        bindings.push(tag_filter.clone());
    }

    if let Some(state_filter) = state {
        query_str.push_str(" AND state = ?");
        bindings.push(state_filter.clone());
    }

    query_str.push_str(" ORDER BY updated_at DESC LIMIT ? OFFSET ?");
    bindings.push(limit.to_string());
    bindings.push(offset.to_string());

    let mut query = query_as::<LinkListItem>(&query_str);
    for binding in bindings {
        query = query.bind(binding);
    }

    let rows = query
        .fetch_all(&mut db.conn)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", "no-store".parse().unwrap());

    Ok((
        StatusCode::OK,
        headers,
        Json(json!({
            "links": rows,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "has_more": rows.len() as i64 == limit
            }
        })),
    ))
}

/// GET /v1/links/compact - list compact records (id, canonical_url, updated_at, state)
pub async fn get_links_compact(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> AppResult<(StatusCode, HeaderMap, Json<serde_json::Value>)> {
    let user = get_current_user_from_request(&mut db, &headers).await?;
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100)
        .min(500);

    let since = params.get("since");

    let mut query_str = String::from(
        r#"
        SELECT id, canonical_url, updated_at, state
        FROM links
        WHERE user_id = ? AND state != 'deleted'
        "#,
    );

    let mut bindings = vec![user.id.clone()];

    if let Some(since_time) = since {
        query_str.push_str(" AND updated_at > ?");
        bindings.push(since_time.clone());
    }

    query_str.push_str(" ORDER BY updated_at DESC LIMIT ?");
    bindings.push(limit.to_string());

    let mut query = query_as::<LinkCompactItem>(&query_str);
    for binding in bindings {
        query = query.bind(binding);
    }

    let rows = query
        .fetch_all(&mut db.conn)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", "no-store".parse().unwrap());

    Ok((
        StatusCode::OK,
        headers,
        Json(json!({
            "links": rows,
            "count": rows.len()
        })),
    ))
}