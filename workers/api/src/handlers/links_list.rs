use crate::error::AppResult;
use crate::handlers::common::LinkCompactItem;
use crate::handlers::users::get_current_user_from_request;
use crate::shared_handles::SharedHandles;
use axum::{
    extract::{Extension, Query},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde_json::json;
use sqlx_d1::query_as;
use std::collections::HashMap;

/// GET /v1/links - delta sync: returns links since cursor and next_cursor
pub async fn get_links(
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> AppResult<(StatusCode, HeaderMap, Json<serde_json::Value>)> {
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

    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100)
        .min(500);

    // since is an INTEGER timestamp (ms)
    let since: i64 = params
        .get("since")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);

    #[derive(sqlx::FromRow, Debug)]
    struct DeltaRow {
        id: String,
        original_url: String,
        canonical_url: String,
        title: Option<String>,
        description: Option<String>,
        summary_short: Option<String>,
        summary_long: Option<String>,
        lang: Option<String>,
        save_count: i64,
        state: String,
        created_at: i64,
        updated_at: i64,
        shared_at: Option<i64>,
    }

    #[derive(sqlx::FromRow)]
    struct LinkTagRow {
        link_id: String,
        tag_name: String,
    }

    let user_id_q = user.id.clone();
    let since_q: i64 = since;
    let limit_q = limit;

    // Query 1: Get the links
    let rows = handles
        .db
        .run(move |mut db| async move {
            query_as::<DeltaRow>(
                r#"
        SELECT
          l.id,
          l.original_url,
          l.canonical_url,
          l.title,
          l.description,
          l.summary_short,
          l.summary_long,
          l.lang,
          l.save_count,
          l.state,
          l.created_at,
          l.updated_at,
          (SELECT shared_at FROM link_saves ls WHERE ls.link_id = l.id ORDER BY shared_at DESC LIMIT 1) AS shared_at
        FROM links l
        WHERE l.user_id = ? AND l.deleted_at IS NULL AND l.updated_at > ?
        ORDER BY l.updated_at ASC
        LIMIT ?
        "#,
            )
            .bind(&user_id_q)
            .bind(since_q)
            .bind(limit_q)
            .fetch_all(&mut db.conn)
            .await
        })
        .await
        .map_err(|e| {
            AppError::internal(format!("Database error: {}", e))
        })?;

    // Query 2: Get all tags for these links in one batch
    let mut tags_map: HashMap<String, Vec<String>> = HashMap::new();

    if !rows.is_empty() {
        let link_ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
        let placeholders = link_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");

        let tag_query = format!(
            r#"
            SELECT lt.link_id, t.name as tag_name
            FROM link_tags lt
            JOIN tags t ON t.id = lt.tag_id
            WHERE lt.link_id IN ({})
            ORDER BY lt.link_id, t.name ASC
            "#,
            placeholders
        );

        let tag_rows = handles
            .db
            .run(move |mut db| async move {
                let mut q = query_as::<LinkTagRow>(&tag_query);
                for link_id in link_ids {
                    q = q.bind(link_id);
                }
                let result = q.fetch_all(&mut db.conn).await;
                result
            })
            .await
            .map_err(|e| AppError::internal(format!("Database error fetching tags: {}", e)))?;

        // Group tags by link_id
        for tag_row in tag_rows {
            tags_map
                .entry(tag_row.link_id)
                .or_default()
                .push(tag_row.tag_name);
        }
    }

    // Combine links with their tags
    let mut out_links = Vec::with_capacity(rows.len());
    for row in &rows {
        let tags = tags_map.get(&row.id).cloned().unwrap_or_default();

        out_links.push(json!({
            "id": row.id,
            "original_url": row.original_url,
            "canonical_url": row.canonical_url,
            "title": row.title,
            "snippet": row.description,
            "summary_short": row.summary_short,
            "summary_long": row.summary_long,
            "lang": row.lang,
            "tags": tags,
            "save_count": row.save_count,
            "status": row.state,
            "shared_at": row.shared_at,
            "created_at": row.created_at
        }));
    }

    // next_cursor is an i64 (ms)
    let next_cursor: Option<i64> = if (rows.len() as i64) == limit {
        rows.last().map(|r| r.updated_at)
    } else {
        None
    };

    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", "no-store".parse().unwrap());

    Ok((
        StatusCode::OK,
        headers,
        Json(json!({
            "links": out_links,
            "next_cursor": next_cursor
        })),
    ))
}

/// GET /v1/links/compact - list compact records (id, canonical_url, updated_at, state)
pub async fn get_links_compact(
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> AppResult<(StatusCode, HeaderMap, Json<serde_json::Value>)> {
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
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100)
        .min(500);

    let since_i64 = params.get("since").and_then(|s| s.parse::<i64>().ok());

    let mut query_str = String::from(
        r#"
        SELECT id, canonical_url, updated_at, state
        FROM links
        WHERE user_id = ? AND deleted_at IS NULL
        "#,
    );

    if since_i64.is_some() {
        query_str.push_str(" AND updated_at > ?");
    }

    query_str.push_str(" ORDER BY updated_at DESC LIMIT ?");

    let query_str2 = query_str.clone();
    let user_id_q = user.id.clone();
    let rows = handles
        .db
        .run(move |mut db| async move {
            let mut q = query_as::<LinkCompactItem>(&query_str2);
            q = q.bind(&user_id_q);
            if let Some(since_val) = since_i64 {
                q = q.bind(since_val);
            }
            q = q.bind(limit);
            q.fetch_all(&mut db.conn).await
        })
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
