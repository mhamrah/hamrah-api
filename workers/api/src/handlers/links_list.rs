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

    let since = params
        .get("since")
        .cloned()
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

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
        created_at: String,
        updated_at: String,
        shared_at: Option<String>,
    }

    #[derive(sqlx::FromRow)]
    struct TagRow {
        name: String,
    }

    let user_id_q = user.id.clone();
    let since_q = since.clone();
    let limit_q = limit;
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
          (SELECT MAX(shared_at) FROM link_saves ls WHERE ls.link_id = l.id) AS shared_at
        FROM links l
        WHERE l.user_id = ? AND l.deleted_at IS NULL AND l.updated_at > ?
        ORDER BY l.updated_at ASC
        LIMIT ?
        "#,
            )
            .bind(&user_id_q)
            .bind(&since_q)
            .bind(limit_q)
            .fetch_all(&mut db.conn)
            .await
        })
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    let mut out_links = Vec::with_capacity(rows.len());
    for row in &rows {
        let row_id_q = row.id.clone();
        let tag_rows = handles
            .db
            .run(move |mut db| async move {
                query_as::<TagRow>(
                    r#"
            SELECT t.name as name
            FROM link_tags lt
            JOIN tags t ON t.id = lt.tag_id
            WHERE lt.link_id = ?
            ORDER BY t.name ASC
            "#,
                )
                .bind(&row_id_q)
                .fetch_all(&mut db.conn)
                .await
            })
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        let tags: Vec<String> = tag_rows.into_iter().map(|t| t.name).collect();

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

    let next_cursor = if (rows.len() as i64) == limit {
        rows.last().map(|r| r.updated_at.clone())
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

    let query_str2 = query_str.clone();
    let bindings2 = bindings.clone();
    let rows = handles
        .db
        .run(move |mut db| async move {
            let mut q = query_as::<LinkCompactItem>(&query_str2);
            for b in bindings2 {
                q = q.bind(b);
            }
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
