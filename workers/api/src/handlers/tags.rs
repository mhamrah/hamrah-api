use crate::error::{AppError, AppResult};
use crate::handlers::common::{LinkTagView, TagSummary};
use crate::handlers::users::get_current_user_from_request;
use crate::shared_handles::SharedHandles;
use axum::{extract::Path, http::HeaderMap, response::Json};
use serde_json::json;
use sqlx_d1::query_as;

/// GET /v1/links/{id}/tags - list tags for a specific link (owned by current user)
pub async fn get_link_tags(
    axum::extract::Extension(handles): axum::extract::Extension<SharedHandles>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    // Build owned headers to avoid borrowing across await points
    let header_pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();

    // Authenticate current user through executor
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

    // Verify link ownership
    let id_q = id.clone();
    let user_id_q = user.id.clone();
    let link_exists = handles
        .db
        .run(move |mut db| async move {
            query_as::<(String,)>(
                "SELECT id FROM links WHERE id = ? AND user_id = ? AND state != 'deleted'",
            )
            .bind(&id_q)
            .bind(&user_id_q)
            .fetch_optional(&mut db.conn)
            .await
        })
        .await
        .map_err(AppError::from)?;

    if link_exists.is_none() {
        return Err(Box::new(AppError::not_found("Link not found")));
    }

    // Get tags for this link
    let id_q2 = id.clone();
    let tags = handles
        .db
        .run(move |mut db| async move {
            query_as::<LinkTagView>(
                r#"
        SELECT tag_name
        FROM link_tags
        WHERE link_id = ?
        ORDER BY tag_name
        "#,
            )
            .bind(&id_q2)
            .fetch_all(&mut db.conn)
            .await
        })
        .await
        .map_err(AppError::from)?;

    Ok(Json(json!({
        "link_id": id,
        "tags": tags
    })))
}

/// GET /v1/users/me/tags - aggregate tag counts across user's non-deleted links
pub async fn get_user_tags(
    axum::extract::Extension(handles): axum::extract::Extension<SharedHandles>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    // Build owned headers to avoid borrowing across await points
    let header_pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();

    // Authenticate current user via executor
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

    // Aggregate tag counts for this user
    let user_id_q = user.id.clone();
    let rows = handles
        .db
        .run(move |mut db| async move {
            query_as::<TagSummary>(
                r#"
        SELECT lt.tag_name, COUNT(*) as count
        FROM link_tags lt
        INNER JOIN links l ON lt.link_id = l.id
        WHERE l.user_id = ? AND l.state != 'deleted'
        GROUP BY lt.tag_name
        ORDER BY count DESC, lt.tag_name
        "#,
            )
            .bind(&user_id_q)
            .fetch_all(&mut db.conn)
            .await
        })
        .await
        .map_err(AppError::from)?;

    Ok(Json(json!({ "tags": rows })))
}
