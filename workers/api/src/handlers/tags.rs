use crate::db::Database;
use crate::error::{AppError, AppResult};
use crate::handlers::common::{LinkTagView, TagSummary};
use crate::handlers::users::get_current_user_from_request;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Json,
};
use serde_json::json;
use sqlx_d1::query_as;

/// GET /v1/links/{id}/tags - list tags for a specific link (owned by current user)
pub async fn get_link_tags(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Verify link ownership
    let link_exists = query_as::<(String,)>(
        "SELECT id FROM links WHERE id = ? AND user_id = ? AND state != 'deleted'"
    )
    .bind(&id)
    .bind(&user.id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    if link_exists.is_none() {
        return Err(Box::new(AppError::not_found("Link not found")));
    }

    // Get tags for this link
    let tags = query_as::<LinkTagView>(
        r#"
        SELECT tag_name
        FROM link_tags
        WHERE link_id = ?
        ORDER BY tag_name
        "#
    )
    .bind(&id)
    .fetch_all(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    Ok(Json(json!({
        "link_id": id,
        "tags": tags
    })))
}

/// GET /v1/users/me/tags - aggregate tag counts across user's non-deleted links
pub async fn get_user_tags(
    State(mut db): State<Database>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    let rows = query_as::<TagSummary>(
        r#"
        SELECT lt.tag_name, COUNT(*) as count
        FROM link_tags lt
        INNER JOIN links l ON lt.link_id = l.id
        WHERE l.user_id = ? AND l.state != 'deleted'
        GROUP BY lt.tag_name
        ORDER BY count DESC, lt.tag_name
        "#
    )
    .bind(&user.id)
    .fetch_all(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    Ok(Json(json!({ "tags": rows })))
}