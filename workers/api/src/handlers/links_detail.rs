use crate::db::Database;
use crate::error::{AppError, AppResult};
use crate::handlers::common::{LinkListItem, LinkPatchRequest};
use crate::handlers::users::get_current_user_from_request;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Json,
    Json as JsonExtractor,
};
use chrono::Utc;
use serde_json::json;
use sqlx_d1::{query, query_as};

/// GET /v1/links/{id}
pub async fn get_link_by_id(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    let link = query_as::<LinkListItem>(
        r#"
        SELECT id, canonical_url, original_url, state, save_count,
               created_at, updated_at, title, description, site_name, image_url, favicon_url
        FROM links
        WHERE id = ? AND user_id = ? AND state != 'deleted'
        "#,
    )
    .bind(&id)
    .bind(&user.id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    match link {
        Some(link) => Ok(Json(serde_json::to_value(link).unwrap())),
        None => Err(Box::new(AppError::not_found("Link not found"))),
    }
}

/// PATCH /v1/links/{id} - update metadata fields
pub async fn patch_link_by_id(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonExtractor(req): JsonExtractor<LinkPatchRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Verify the link belongs to the user
    let link_exists = query_as::<(String,)>(
        "SELECT id FROM links WHERE id = ? AND user_id = ? AND state != 'deleted'",
    )
    .bind(&id)
    .bind(&user.id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    if link_exists.is_none() {
        return Err(Box::new(AppError::not_found("Link not found")));
    }

    // Build dynamic update query
    let mut update_fields = Vec::new();
    let mut bindings = Vec::new();

    if let Some(title) = req.title {
        update_fields.push("title = ?");
        bindings.push(title);
    }
    if let Some(description) = req.description {
        update_fields.push("description = ?");
        bindings.push(description);
    }
    if let Some(site_name) = req.site_name {
        update_fields.push("site_name = ?");
        bindings.push(site_name);
    }
    if let Some(image_url) = req.image_url {
        update_fields.push("image_url = ?");
        bindings.push(image_url);
    }
    if let Some(favicon_url) = req.favicon_url {
        update_fields.push("favicon_url = ?");
        bindings.push(favicon_url);
    }
    if let Some(state) = req.state {
        update_fields.push("state = ?");
        bindings.push(state);
    }

    if update_fields.is_empty() {
        return Err(Box::new(AppError::bad_request("No fields to update")));
    }

    update_fields.push("updated_at = ?");
    bindings.push(Utc::now().to_rfc3339());
    bindings.push(id.clone());

    let query_str = format!(
        "UPDATE links SET {} WHERE id = ?",
        update_fields.join(", ")
    );

    let mut query = query(&query_str);
    for binding in bindings {
        query = query.bind(binding);
    }

    query
        .execute(&mut db.conn)
        .await
        .map_err(|e| AppError::from(e))?;

    // Return updated link
    let updated_link = query_as::<LinkListItem>(
        r#"
        SELECT id, canonical_url, original_url, state, save_count,
               created_at, updated_at, title, description, site_name, image_url, favicon_url
        FROM links
        WHERE id = ?
        "#,
    )
    .bind(&id)
    .fetch_one(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    Ok(Json(serde_json::to_value(updated_link).unwrap()))
}

/// DELETE /v1/links/{id}
pub async fn delete_link_by_id(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Soft delete: set state to 'deleted'
    let result = query(
        "UPDATE links SET state = 'deleted', updated_at = ? WHERE id = ? AND user_id = ? AND state != 'deleted'"
    )
    .bind(Utc::now().to_rfc3339())
    .bind(&id)
    .bind(&user.id)
    .execute(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    let rows_affected = result.rows_affected;

    if rows_affected == 0 {
        return Err(Box::new(AppError::not_found("Link not found")));
    }

    Ok(Json(json!({ "success": true, "id": id })))
}