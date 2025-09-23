use crate::error::{AppError, AppResult};
use crate::handlers::common::{LinkListItem, LinkPatchRequest};
use crate::handlers::users::get_current_user_from_request;
use crate::shared_handles::SharedHandles;
use axum::{
    extract::{Extension, Path},
    http::HeaderMap,
    response::Json,
    Json as JsonExtractor,
};
use chrono::Utc;
use serde_json::json;
use sqlx_d1::{query, query_as};

/// GET /v1/links/{id}
pub async fn get_link_by_id(
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
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

    let id_q = id.clone();
    let user_id_q = user.id.clone();
    let link = handles
        .db
        .run(move |mut db| async move {
            query_as::<LinkListItem>(
                r#"
        SELECT id, canonical_url, original_url, state, save_count,
               created_at, updated_at, title, description, site_name, image_url, favicon_url
        FROM links
        WHERE id = ? AND user_id = ? AND state != 'deleted'
        "#,
            )
            .bind(&id_q)
            .bind(&user_id_q)
            .fetch_optional(&mut db.conn)
            .await
        })
        .await
        .map_err(AppError::from)?;

    match link {
        Some(link) => Ok(Json(serde_json::to_value(link).unwrap())),
        None => Err(Box::new(AppError::not_found("Link not found"))),
    }
}

/// PATCH /v1/links/{id} - update metadata fields
pub async fn patch_link_by_id(
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonExtractor(req): JsonExtractor<LinkPatchRequest>,
) -> AppResult<Json<serde_json::Value>> {
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

    // Verify the link belongs to the user
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

    let query_str = format!("UPDATE links SET {} WHERE id = ?", update_fields.join(", "));

    let query_str_c = query_str.clone();
    let bindings_c = bindings.clone();
    handles
        .db
        .run(move |mut db| async move {
            let mut q = query(&query_str_c);
            for b in bindings_c {
                q = q.bind(b);
            }
            q.execute(&mut db.conn).await
        })
        .await
        .map_err(AppError::from)?;

    // Return updated link
    let id_q = id.clone();
    let updated_link = handles
        .db
        .run(move |mut db| async move {
            query_as::<LinkListItem>(
                r#"
        SELECT id, canonical_url, original_url, state, save_count,
               created_at, updated_at, title, description, site_name, image_url, favicon_url
        FROM links
        WHERE id = ?
        "#,
            )
            .bind(&id_q)
            .fetch_one(&mut db.conn)
            .await
        })
        .await
        .map_err(AppError::from)?;

    Ok(Json(serde_json::to_value(updated_link).unwrap()))
}

/// DELETE /v1/links/{id}
pub async fn delete_link_by_id(
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
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

    // Soft delete: set state to 'deleted'
    let id_q = id.clone();
    let user_id_q = user.id.clone();
    let rows_affected = handles
        .db
        .run(move |mut db| async move {
            let res = query(
                "UPDATE links SET state = 'deleted', updated_at = ? WHERE id = ? AND user_id = ? AND state != 'deleted'"
            )
            .bind(Utc::now().to_rfc3339())
            .bind(&id_q)
            .bind(&user_id_q)
            .execute(&mut db.conn)
            .await?;
            Ok::<u64, sqlx_d1::Error>(res.rows_affected as u64)
        })
        .await
        .map_err(AppError::from)?;

    if rows_affected == 0 {
        return Err(Box::new(AppError::not_found("Link not found")));
    }

    Ok(Json(json!({ "success": true, "id": id })))
}
