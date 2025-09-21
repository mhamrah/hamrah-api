use crate::db::Database;
use crate::error::{AppError, AppResult};
use crate::handlers::common::{ArchiveInfo, ArchiveRow};
use crate::handlers::users::get_current_user_from_request;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use serde_json::json;
use sqlx_d1::query_as;

/// HEAD /v1/links/{id}/archive
pub async fn head_link_archive(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Check if link exists and belongs to user
    let link = query_as::<ArchiveInfo>(
        "SELECT id, canonical_url FROM links WHERE id = ? AND user_id = ? AND state != 'deleted'"
    )
    .bind(&id)
    .bind(&user.id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    let _link = match link {
        Some(l) => l,
        None => return Err(Box::new(AppError::not_found("Link not found"))),
    };

    // Check if archive exists
    let archive = query_as::<ArchiveRow>(
        "SELECT archive_path, archive_size_bytes FROM links WHERE id = ?"
    )
    .bind(&id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    match archive {
        Some(row) if row.archive_path.is_some() => {
            let mut headers = HeaderMap::new();
            if let Some(size) = row.archive_size_bytes {
                headers.insert("Content-Length", HeaderValue::from_str(&size.to_string()).unwrap());
            }
            headers.insert("Content-Type", HeaderValue::from_static("text/html"));
            Ok((StatusCode::OK, headers))
        }
        _ => Err(Box::new(AppError::not_found("Archive not available"))),
    }
}

/// GET /v1/links/{id}/archive
pub async fn get_link_archive(
    State(mut db): State<Database>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    let user = get_current_user_from_request(&mut db, &headers).await?;

    // Check if link exists and belongs to user
    let link = query_as::<ArchiveInfo>(
        "SELECT id, canonical_url FROM links WHERE id = ? AND user_id = ? AND state != 'deleted'"
    )
    .bind(&id)
    .bind(&user.id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    let link = match link {
        Some(l) => l,
        None => return Err(Box::new(AppError::not_found("Link not found"))),
    };

    // Check if archive exists
    let archive = query_as::<ArchiveRow>(
        "SELECT archive_path, archive_size_bytes FROM links WHERE id = ?"
    )
    .bind(&id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| AppError::from(e))?;

    match archive {
        Some(row) if row.archive_path.is_some() => {
            // For now, return metadata about the archive
            // In a full implementation, this would serve the actual archived content
            let mut headers = HeaderMap::new();
            headers.insert("Content-Type", HeaderValue::from_static("application/json"));

            Ok((
                StatusCode::OK,
                headers,
                json!({
                    "id": id,
                    "canonical_url": link.canonical_url,
                    "archive_path": row.archive_path,
                    "archive_size_bytes": row.archive_size_bytes,
                    "message": "Archive content would be served here"
                }).to_string()
            ))
        }
        _ => Err(Box::new(AppError::not_found("Archive not available"))),
    }
}