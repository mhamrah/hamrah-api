use crate::auth::require_claims;
use crate::db::{list_tags_for_user, set_link_tags, DbPool};
use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use serde::Deserialize;
use uuid::Uuid;

pub async fn list_tags(State(pool): State<DbPool>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match require_claims(&headers) {
        Ok(c) => c,
        Err(_) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    match list_tags_for_user(&pool, claims.sub).await {
        Ok(tags) => Json(tags).into_response(),
        Err(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
pub struct SetTagsRequest {
    pub tags: Vec<String>,
}

pub async fn set_tags_for_link(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    axum::extract::Path(link_id): axum::extract::Path<Uuid>,
    Json(req): Json<SetTagsRequest>,
) -> impl IntoResponse {
    let claims = match require_claims(&headers) {
        Ok(c) => c,
        Err(_) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    match set_link_tags(&pool, claims.sub, link_id, &req.tags).await {
        Ok(()) => axum::http::StatusCode::NO_CONTENT.into_response(),
        Err(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
