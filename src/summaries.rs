use crate::auth::require_claims;
use crate::db::{get_summary_for_link, DbPool};
use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use uuid::Uuid;

pub async fn latest_summary_for_link(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    axum::extract::Path(link_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    let claims = match require_claims(&headers) {
        Ok(c) => c,
        Err(_) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    match get_summary_for_link(&pool, claims.sub, link_id).await {
        Ok(Some(s)) => Json(s).into_response(),
        Ok(None) => axum::http::StatusCode::NOT_FOUND.into_response(),
        Err(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
