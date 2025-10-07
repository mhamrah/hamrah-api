use crate::auth::require_claims;
use crate::db::{get_user_by_id, DbPool, User};
use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};

pub async fn me(State(pool): State<DbPool>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match require_claims(&headers) {
        Ok(c) => c,
        Err(_) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    match get_user_by_id(&pool, claims.sub).await {
        Ok(Some(u)) => Json(u).into_response(),
        Ok(None) => axum::http::StatusCode::NOT_FOUND.into_response(),
        Err(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
