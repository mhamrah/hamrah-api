use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::require_claims;
use crate::db::DbPool;

#[derive(Serialize, sqlx::FromRow)]
pub struct Link {
    pub id: Uuid,
    pub user_id: Uuid,
    pub url: String,
    pub title: Option<String>,
    pub state: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
pub struct CreateLinkRequest {
    pub url: String,
    pub title: Option<String>,
}

pub async fn list_links(State(pool): State<DbPool>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match require_claims(&headers) {
        Ok(c) => c,
        Err(_) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    let links = sqlx::query_as!(
        Link,
        r#"SELECT id, user_id, url, title, state, created_at FROM links WHERE user_id = $1 ORDER BY created_at DESC"#,
        claims.sub
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_default();
    Json(links).into_response()
}

pub async fn create_link(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Json(req): Json<CreateLinkRequest>,
) -> impl IntoResponse {
    let claims = match require_claims(&headers) {
        Ok(c) => c,
        Err(_) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    let id = Uuid::new_v4();
    let link = sqlx::query_as!(
        Link,
        r#"INSERT INTO links (id, user_id, url, title, state)
           VALUES ($1, $2, $3, $4, 'new')
           RETURNING id, user_id, url, title, state, created_at"#,
        id,
        claims.sub,
        req.url,
        req.title
    )
    .fetch_one(&pool)
    .await;
    match link {
        Ok(l) => (axum::http::StatusCode::CREATED, Json(l)).into_response(),
        Err(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
