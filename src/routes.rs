use crate::attestation;
use crate::auth;
use crate::db::DbPool;
use crate::links;
use crate::summaries;
use crate::tags;
use crate::users;
use axum::response::IntoResponse;
use axum::{
    routing::{get, post},
    Router,
};

pub fn health_routes() -> Router<DbPool> {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/api/auth/native", post(auth::auth_native))
        .route("/api/auth/tokens/refresh", post(auth::auth_refresh))
        .route("/api/auth/tokens/validate", get(auth::auth_validate))
        .route("/api/attestation/challenge", post(attestation::challenge))
        .route("/api/attestation/verify", post(attestation::verify_attestation))
        .route("/api/attestation/assert", post(attestation::verify_assertion))
        .route("/v1/links", get(links::list_links).post(links::create_link))
        .route("/v1/users/me", get(users::me))
        .route("/v1/tags", get(tags::list_tags))
        .route(
            "/v1/links/:id/summary",
            get(summaries::latest_summary_for_link),
        )
        .route("/v1/links/:id/tags", post(tags::set_tags_for_link))
}

async fn health() -> impl IntoResponse {
    "ok"
}

async fn ready() -> impl IntoResponse {
    "ready"
}

// Auth handlers moved to src/auth.rs
