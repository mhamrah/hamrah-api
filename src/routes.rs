use crate::attestation;
use crate::auth;
use crate::db::DbPool;
use crate::links;
use crate::summaries;
use crate::tags;
use crate::users;
use crate::webauthn;
use axum::response::IntoResponse;
use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use std::sync::Arc;

pub type AppState = (DbPool, Arc<webauthn::WebAuthnConfig>);

// Wrapper handlers that extract pool from tuple state for existing handlers
async fn auth_native_wrapper(
    axum::extract::State((pool, _)): axum::extract::State<AppState>,
    json: axum::Json<auth::NativeLoginRequest>,
) -> impl IntoResponse {
    auth::auth_native(axum::extract::State(pool), json).await
}

async fn auth_refresh_wrapper(
    axum::extract::State((pool, _)): axum::extract::State<AppState>,
    json: axum::Json<auth::RefreshRequest>,
) -> impl IntoResponse {
    auth::auth_refresh(axum::extract::State(pool), json).await
}

async fn auth_validate_wrapper(headers: axum::http::HeaderMap) -> impl IntoResponse {
    auth::auth_validate(headers).await
}

async fn attestation_challenge_wrapper(
    axum::extract::State((pool, _)): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    json: axum::Json<attestation::AttestationChallengeRequest>,
) -> impl IntoResponse {
    attestation::challenge(axum::extract::State(pool), headers, json).await
}

async fn attestation_verify_wrapper(
    axum::extract::State((pool, _)): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    json: axum::Json<attestation::AttestationVerifyRequest>,
) -> impl IntoResponse {
    attestation::verify_attestation(axum::extract::State(pool), headers, json).await
}

async fn attestation_assert_wrapper(
    axum::extract::State((pool, _)): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    json: axum::Json<attestation::AssertionRequest>,
) -> impl IntoResponse {
    attestation::verify_assertion(axum::extract::State(pool), headers, json).await
}

async fn list_links_wrapper(
    axum::extract::State((pool, _)): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    links::list_links(axum::extract::State(pool), headers).await
}

async fn create_link_wrapper(
    axum::extract::State((pool, _)): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    json: axum::Json<links::CreateLinkRequest>,
) -> impl IntoResponse {
    links::create_link(axum::extract::State(pool), headers, json).await
}

async fn me_wrapper(
    axum::extract::State((pool, _)): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    users::me(axum::extract::State(pool), headers).await
}

async fn list_tags_wrapper(
    axum::extract::State((pool, _)): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    tags::list_tags(axum::extract::State(pool), headers).await
}

async fn latest_summary_for_link_wrapper(
    axum::extract::State((pool, _)): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    path: axum::extract::Path<uuid::Uuid>,
) -> impl IntoResponse {
    summaries::latest_summary_for_link(axum::extract::State(pool), headers, path).await
}

async fn set_tags_for_link_wrapper(
    axum::extract::State((pool, _)): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    path: axum::extract::Path<uuid::Uuid>,
    json: axum::Json<tags::SetTagsRequest>,
) -> impl IntoResponse {
    tags::set_tags_for_link(axum::extract::State(pool), headers, path, json).await
}

pub fn create_router(pool: DbPool) -> Router {
    // Initialize WebAuthn config
    let rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let rp_origin = std::env::var("WEBAUTHN_RP_ORIGIN")
        .unwrap_or_else(|_| "https://localhost:5173".to_string());

    let webauthn_config = Arc::new(
        webauthn::WebAuthnConfig::new(&rp_id, &rp_origin)
            .expect("Failed to create WebAuthn config"),
    );

    let state: AppState = (pool, webauthn_config);

    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/api/auth/native", post(auth_native_wrapper))
        .route("/api/auth/tokens/refresh", post(auth_refresh_wrapper))
        .route("/api/auth/tokens/validate", get(auth_validate_wrapper))
        .route(
            "/api/attestation/challenge",
            post(attestation_challenge_wrapper),
        )
        .route("/api/attestation/verify", post(attestation_verify_wrapper))
        .route("/api/attestation/assert", post(attestation_assert_wrapper))
        // WebAuthn routes
        .route(
            "/api/webauthn/register/begin",
            post(webauthn::register_begin),
        )
        .route(
            "/api/webauthn/register/verify",
            post(webauthn::register_verify),
        )
        .route(
            "/api/webauthn/authenticate/discoverable",
            post(webauthn::authenticate_begin),
        )
        .route(
            "/api/webauthn/authenticate/discoverable/verify",
            post(webauthn::authenticate_verify),
        )
        // WebAuthn challenge management
        .route(
            "/api/webauthn/challenges",
            post(webauthn::create_challenge_handler),
        )
        .route(
            "/api/webauthn/challenges/{id}",
            get(webauthn::get_challenge_handler),
        )
        .route(
            "/api/webauthn/challenges/{id}",
            delete(webauthn::delete_challenge_handler),
        )
        // WebAuthn credential management
        .route(
            "/api/webauthn/credentials",
            post(webauthn::create_credential_handler),
        )
        .route(
            "/api/webauthn/credentials/{id}",
            get(webauthn::get_credential_handler),
        )
        .route(
            "/api/webauthn/credentials/{id}",
            delete(webauthn::delete_credential_handler),
        )
        .route(
            "/api/webauthn/credentials/{id}/counter",
            patch(webauthn::update_credential_counter_handler),
        )
        .route(
            "/api/webauthn/users/{user_id}/credentials",
            get(webauthn::get_user_credentials_handler),
        )
        // Existing routes
        .route(
            "/v1/links",
            get(list_links_wrapper).post(create_link_wrapper),
        )
        .route("/v1/users/me", get(me_wrapper))
        .route("/v1/tags", get(list_tags_wrapper))
        .route(
            "/v1/links/{id}/summary",
            get(latest_summary_for_link_wrapper),
        )
        .route("/v1/links/{id}/tags", post(set_tags_for_link_wrapper))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    "ok"
}

async fn ready() -> impl IntoResponse {
    "ready"
}

// Auth handlers moved to src/auth.rs
