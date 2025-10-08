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

pub fn health_routes() -> Router<DbPool> {
    // Initialize WebAuthn config
    let rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let rp_origin = std::env::var("WEBAUTHN_RP_ORIGIN")
        .unwrap_or_else(|_| "https://localhost:5173".to_string());

    let webauthn_config = Arc::new(
        webauthn::WebAuthnConfig::new(&rp_id, &rp_origin)
            .expect("Failed to create WebAuthn config"),
    );

    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/api/auth/native", post(auth::auth_native))
        .route("/api/auth/tokens/refresh", post(auth::auth_refresh))
        .route("/api/auth/tokens/validate", get(auth::auth_validate))
        .route("/api/attestation/challenge", post(attestation::challenge))
        .route(
            "/api/attestation/verify",
            post(attestation::verify_attestation),
        )
        .route(
            "/api/attestation/assert",
            post(attestation::verify_assertion),
        )
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
            "/api/webauthn/challenges/:id",
            get(webauthn::get_challenge_handler),
        )
        .route(
            "/api/webauthn/challenges/:id",
            delete(webauthn::delete_challenge_handler),
        )
        // WebAuthn credential management
        .route(
            "/api/webauthn/credentials",
            post(webauthn::create_credential_handler),
        )
        .route(
            "/api/webauthn/credentials/:id",
            get(webauthn::get_credential_handler),
        )
        .route(
            "/api/webauthn/credentials/:id",
            delete(webauthn::delete_credential_handler),
        )
        .route(
            "/api/webauthn/credentials/:id/counter",
            patch(webauthn::update_credential_counter_handler),
        )
        .route(
            "/api/webauthn/users/:user_id/credentials",
            get(webauthn::get_user_credentials_handler),
        )
        // Existing routes
        .route("/v1/links", get(links::list_links).post(links::create_link))
        .route("/v1/users/me", get(users::me))
        .route("/v1/tags", get(tags::list_tags))
        .route(
            "/v1/links/:id/summary",
            get(summaries::latest_summary_for_link),
        )
        .route("/v1/links/:id/tags", post(tags::set_tags_for_link))
        .layer(axum::extract::Extension(webauthn_config))
}

async fn health() -> impl IntoResponse {
    "ok"
}

async fn ready() -> impl IntoResponse {
    "ready"
}

// Auth handlers moved to src/auth.rs
