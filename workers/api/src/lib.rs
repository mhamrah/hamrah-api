//! # Hamrah API - Rust Worker
//!
//! A Rust-based HTTP API built with Axum and SQLx that provides secure authentication
//! and user management for the hamrah ecosystem. Runs as WASM on Cloudflare Workers.
//!
//! ## Current API Endpoints
//!
//! ### Basic Endpoints
//! - `GET /` - Root endpoint returning "Hamrah API v1.0"
//! - `GET /health` - Health check endpoint returning JSON status
//! - `GET /api/test` - Test endpoint returning "Hamrah API v1.0"
//! - `GET /api/status` - API status endpoint with operational information
//!
//! ### Future Endpoints (To Be Implemented)
//! - `POST /api/internal/users` - Create user (internal service-to-service)
//! - `POST /api/internal/sessions` - Create session (internal)
//! - `POST /api/internal/tokens` - Create tokens (internal)
//! - `POST /api/internal/sessions/validate` - Validate session (internal)
//! - `POST /api/internal/check-user-by-email` - Check user by email (internal)
//! - `GET /v1/links` - Get user links
//! - `POST /v1/links` - Create new links
//! - `GET /v1/links/compact` - Get compact link list
//! - `GET /v1/links/:id` - Get specific link
//! - `PATCH /v1/links/:id` - Update link
//! - `DELETE /v1/links/:id` - Delete link
//! - `POST /v1/links/:id/refresh` - Refresh link
//! - `GET /v1/links/:id/archive` - Get link archive
//! - `HEAD /v1/links/:id/archive` - Check link archive
//! - `POST /v1/push/register` - Register push token
//! - `GET /v1/user/prefs` - Get user preferences
//! - `PUT /v1/user/prefs` - Update user preferences
//! - `GET /v1/models` - Get available AI models from Cloudflare AI platform
//! - WebAuthn endpoints for passkey authentication
//! - Auth endpoints for session and token management
//! - User management endpoints
//!
//! ## Architecture
//! - Uses stateless routing with middleware for state injection
//! - Database operations via SQLx with D1 integration
//! - Authentication via JWT tokens and WebAuthn passkeys
//! - CORS configured for web and mobile clients

pub mod auth;
pub mod db;
pub mod error;
pub mod handlers;
pub mod pipeline_shim;
pub mod utils;

use axum::{
    extract::FromRef,
    http::HeaderValue,
    routing::{delete, get, patch, post, put},
    Router,
};
use db::{
    migrations::{get_migrations, MigrationRunner},
    Database,
};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::Method;

use axum::middleware;
use tower_http::cors::CorsLayer;
use tower_service::Service;

use worker::*;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub env: Env,
}

impl FromRef<AppState> for Database {
    fn from_ref(state: &AppState) -> Database {
        state.db.clone()
    }
}

impl FromRef<AppState> for Env {
    fn from_ref(state: &AppState) -> Env {
        state.env.clone()
    }
}

pub fn app_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        // Internal service endpoints (service-to-service only)
        .route(
            "/api/internal/users",
            post(handlers::internal::create_user_internal),
        )
        .route(
            "/api/internal/sessions",
            post(handlers::internal::create_session_internal),
        )
        .route(
            "/api/internal/sessions/validate",
            post(handlers::internal::validate_session_internal),
        )
        .route(
            "/api/internal/users/by-email",
            post(handlers::internal::check_user_by_email_internal),
        )
        // --- v1 Links Pipeline Endpoints ---
        .route("/v1/links", get(handlers::links_list::get_links).post(handlers::links::post_links))
        .route("/v1/links/compact", get(handlers::links_list::get_links_compact))
        .route(
            "/v1/links/:id",
            get(handlers::links_detail::get_link_by_id)
                .patch(handlers::links_detail::patch_link_by_id)
                .delete(handlers::links_detail::delete_link_by_id),
        )
        .route(
            "/v1/links/:id/archive",
            get(handlers::links_archive::get_link_archive).head(handlers::links_archive::head_link_archive),
        )
        // .route("/v1/links/:id/refresh", post(handlers::post_link_refresh))
        .route("/v1/push/register", post(handlers::push::post_push_register))
        .route(
            "/v1/user/prefs",
            get(handlers::user_prefs::get_user_prefs).put(handlers::user_prefs::put_user_prefs),
        )
        .route("/v1/links/:id/tags", get(handlers::tags::get_link_tags))
        .route("/v1/users/me/tags", get(handlers::tags::get_user_tags))
        .route("/v1/summary/config", get(handlers::get_summary_config))
        .route("/v1/models", get(handlers::models::get_models))
        .route(
            "/api/internal/tokens",
            post(handlers::internal::create_tokens_internal),
        )
        // Public endpoints for client-side API access
        .route(
            "/api/auth/native",
            post(handlers::auth::native_auth_endpoint),
        )
        // App Attestation endpoints
        .route(
            "/api/app-attestation/challenge",
            post(handlers::auth::app_attestation_challenge),
        )
        .route(
            "/api/app-attestation/verify",
            post(handlers::auth::app_attestation_verify),
        )
        .route(
            "/api/auth/sessions/validate",
            get(handlers::auth::validate_session),
        )
        .route(
            "/api/auth/sessions/logout",
            post(handlers::auth::logout_session),
        )
        .route(
            "/api/auth/tokens/refresh",
            post(handlers::auth::refresh_token_endpoint),
        )
        .route(
            "/api/auth/tokens/{token_id}/revoke",
            delete(handlers::auth::revoke_token_endpoint),
        )
        .route(
            "/api/auth/users/{user_id}/tokens/revoke",
            delete(handlers::auth::revoke_all_user_tokens_endpoint),
        )
        // User endpoints
        .route("/api/users/me", get(handlers::users::get_current_user))
        .route("/api/users/me", put(handlers::users::update_current_user))
        .route(
            "/api/users/me/tokens",
            get(handlers::users::get_user_tokens),
        )
        .route(
            "/api/users/me",
            delete(handlers::users::delete_user_account),
        )
        .route("/api/users/{user_id}", get(handlers::users::get_user_by_id))
        // WebAuthn data persistence endpoints (called by hamrah-web)
        .route(
            "/api/webauthn/credentials",
            post(handlers::webauthn_data::store_webauthn_credential),
        )
        .route(
            "/api/webauthn/credentials/{credential_id}",
            get(handlers::webauthn_data::get_webauthn_credential),
        )
        .route(
            "/api/webauthn/credentials/{credential_id}",
            delete(handlers::webauthn_data::delete_webauthn_credential),
        )
        .route(
            "/api/webauthn/credentials/{credential_id}/counter",
            patch(handlers::webauthn_data::update_webauthn_credential_counter),
        )
        .route(
            "/api/webauthn/credentials/{credential_id}/name",
            patch(handlers::webauthn_data::update_webauthn_credential_name),
        )
        .route(
            "/api/webauthn/users/{user_id}/credentials",
            get(handlers::webauthn_data::get_user_webauthn_credentials),
        )
        .route(
            "/api/webauthn/challenges",
            post(handlers::webauthn_data::store_webauthn_challenge),
        )
        .route(
            "/api/webauthn/challenges/{challenge_id}",
            get(handlers::webauthn_data::get_webauthn_challenge),
        )
        .route(
            "/api/webauthn/challenges/{challenge_id}",
            delete(handlers::webauthn_data::delete_webauthn_challenge),
        )
        .layer(
            CorsLayer::new()
                .allow_origin([
                    "https://hamrah.app".parse::<HeaderValue>().unwrap(),
                    "https://localhost:5173".parse::<HeaderValue>().unwrap(),
                ])
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::DELETE,
                    Method::PATCH,
                ])
                .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT])
                .allow_credentials(true),
        )
        .fallback(not_found_fallback)
        .with_state(state)
}

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();

    // Initialize database
    let mut db = Database::new(&env).await?;

    // Run migrations
    let mut migration_runner = MigrationRunner::new(&mut db);
    let migrations = get_migrations();
    migration_runner
        .run_migrations(&migrations)
        .await
        .map_err(|e| worker::Error::from(format!("Migration failed: {}", e)))?;

    // Create application state
    let state = AppState { db, env };

    // Create router with state injection middleware
    use axum::routing::get;
    let mut router = Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .route("/api/test", get(root))
        .route("/api/status", get(api_status))
        .fallback(not_found_fallback)
        .layer(middleware::from_fn(move |req, next| {
            inject_state(req, next, state.clone())
        }));

    // Call the router
    Ok(router.call(req).await?)
}

pub async fn root() -> &'static str {
    "Hamrah API v1.0"
}

// Middleware to inject AppState into request extensions
async fn inject_state(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
    state: AppState,
) -> axum::response::Response {
    req.extensions_mut().insert(state);
    next.run(req).await
}

// Simple API endpoint that uses injected state
pub async fn api_status(
    req: axum::extract::Request,
) -> axum::response::Result<axum::Json<serde_json::Value>> {
    // Extract state from request extensions (optional for testing)
    let _state = req.extensions().get::<AppState>();

    // Return status even if state is not available (for testing)
    Ok(axum::Json(serde_json::json!({
        "status": "operational",
        "database": if _state.is_some() { "connected" } else { "test_mode" },
        "environment": "cloudflare_workers",
        "version": "1.0.0",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

pub async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": "1.0.0"
    }))
}

// JSON 404 fallback for unknown routes
async fn not_found_fallback() -> impl axum::response::IntoResponse {
    crate::error::AppError::not_found("Route not found")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use serde_json::Value;

    #[tokio::test]
    async fn test_app_error_envelopes_table() {
        let cases: Vec<(crate::error::AppError, StatusCode, &str)> = vec![
            (
                crate::error::AppError::not_found("x"),
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                crate::error::AppError::unauthorized("nope"),
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            ),
            (
                crate::error::AppError::conflict("dup"),
                StatusCode::CONFLICT,
                "conflict",
            ),
            (
                crate::error::AppError::bad_request("bad"),
                StatusCode::BAD_REQUEST,
                "bad_request",
            ),
            (
                crate::error::AppError::internal("err"),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ];

        for (err, status, code) in cases {
            let resp = err.into_response();
            assert_eq!(resp.status(), status);

            let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["error"]["code"], code);
            assert!(v["error"]["message"].is_string());
        }
    }

    #[tokio::test]
    async fn test_json_404_fallback() {
        let resp = not_found_fallback().await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["code"], "not_found");
        assert_eq!(v["error"]["message"], "Route not found");
    }
}
