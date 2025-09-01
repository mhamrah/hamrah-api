pub mod auth;
pub mod db;
pub mod handlers;
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
use tower_http::cors::{Any, CorsLayer};
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

fn app_router(state: AppState) -> Router {
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
            "/api/internal/tokens",
            post(handlers::internal::create_tokens_internal),
        )
        // Public endpoints for client-side API access
        .route(
            "/api/auth/native",
            post(handlers::auth::native_auth_endpoint),
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
        .route(
            "/api/users/by-email/{email}",
            get(handlers::webauthn_data::get_user_by_email),
        )
        .layer(
            CorsLayer::new()
                .allow_origin([
                    "https://hamrah.app".parse::<HeaderValue>().unwrap(),
                    "https://localhost:5173".parse::<HeaderValue>().unwrap(),
                ])
                .allow_methods(Any)
                .allow_headers(Any)
                .allow_credentials(true),
        )
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

    let state = AppState { db, env };
    Ok(app_router(state).call(req).await?)
}

pub async fn root() -> &'static str {
    "Hamrah API v1.0"
}

pub async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": "1.0.0"
    }))
}
