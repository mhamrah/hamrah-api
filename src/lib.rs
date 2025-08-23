mod auth;
mod db;
mod handlers;

use axum::{
    routing::{get, post, put, delete, patch},
    Router,
    middleware,
    http::HeaderValue,
    extract::FromRef,
};
use tower_service::Service;
use tower_http::cors::{CorsLayer, Any};
use worker::*;
use db::{Database, migrations::{get_migrations, MigrationRunner}};

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
        .route("/api/internal/users", post(handlers::internal::create_user_internal))
        .route("/api/internal/sessions", post(handlers::internal::create_session_internal))
        .route("/api/internal/sessions/validate", post(handlers::internal::validate_session_internal))
        .route("/api/internal/tokens", post(handlers::internal::create_tokens_internal))
        
        // Public endpoints for client-side API access
        .route("/api/auth/sessions/validate", get(handlers::auth::validate_session))
        .route("/api/auth/sessions/logout", post(handlers::auth::logout_session))
        .route("/api/auth/tokens/refresh", post(handlers::auth::refresh_token_endpoint))
        .route("/api/auth/tokens/:token_id/revoke", delete(handlers::auth::revoke_token_endpoint))
        .route("/api/auth/users/:user_id/tokens/revoke", delete(handlers::auth::revoke_all_user_tokens_endpoint))
        
        // User endpoints
        .route("/api/users/me", get(handlers::users::get_current_user))
        .route("/api/users/me", put(handlers::users::update_current_user))
        .route("/api/users/me/tokens", get(handlers::users::get_user_tokens))
        .route("/api/users/me", delete(handlers::users::delete_user_account))
        .route("/api/users/:user_id", get(handlers::users::get_user_by_id))
        
        // WebAuthn endpoints
        .route("/api/webauthn/register/begin", post(handlers::webauthn::begin_registration))
        .route("/api/webauthn/register/complete", post(handlers::webauthn::complete_registration))
        .route("/api/webauthn/authenticate/begin", post(handlers::webauthn::begin_authentication))
        .route("/api/webauthn/authenticate/complete", post(handlers::webauthn::complete_authentication))
        .route("/api/webauthn/credentials", get(handlers::webauthn::get_credentials))
        .route("/api/webauthn/credentials/:credential_id", delete(handlers::webauthn::delete_credential))
        .route("/api/webauthn/credentials/:credential_id", patch(handlers::webauthn::update_credential_name))
        
        .layer(
            CorsLayer::new()
                .allow_origin([
                    "https://hamrah.app".parse::<HeaderValue>().unwrap(),
                    "http://localhost:5173".parse::<HeaderValue>().unwrap(),
                    "http://localhost:3000".parse::<HeaderValue>().unwrap(),
                ])
                .allow_methods(Any)
                .allow_headers(Any)
                .allow_credentials(true)
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
    let db = Database::new(&env).await?;
    
    // Run migrations
    let migration_runner = MigrationRunner::new(&db);
    let migrations = get_migrations();
    migration_runner.run_migrations(&migrations).await
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
