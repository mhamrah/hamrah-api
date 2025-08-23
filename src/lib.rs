mod auth;
mod db;
mod handlers;

use axum::{
    routing::{get, post, put, delete},
    Router,
    middleware,
    http::HeaderValue,
};
use tower_service::Service;
use tower_http::cors::{CorsLayer, Any};
use worker::*;
use db::{Database, migrations::{get_migrations, MigrationRunner}};

fn app_router(db: Database, env: Env) -> Router {
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
        .with_state(db)
        .with_state(env)
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
    
    Ok(app_router(db, env).call(req).await?)
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
