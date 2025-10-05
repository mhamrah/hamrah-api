hamrah-api/workers/api/tests/helpers/mod.rs
```
```hamrah-api/workers/api/tests/helpers/mod.rs#L1-260
//! Test helpers for building a Router with the links endpoints and (optionally) an
//! in-memory database + environment state suitable for unit/integration tests.
//!
//! Notes:
//! - Handlers use `Extension<SharedHandles>` and execute DB work on a single-thread executor.
//! - App Attestation middleware is enforced in production, so tests should include the
//!   provided "bypass" headers (simulator/dev) when exercising authenticated endpoints.

use axum::{
    http::HeaderMap,
    routing::{get, post},
    Extension, Router,
};

use crate::handlers;
use crate::handlers::links::post_links;
use crate::handlers::links_detail::{delete_link_by_id, get_link_by_id, patch_link_by_id};
use crate::handlers::links_list::{get_links, get_links_compact};
use crate::shared_handles::SharedHandles;

/// Build a Router with all routes required for links tests.
///
/// Routes included:
/// - GET /v1/links
/// - POST /v1/links
/// - GET /v1/links/compact
/// - GET /v1/links/{id}
/// - PATCH /v1/links/{id}
/// - DELETE /v1/links/{id}
/// - POST /v1/links/{id}/refresh
/// - GET /v1/links/{id}/tags
/// - GET /v1/users/me/tags
///
/// The router is layered with `Extension(handles)` so handlers can access the
/// single-threaded executors for DB and Env via `SharedHandles`.
pub fn build_links_test_router(handles: SharedHandles) -> Router {
    Router::new()
        .route("/v1/links", get(get_links).post(post_links))
        .route("/v1/links/compact", get(get_links_compact))
        .route(
            "/v1/links/{id}",
            get(get_link_by_id).patch(patch_link_by_id).delete(delete_link_by_id),
        )
        .route("/v1/links/{id}/refresh", post(handlers::post_link_refresh))
        .route("/v1/links/{id}/tags", get(handlers::tags::get_link_tags))
        .route("/v1/users/me/tags", get(handlers::tags::get_user_tags))
        .layer(Extension(handles))
}

/// Provide a baseline set of headers to bypass iOS App Attestation during tests.
///
/// Many tests run in a non-iOS context and should not need full App Attestation. The
/// server-side middleware supports a development bypass. These headers mirror what the
/// native app would send in simulator/dev mode and should keep auth + attestation
/// checks satisfied for unit/integration tests.
pub fn default_attestation_bypass_headers() -> HeaderMap {
    use axum::http::header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, AUTHORIZATION, USER_AGENT};
    use axum::http::HeaderValue;

    let mut headers = HeaderMap::new();

    // Typical client headers
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, br"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("Hamrah/TEST CFNetwork/TEST Darwin/TEST"),
    );

    // iOS dev/simulator bypass signal headers
    headers.insert(
        "x-ios-development",
        HeaderValue::from_static("simulator"), // dev/simulator flag
    );
    headers.insert(
        "x-ios-bundle-id",
        HeaderValue::from_static("app.hamrah.ios"),
    );
    headers.insert("x-ios-app-version", HeaderValue::from_static("1.0"));
    headers.insert(
        "x-request-challenge",
        // Any stable, base64 value is fine for bypass; attestation middleware ignores it in dev.
        HeaderValue::from_static("VEVTVDpCVVlBU1M="),
    );

    headers
}

/// Attach a Bearer token to a header map (mutates in place).
pub fn with_bearer_token(headers: &mut HeaderMap, token: &str) {
    use axum::http::header::AUTHORIZATION;
    use axum::http::HeaderValue;

    let value = format!("Bearer {}", token);
    if let Ok(hv) = HeaderValue::from_str(&value) {
        headers.insert(AUTHORIZATION, hv);
    }
}

/// Convenience for creating a fresh set of test headers with an Authorization token.
pub fn make_auth_headers(token: &str) -> HeaderMap {
    let mut headers = default_attestation_bypass_headers();
    with_bearer_token(&mut headers, token);
    headers
}

/// Build the full application router using the crate's top-level `app_router`, which
/// adds all API routes and any global middleware configured by the server.
///
/// If you want only the minimal set of routes needed for links tests, prefer
/// `build_links_test_router`.
pub fn build_full_app_router(handles: SharedHandles) -> Router {
    crate::app_router(handles)
}

/// Attempt to create an in-memory test `SharedHandles` with a fresh database and environment.
///
/// This helper is enabled only for non-WASM test targets. It expects the crate to expose
/// appropriate constructors for creating a `Database` and `Env` suitable for tests and to
/// run schema migrations before returning handles.
///
/// If your crate already provides a canonical way to create test handles (for example,
/// `SharedHandles::for_tests()` or similar), consider swapping the implementation below
/// to call that directly.
///
/// Important: This function intentionally returns a Result so tests can bubble up any
/// setup errors clearly rather than panic at the call site.
#[cfg(not(target_arch = "wasm32"))]
pub async fn create_in_memory_handles() -> Result<SharedHandles, Box<dyn std::error::Error>> {
    // 1) Create a fresh in-memory database
    //
    // Replace the following line with the actual way your crate constructs an in-memory Database.
    // For example, if you expose `Database::connect_in_memory().await` or similar, use that here.
    //
    // let mut db = crate::db::Database::connect_in_memory().await?;
    //
    // 2) Run migrations for a clean schema
    //
    // use crate::db::migrations::{get_migrations, MigrationRunner};
    // MigrationRunner::new(&mut db).run_migrations(&get_migrations()).await?;
    //
    // 3) Wrap Database + Env in single-thread executors and build SharedHandles
    //
    // use crate::single_thread_executor::SingleThreadExecutor;
    // let db_exec = SingleThreadExecutor::new(db);
    //
    // If you have a dedicated test env type/constructor, use it. Otherwise, create a minimal one.
    // let env = crate::shared_handles::TestEnv::default();
    // let env_exec = SingleThreadExecutor::new(env);
    //
    // Ok(SharedHandles { db: db_exec, env: env_exec })
    //
    // ----
    // If your repository already has a recommended "one-liner" for test handles,
    // call that instead. For example:
    //
    // return Ok(SharedHandles::for_tests().await);
    //
    // ----
    // Fallback: Return a clear error to prompt wiring this helper to your actual constructors.
    Err("create_in_memory_handles is not yet wired to your Database/Env constructors. Replace the commented block with the appropriate calls in your repo.".into())
}
