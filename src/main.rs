use std::net::SocketAddr;

use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

mod attestation;
mod auth;
mod db;
mod links;
mod routes;
mod summaries;
mod tags;
mod users;
mod webauthn;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    // Load .env file if present (ignored in production)
    let _ = dotenvy::dotenv();

    // Logging
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).compact().init();

    info!("hamrah-api starting up...");

    // Database init
    info!("connecting to database...");
    let pool = db::init_pool().await?;
    info!("database connected, running migrations...");
    db::run_migrations(&pool).await?;
    info!("migrations complete");

    // Router
    let app = routes::health_routes()
        .with_state(pool)
        .layer(TraceLayer::new_for_http());

    // Bind address from PORT env or default 8080
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(?addr, "starting server");

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    // Graceful shutdown on SIGTERM for Cloud Run
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    // SIGTERM handling
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install signal handler");
        sigterm.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
