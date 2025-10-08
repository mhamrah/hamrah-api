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
    // Print to stdout immediately to verify container is starting
    println!("Starting hamrah-api...");

    // Load .env file if present (ignored in production)
    let _ = dotenvy::dotenv();

    // Logging - use JSON format for Cloud Run, pretty format for local dev
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Detect if running in Cloud Run (has K_SERVICE env var)
    if std::env::var("K_SERVICE").is_ok() {
        // Cloud Run: use JSON format for proper log parsing
        fmt()
            .with_env_filter(filter)
            .json()
            .with_target(false)
            .with_current_span(false)
            .init();
    } else {
        // Local dev: use pretty format
        fmt()
            .with_env_filter(filter)
            .compact()
            .init();
    }

    info!("=================================================");
    info!("🚀 hamrah-api starting up");
    info!("   Version: {}", env!("CARGO_PKG_VERSION"));
    info!("   Rust: {}", env!("CARGO_PKG_RUST_VERSION").unwrap_or("unknown"));
    info!("=================================================")

    // Database init
    info!("📊 Connecting to database...");
    let pool = db::init_pool().await?;
    info!("✓ Database connected successfully");

    info!("🔄 Running database migrations...");
    db::run_migrations(&pool).await?;
    info!("✓ Migrations complete");

    // Router with state
    info!("🔧 Setting up routes and middleware...");
    let app = routes::create_router(pool).layer(TraceLayer::new_for_http());
    info!("✓ Router configured");

    // Bind address from PORT env or default 8080
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!("🌐 Binding to {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("✓ Successfully bound to {}", addr);

    info!("=================================================");
    info!("✅ Server is ready and listening on port {}", port);
    info!("   Health check: http://0.0.0.0:{}/healthz", port);
    info!("   Ready check: http://0.0.0.0:{}/readyz", port);
    info!("=================================================");

    // Graceful shutdown on SIGTERM for Cloud Run
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("🛑 Server shutting down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    use tracing::warn;

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
        _ = ctrl_c => {
            warn!("📡 Received Ctrl+C signal");
        },
        _ = terminate => {
            warn!("📡 Received SIGTERM signal");
        },
    }

    warn!("⏳ Initiating graceful shutdown...");
}
