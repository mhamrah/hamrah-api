# syntax=docker/dockerfile:1.7

# -------- Builder stage --------
FROM rust:1.90-slim AS builder
WORKDIR /app

# Install build deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Set cargo environment variables
ENV SQLX_OFFLINE=true

# Copy manifest first for caching
COPY Cargo.toml Cargo.toml

# Create dummy src to build deps
RUN mkdir -p src && echo "fn main(){}" > src/main.rs

# Fetch deps
RUN cargo build --release || true

# Copy real source
COPY src src
COPY migrations migrations

# Build release binary
RUN cargo build --release

# -------- Runtime stage (debian-slim for debugging) --------
FROM debian:12-slim
WORKDIR /app

# Install runtime deps (OpenSSL, CA certs)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary with explicit permissions
COPY --from=builder --chmod=0755 /app/target/release/hamrah-server /app/server

# Verify binary can load (check for missing libs) - do this as root before switching users
RUN ldd /app/server || echo "ldd failed but continuing..."

ENV RUST_LOG=info
ENV PORT=8080
EXPOSE 8080

# Create non-root user
RUN useradd -m -u 1000 appuser
USER appuser

# Test that binary is executable
RUN /app/server --version 2>&1 || echo "Binary test failed - this is expected if --version not supported"

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/bin/sh", "-c", "wget -q --spider http://localhost:8080/healthz || exit 1"]

# Run the server - using exec form for proper signal handling
CMD ["/app/server"]
