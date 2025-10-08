# syntax=docker/dockerfile:1.7

# -------- Builder stage --------
FROM rust:1.90-slim AS builder
WORKDIR /app

# Install build deps
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy manifest first for caching
COPY Cargo.toml Cargo.toml

# Create dummy src to build deps
RUN mkdir -p src && echo "fn main(){}" > src/main.rs

# Fetch deps
ENV SQLX_OFFLINE=true
RUN cargo build --release || true

# Copy real source
COPY src src
COPY migrations migrations

# Build release binary
RUN cargo build --release

# -------- Runtime stage (debian-slim for debugging) --------
FROM debian:12-slim
WORKDIR /app

# Install runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy binary with explicit permissions
COPY --from=builder --chmod=0755 /app/target/release/hamrah-server /app/server

ENV RUST_LOG=info
EXPOSE 8080

# Create non-root user
RUN useradd -m -u 1000 appuser
USER appuser

CMD ["/app/server"]
