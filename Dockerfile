FROM rust:1.90-slim AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y pkg-config libssl-dev
ENV SQLX_OFFLINE=true

COPY Cargo.toml Cargo.toml
COPY src src
COPY .sqlx .sqlx
COPY migrations migrations

# Build release binary
RUN cargo build --release

# Create non-root user
RUN useradd -m -u 1000 appuser
USER appuser

CMD ["/app/target/release/hamrah-server"]
