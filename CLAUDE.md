# hamrah-api

A Rust-based HTTP API built with Axum, Tokio, and Prost that serves protobuf-serialized payloads for the hamrah ecosystem.

## Architecture

- **Framework**: Axum (async web framework)
- **Runtime**: Tokio (async runtime)
- **Serialization**: Prost (Protocol Buffers for Rust)
- **Deployment**: Runs as WASM module on Cloudflare Workers

## Purpose

Backend API for hamrah productivity management applications:
- **hamrah-ios**: iOS mobile application
- **hamrah-web**: Web application

Both client applications follow an offline-first approach with AI-enabled productivity management tools.

## Development Commands

```bash
# Build the project
cargo build

# Run tests
cargo test

# Check code formatting
cargo fmt --check

# Run clippy for linting
cargo clippy

# Build for WASM target (for Cloudflare Workers)
cargo build --target wasm32-unknown-unknown --release
```

## Key Technologies

- **Axum**: Web framework for handling HTTP requests
- **Tokio**: Async runtime for concurrent operations
- **Prost**: Protocol Buffers implementation for efficient serialization
- **WASM**: Enables deployment to Cloudflare Workers edge computing platform