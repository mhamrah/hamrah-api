# hamrah-api

A Rust-based HTTP API built with Axum and SQLx that provides secure authentication and user management for the hamrah ecosystem.

## Architecture

- **Framework**: Axum (async web framework)
- **Database**: SQLite with SQLx for async database operations
- **Authentication**: JWT tokens, sessions, and WebAuthn passkeys
- **Deployment**: Runs as WASM module on Cloudflare Workers
- **CORS**: Configured for web and mobile clients

## Purpose

Backend API for hamrah productivity management applications:
- **hamrah-ios**: iOS mobile application with App Attestation (calls api.hamrah.app directly)
- **hamrah-app**: Web application (Qwik-based) deployed at hamrah.app (uses internal service bindings to hamrah-api)

The API handles all database operations and provides secure authentication endpoints for both platforms.

### API Deployment
- **External API**: `https://api.hamrah.app` - Used by mobile apps and external clients
- **Internal API**: Service binding communication from hamrah.app web application

## API Endpoints

### Internal Service Endpoints (service-to-service only)
- `POST /api/internal/users` - Create users via internal service
- `POST /api/internal/sessions` - Create web sessions
- `POST /api/internal/tokens` - Create API tokens for mobile
- `POST /api/internal/sessions/validate` - Validate session tokens

### Public Authentication Endpoints
- `GET /api/auth/sessions/validate` - Validate session
- `POST /api/auth/sessions/logout` - Logout session
- `POST /api/auth/tokens/refresh` - Refresh access token
- `DELETE /api/auth/tokens/:token_id/revoke` - Revoke specific token
- `DELETE /api/auth/users/:user_id/tokens/revoke` - Revoke all user tokens

### WebAuthn Passkey Endpoints
- `POST /api/webauthn/register/begin` - Start passkey registration
- `POST /api/webauthn/register/complete` - Complete passkey registration
- `POST /api/webauthn/authenticate/begin` - Start passkey authentication
- `POST /api/webauthn/authenticate/complete` - Complete passkey authentication
- `GET /api/webauthn/credentials` - List user's passkeys
- `DELETE /api/webauthn/credentials/:id` - Delete passkey
- `PATCH /api/webauthn/credentials/:id` - Rename passkey

### User Management Endpoints
- `GET /api/users/me` - Get current user info
- `PUT /api/users/me` - Update user info
- `DELETE /api/users/me` - Delete user account
- `GET /api/users/me/tokens` - List user's active tokens
- `GET /api/users/:user_id` - Get user by ID

## Development Commands

```bash
# Build the project (requires cargo in PATH or use full path)
/Users/mhamrah/.cargo/bin/cargo build

# Run tests
/Users/mhamrah/.cargo/bin/cargo test

# Check code formatting
/Users/mhamrah/.cargo/bin/cargo fmt --check

# Run clippy for linting
/Users/mhamrah/.cargo/bin/cargo clippy

# Build for WASM target (for Cloudflare Workers)
/Users/mhamrah/.cargo/bin/cargo build --target wasm32-unknown-unknown --release
```

## Key Technologies

- **Axum**: Web framework for HTTP request handling
- **SQLx**: Async SQL toolkit for database operations
- **WebAuthn-RS**: WebAuthn implementation for passkey authentication
- **Chrono**: Date and time handling
- **UUID**: Unique identifier generation
- **Base64/Base32**: Encoding for tokens and challenges
- **Tower-HTTP**: HTTP middleware (CORS, etc.)
- **Worker**: Cloudflare Workers runtime integration

## Database Schema

### Users Table
Stores user account information with OAuth provider details.

### Sessions Table  
Manages web application session tokens with expiration.

### Auth Tokens Table
Handles API access/refresh tokens for mobile applications with platform tracking.

### WebAuthn Tables
- `webauthn_credentials`: Stores registered passkeys
- `webauthn_challenges`: Temporary challenge storage for WebAuthn flows

## Security Features

- **Internal Service Authentication**: X-Internal-Service and X-Internal-Key headers
- **iOS App Attestation**: Validates authentic iOS client requests  
- **JWT Token Management**: Secure access/refresh token pairs
- **WebAuthn Support**: Passwordless authentication with passkeys
- **CORS Configuration**: Restricted to authorized origins
- **Rate Limiting**: Implemented at Cloudflare level