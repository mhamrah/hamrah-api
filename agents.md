# hamrah-api Architecture and Agents

This document describes the long-term architecture for hamrah-api and the agents that power AI features.

Summary
- Backend API for Hamrah on iOS, macOS, and Web.
- Designed for offline-first on iOS and macOS: local-first storage, resilient sync, and conflict handling.
- Organizes user content, notes, and research, integrating with native Apple features and powered by Cloudflare AI.
- Saves and summarizes articles/URLs for offline reading and later retrieval.
- Roadmap includes reminders, lists, notes, and proactive surfacing of relevant content on demand.

---

## System Architecture

- Framework: Axum (Rust async web framework)
- Database: SQLite with SQLx for async operations
- Runtime/Deployment: Cloudflare Workers (WASM for Rust)
- Workflow Engine: Cloudflare Workflows powering the link pipeline worker (TypeScript)
- Auth: JWT access/refresh tokens, session tokens, and WebAuthn passkeys
- Clients:
  - iOS/macOS apps with offline-first data model and background sync
  - Web app (hamrah.app) via internal service bindings
- CORS: Restricted to authorized origins
- Rate Limiting: At Cloudflare edge

### Components

1) API Worker (Rust)
- Endpoint handling (auth, users, tokens, WebAuthn)
- Data access (SQLx, SQLite)
- JWT/session lifecycle
- Internal service endpoints for web app and services

2) Link Pipeline Worker (TypeScript)
- Ingests URLs and content
- Orchestrates AI summarization (Cloudflare AI)
- Normalizes and persists summaries for offline access
- Future: classify, tag, cluster content for retrieval

---

## Platforms and Offline-First Design

- iOS and macOS:
  - Local-first data store for notes, links, summaries, and metadata
  - Background sync with the API worker using durable, incremental updates
  - Conflict detection via versioning/timestamps and server reconciliation
  - Offline persistence for AI-generated summaries and extracted content
  - Native integrations (e.g., share extensions, system services, Spotlight/Shortcuts where applicable)

- Web:
  - Uses the same API, with internal service bindings from hamrah.app to hamrah-api

---

## AI Agents (Cloudflare AI)

- URL Summarization Agent
  - Fetches content from URLs
  - Summarizes via Cloudflare AI
  - Extracts key insights/metadata (title, authors, topics, entities)
  - Stores summary and metadata for offline access

- Organization/Context Agent (Roadmap)
  - Classifies and tags content and notes
  - Clusters related items and builds navigable contexts
  - Suggests related material on demand

- Reminders/Recall Agent (Roadmap)
  - Manages reminders, lists, and notes
  - Surfaces relevant content when asked (query-driven recall)
  - Leverages embeddings and metadata for semantic retrieval

Privacy & Security
- AI runs with scoped credentials via Cloudflare Workers
- No user secrets are embedded in models
- Only necessary data is passed to the AI provider

---

## API Deployment

- External API: https://api.hamrah.app (mobile and external clients)
- Internal API: Service binding from hamrah.app (web)

---

## API Endpoints

Internal (service-to-service)
- POST /api/internal/users — Create users
- POST /api/internal/sessions — Create web sessions
- POST /api/internal/tokens — Create API tokens for mobile
- POST /api/internal/sessions/validate — Validate session tokens

Public Authentication
- GET /api/auth/sessions/validate — Validate session
- GET /api/auth/tokens/validate — Validate access token (Bearer) and return validity/expiry metadata
- POST /api/auth/sessions/logout — Logout session
- POST /api/auth/tokens/refresh — Refresh access token
- DELETE /api/auth/tokens/:token_id/revoke — Revoke specific token
- DELETE /api/auth/users/:user_id/tokens/revoke — Revoke all user tokens

WebAuthn Passkeys
- POST /api/webauthn/register/begin — Start registration
- POST /api/webauthn/register/complete — Complete registration
- POST /api/webauthn/authenticate/begin — Start authentication
- POST /api/webauthn/authenticate/complete — Complete authentication
- GET /api/webauthn/credentials — List passkeys
- DELETE /api/webauthn/credentials/:id — Delete passkey
- PATCH /api/webauthn/credentials/:id — Rename passkey

User Management
- GET /api/users/me — Current user info
- PUT /api/users/me — Update user info
- DELETE /api/users/me — Delete account
- GET /api/users/me/tokens — List active tokens
- GET /api/users/:user_id — Get user by ID

### Authentication Endpoint Details

- GET /api/auth/tokens/validate
  - Purpose: Lightweight validation of Bearer access token without fetching user profile
  - Auth: Authorization: Bearer <access_token>
  - Success (200): { success: true, valid: true, userId, platform, accessExpiresAt, expiresIn }
  - Failure (401): Unauthorized when token is missing, invalid, expired, or revoked
  - Notes: Does not rotate tokens and does not return user profile; prefer GET /api/users/me when user data is needed

---

## Database Schema (Conceptual)

- Users: Account profile and identity provider fields
- Sessions: Web sessions with expiration
- Auth Tokens: Access/refresh tokens for mobile/web
- WebAuthn:
  - webauthn_credentials: Registered passkeys
  - webauthn_challenges: Ephemeral challenges

---

## Security

- Internal Service Authentication: X-Internal-Service, X-Internal-Key headers
- iOS App Attestation for native clients
- JWT Token Management: Short-lived access + refresh rotation
- WebAuthn: Passwordless auth
- CORS: Restricted origins
- Rate Limiting: Cloudflare edge

---

## Roadmap

- Comprehensive offline note/link search with embeddings
- Intelligent lists and reminders
- Proactive recall: surface relevant content upon user query
- Enhanced sync diffing for large offline datasets
- Cross-device continuity and secure backup/restore

---

## Development Notes

- Always run formatters before committing and after edits.
- Rust: cargo fmt / clippy / test
- TS: type-check / build / test
