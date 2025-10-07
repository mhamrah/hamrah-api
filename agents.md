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

- Rust-based backend API running natively with Axum and Tokio (no WASM)
- Framework: Axum (Rust async web framework)
- Database: Postgres (Neon) with SQLx for async operations and compile-time checked queries
- Runtime/Deployment: Cloud Run (containerized native binary)
- Workflow Engine: Server-side jobs and/or Cloud Run Workflows (future)
- Auth: JWT access/refresh tokens, session tokens, and WebAuthn passkeys
- Clients:
  - iOS/macOS apps with offline-first data model and background sync
  - Web app (hamrah.app) via internal service bindings
- CORS: Restricted to authorized origins
- Rate Limiting: At Cloudflare edge

### Components

1) API Server (Rust)
- Endpoint handling (auth, users, tokens, WebAuthn)
- Data access (SQLx, Postgres)
- JWT/session lifecycle
- Internal service endpoints for web app and services

2) Link Pipeline (Server-side)
- Ingests URLs and content
- Orchestrates AI summarization (AI provider agnostic)
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
  - Uses the same API via internal service bindings or direct Cloud Run ingress

---

## AI Agents

- URL Summarization Agent
  - Fetches content from URLs
- Summarizes via AI provider
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
- AI runs with scoped credentials in the server or Cloud Run jobs
- No user secrets are embedded in models
- Only necessary data is passed to the AI provider

---

## API Deployment

- External API: https://api.hamrah.app (mobile and external clients)
- Internal API: Service binding from hamrah.app (web)

## Security

- Internal Service Authentication: X-Internal-Service, X-Internal-Key headers
- iOS App Attestation for native clients
- JWT Token Management: Short-lived access + refresh rotation
- WebAuthn: Passwordless auth
- CORS: Restricted origins
- Rate Limiting: Cloudflare edge

---

## Development Notes

- Always run `cargo fmt` after saving a file or making a change.
- Always run `cargo clippy -- -D warnings` to catch lints before committing code.
