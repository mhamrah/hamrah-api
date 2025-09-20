# hamrah-api

Backend API for the Hamrah apps on iOS, macOS, and the web. Designed for an offline-first experience on Apple platforms, with AI-powered content organization and summarization at the edge.

## Long-term Architecture

- Core: Rust (Axum, SQLx) compiled to WASM and deployed on Cloudflare Workers
- Workflow engine: TypeScript worker (Cloudflare Workflows) for link ingestion and processing
- Auth: JWT access/refresh tokens, sessions, and WebAuthn passkeys
- Data: SQLite/SQLx (with D1 on Workers), designed to sync with local-first stores on iOS/macOS
- Access:
  - External API: https://api.hamrah.app (mobile and external clients)
  - Internal API: service binding from hamrah.app (web)

See “agents and architecture” for more detail: ./agents.md

## Platform Scope

- iOS and macOS apps: offline-first, local-first storage with resilient background sync and conflict handling
- Web app: integrates through internal service bindings to the same API

## Key Capabilities

- Organize a user’s content, notes, and research with native integrations on iOS and macOS
- Save articles and URLs; fetch, summarize, and enrich them using Cloudflare AI; persist summaries for offline access
- Foundation for intelligent organization (classification, tagging, clustering) and semantic retrieval
- Roadmap: reminders, lists, and notes management; surface relevant content on demand

## AI at the Edge

- Cloudflare AI for summarization and retrieval augmentation
- Privacy by design: scoped credentials, minimal data sharing, and secure processing at the edge

## Links

- Detailed architecture and AI agents: ./agents.md
- License: ./LICENSE
