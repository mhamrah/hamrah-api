# Auth Migration Guide: hamrah-web to hamrah-api

This guide outlines the complete migration of authentication functionality from the TypeScript/Drizzle-based hamrah-web project to a standalone Rust-based hamrah-api project.

## Migration Overview

The auth system has been completely moved to a standalone API with:
- **Standalone Database**: hamrah-api owns the auth database completely
- **SQLx Integration**: Type-safe, asynchronous database operations
- **Rust API**: All auth logic in Rust for performance and type safety
- **Secure by Default**: HttpOnly, Secure cookies with proper SameSite settings
- **OAuth Integration**: Direct provider token verification (Google, Apple)
- **Dual Auth Methods**: Sessions for web, tokens for mobile/API
- **Migration System**: SQLx-based migration system

## Database Schema

The Rust implementation maintains the same database schema as the original TypeScript version:

### Tables Created
- `users` - User accounts and profile information
- `sessions` - Web session management
- `auth_tokens` - API tokens for mobile/native apps
- `webauthn_credentials` - WebAuthn/Passkey credentials
- `webauthn_challenges` - Temporary challenges for WebAuthn flows
- `migrations` - Migration tracking (similar to Drizzle)

## Migration System (SQLx-based)

### How it Works
```rust
// Migrations use SQLx for type-safe, transactional operations
pub struct InitialMigration;

impl Migration for InitialMigration {
    fn version(&self) -> &'static str { "001" }
    fn name(&self) -> &'static str { "initial_schema" }
    fn up(&self) -> &'static str { "CREATE TABLE ..." }
    fn down(&self) -> &'static str { "DROP TABLE ..." }
}

// Migrations run automatically on startup with transaction safety
let migration_runner = MigrationRunner::new(&db);
let migrations = get_migrations();
migration_runner.run_migrations(&migrations).await?;
```

### Key Benefits of SQLx
- **Type Safety**: Compile-time checked SQL queries
- **Async**: Non-blocking database operations
- **Transactions**: Atomic migration application
- **Row Mapping**: Automatic struct deserialization with `FromRow`

### Adding New Migrations
1. Create a new struct implementing `Migration` trait
2. Add to `get_migrations()` function in `src/db/migrations.rs`
3. Increment version number (e.g., "002", "003", etc.)
4. Provide both `up()` and `down()` SQL statements
5. Test with `sqlx migrate` commands

## API Endpoints

### OAuth Authentication Endpoints

#### Native App Authentication (iOS/Android)
```
POST /api/auth/native
{
  "provider": "google" | "apple",
  "credential": "id_token_from_provider",
  "email": "optional@example.com", // For Apple privacy mode
  "name": "Optional Name",
  "platform": "ios" | "android" | "api"
}
```
Returns access_token, refresh_token, and user info

#### Web App Authentication
```
POST /api/auth/web
{
  "provider": "google" | "apple",
  "credential": "id_token_from_provider"
}
```
Returns session cookie (HttpOnly, Secure, SameSite=Lax) and user info

### Session Management

#### Validate Session
```
GET /api/auth/sessions/validate
Cookie: session=token
```

#### Logout
```
POST /api/auth/sessions/logout
```
Clears session cookie

### Token Management

#### Refresh Token
```
POST /api/auth/tokens/refresh
{
  "refresh_token": "token"
}
```

#### Revoke Token
```
DELETE /api/auth/tokens/:token_id/revoke
```

#### Revoke All User Tokens
```
DELETE /api/auth/users/:user_id/tokens/revoke
```

### User Management Endpoints

#### Get Current User
```
GET /api/users/me
Authorization: Bearer <token>
// OR
Cookie: session=<session_token>
```

#### Update User Profile
```
PUT /api/users/me
{
  "name": "New Name",
  "picture": "https://new-pic.jpg"
}
```

#### Get User Tokens
```
GET /api/users/me/tokens
```
Lists all active tokens for the user

#### Delete Account
```
DELETE /api/users/me
```

## Security Best Practices Implemented

### Cookie Security
- **HttpOnly**: Prevents XSS attacks
- **Secure**: HTTPS-only transmission
- **SameSite=Lax**: CSRF protection while allowing reasonable cross-site usage
- **Path=/**: Scoped to entire domain
- **Expiry**: 30-day sessions with automatic extension

### Token Security
- **SHA-256 Hashing**: All tokens stored as hashes
- **Short Expiry**: Access tokens expire in 1 hour
- **Refresh Tokens**: 30-day refresh tokens for long-term access
- **Revocation**: Individual token and bulk user token revocation
- **Platform Tracking**: Track tokens by platform (web, ios, android, api)

### Input Validation
- Email validation for user creation
- UUID validation for user IDs
- Token format validation
- SQL injection prevention through parameterized queries

### Rate Limiting Ready
- User-agent and IP tracking for rate limiting implementation
- Platform detection for different limits per platform type

## Complete hamrah-web Removal

### Remove All Database Access
1. **Remove Drizzle**: Delete `drizzle.config.ts`, `drizzle/` directory
2. **Remove Database Bindings**: Remove D1 database binding from `wrangler.jsonc`
3. **Delete Auth Files**: Remove `src/lib/db/` and `src/lib/auth/` directories
4. **Update Dependencies**: Remove `drizzle-orm` and related packages

### Replace with API Calls
hamrah-web becomes a pure frontend that calls hamrah-api:

```typescript
// OAuth flow in hamrah-web (frontend only)
const handleGoogleSignIn = async (credential: string) => {
  const response = await fetch('https://api.hamrah.app/api/auth/web', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include', // Important for cookies
    body: JSON.stringify({ 
      provider: 'google', 
      credential 
    })
  });
  
  if (response.ok) {
    // User is now authenticated with session cookie
    window.location.href = '/dashboard';
  }
};
```

### Session Validation
```typescript
// Client-side session validation
const validateSession = async () => {
  const response = await fetch('https://api.hamrah.app/api/auth/sessions/validate', {
    credentials: 'include'
  });
  
  return response.ok ? await response.json() : null;
};

// Server-side session validation (Qwik server functions)
export const validateServerSession = async (sessionCookie?: string) => {
  if (!sessionCookie) return null;
  
  const response = await fetch('https://api.hamrah.app/api/auth/sessions/validate', {
    headers: { 'Cookie': `session=${sessionCookie}` }
  });
  
  return response.ok ? await response.json() : null;
};
```

## Cross-Domain Cookie Management

### Domain Configuration
- **Web App**: `hamrah.app`
- **API**: `api.hamrah.app`
- **Cookie Domain**: `.hamrah.app` (with leading dot for subdomain sharing)

### How It Works
```rust
// API sets cookies with domain: .hamrah.app
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax; Domain=.hamrah.app; Path=/
```

This allows the session cookie to be:
1. **Set by**: `api.hamrah.app` (when user authenticates)
2. **Sent to**: Both `hamrah.app` and `api.hamrah.app` automatically
3. **Shared across**: All `*.hamrah.app` subdomains

### CORS Configuration
```rust
CorsLayer::new()
    .allow_origin([
        "https://hamrah.app",
        "http://localhost:5173", // Development
    ])
    .allow_credentials(true) // Required for cookies
```

### Frontend Requirements
All API calls from hamrah.app must include:
```typescript
fetch('https://api.hamrah.app/api/...', {
  credentials: 'include' // Sends cookies with cross-origin requests
})
```

### Environment Handling
The API automatically detects the environment:
- **Production**: Uses `.hamrah.app` domain for cookie sharing
- **Development**: No domain restriction for localhost testing

## Mobile App Integration

### iOS App Setup
```swift
// Native auth flow
let authRequest = AuthRequest(
    provider: "apple",
    credential: idToken,
    email: email,
    name: name
)

let response = try await apiClient.post("/api/auth/tokens", body: authRequest)
```

### Token Storage
- Store access_token and refresh_token securely (Keychain on iOS)
- Include `Authorization: Bearer <token>` header in API calls
- Refresh tokens before expiry using `/api/auth/tokens/refresh`

## Environment Variables

Required in wrangler.toml:
```toml
[vars]
GOOGLE_CLIENT_ID = "your-client-id"
APPLE_CLIENT_ID = "your-app-id"
APPLE_TEAM_ID = "your-team-id" 
APPLE_KEY_ID = "your-key-id"
NODE_ENV = "production"
```

## Deployment

### Build and Deploy
```bash
# Install dependencies
cargo install -q worker-build

# Build for Cloudflare Workers
worker-build --release

# Deploy
wrangler deploy
```

### Database Setup
The migration system runs automatically on deployment, creating all necessary tables and indexes.

## Monitoring and Maintenance

### Token Cleanup
Implement periodic cleanup of expired tokens:
```rust
// Call periodically (e.g., daily cron job)
tokens::cleanup_expired_tokens(&db).await?;
```

### Health Check
```
GET /health
```
Returns API status and version

## Migration Checklist

### hamrah-api (Rust API)
- [x] SQLx integration for type-safe database operations
- [x] Database schema with FromRow derives
- [x] Migration system implemented with transactions
- [x] OAuth provider verification (Google, Apple)
- [x] Session management with secure cookies
- [x] Token management for mobile apps
- [x] User CRUD operations
- [x] Security best practices implemented
- [x] CORS configuration for web integration
- [x] Health monitoring endpoint

### hamrah-web (Frontend Cleanup)
- [ ] Remove all database dependencies (Drizzle, D1)
- [ ] Remove auth service files
- [ ] Replace auth logic with API calls
- [ ] Add server-side helper functions (see QWIK_HELPERS.md)
- [ ] Update OAuth flows to use API endpoints
- [ ] Update middleware to use server-side API validation
- [ ] Update route loaders to fetch data server-side
- [ ] Test session cookie handling across domains

### Deployment
- [ ] Create separate D1 database for hamrah-api
- [ ] Deploy hamrah-api to production
- [ ] Update environment variables
- [ ] Test cross-origin cookie handling
- [ ] Implement token cleanup cron job

### Mobile Apps
- [ ] Update iOS app to use `/api/auth/native` endpoint
- [ ] Update token storage and refresh logic
- [ ] Test Apple Sign-In integration
- [ ] Update Android app (if applicable)

## Integration Files Created

1. **`SERVER_INTEGRATION.md`** - Complete guide for server-to-server communication patterns
2. **`QWIK_HELPERS.md`** - Ready-to-use TypeScript helper functions for hamrah-web
3. **`MIGRATION_GUIDE.md`** - This comprehensive migration guide

These files provide everything needed to successfully integrate hamrah.app with hamrah-api while maintaining security and performance best practices.