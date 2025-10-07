# hamrah-api

Backend API for the Hamrah apps on iOS, macOS, and the web. Designed for an offline-first experience on Apple platforms, with AI-powered content organization and summarization at the edge.

## Long-term Architecture

- Core: Rust (Axum, SQLx) native server deployed on Cloud Run
- Auth: JWT access/refresh tokens, sessions, and WebAuthn passkeys
- Data: Postgres/SQLx (Neon), designed to sync with local-first stores on iOS/macOS
- Access:
  - External API: https://api.hamrah.app (mobile and external clients)

See “agents and architecture” for more detail: ./agents.md

## Key Capabilities

- Organize a user’s content, notes, and research with native integrations on iOS and macOS
- Save articles and URLs: fetch, summarize, and enrich them using AI; persist summaries for offline access
- Foundation for intelligent organization (classification, tagging, clustering) and semantic retrieval
- Roadmap: reminders, lists, and notes management; surface relevant content on demand

## AI Services

- AI for summarization and retrieval augmentation
- Privacy by design: scoped credentials, minimal data sharing, and secure processing

## Database

This project uses [SQLx](https://github.com/launchbadge/sqlx) for compile-time checked SQL queries and database migrations. SQLx provides:

- **Compile-time verification** of SQL queries against your database schema
- **Type-safe** database interactions
- **Built-in migration management** with versioning
- **Async/await** support with Tokio

### Migration Strategy

Migrations follow the pattern: `{version}_{description}.sql`

- **Version**: Timestamp format `YYYYMMDDhhmmss` (e.g., `20250101000000`)
- **Description**: Snake_case description of the migration (e.g., `initial_schema`)

Example: `20250101000000_initial_schema.sql`

Migrations are executed in lexicographical order based on filename. The timestamp-based versioning ensures chronological execution.

**Current migrations:**
1. `20250101000000_initial_schema.sql` - Core user and session tables
2. `20250101000001_links_and_tags.sql` - Link management, tags, and summaries

### Running Migrations

#### Automatic Migration (Production)

Migrations run automatically on application startup via `db::run_migrations()` in `main.rs`:

```rust
let pool = db::init_pool().await?;
db::run_migrations(&pool).await?;
```

This ensures the database schema is always up-to-date when the application starts.

#### Manual Migration (Development)

Using the SQLx CLI:

```bash
# Install SQLx CLI if not already installed
cargo install sqlx-cli --no-default-features --features postgres

# Run pending migrations
sqlx migrate run --database-url $DATABASE_URL

# Revert last migration
sqlx migrate revert --database-url $DATABASE_URL

# Check migration status
sqlx migrate info --database-url $DATABASE_URL
```

### Creating New Migrations

#### Step 1: Create Migration File

```bash
# Using SQLx CLI (recommended)
sqlx migrate add <description>

# Or manually create file with timestamp
touch migrations/$(date +%Y%m%d%H%M%S)_<description>.sql
```

#### Step 2: Write Migration SQL

Write your SQL migration in the created file:

```sql
-- Description of what this migration does

CREATE TABLE example (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_example_name ON example(name);
```

#### Step 3: Test Migration

```bash
# Run migration
sqlx migrate run --database-url $DATABASE_URL

# Verify schema
psql $DATABASE_URL -c "\dt"
```

#### Step 4: Update Rust Models

Ensure your Rust structs in `src/db.rs` match the new schema:

```rust
#[derive(sqlx::FromRow, Clone)]
pub struct Example {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<Utc>,
}
```

### Best Practices

#### 1. Never Modify Existing Migrations

Once a migration is committed and deployed, **never modify it**. Always create a new migration to alter the schema.

**Bad:**
```sql
-- Editing 20250101000000_initial_schema.sql after deployment
ALTER TABLE users ADD COLUMN age INTEGER; -- DON'T DO THIS
```

**Good:**
```sql
-- Creating new migration 20250105120000_add_user_age.sql
ALTER TABLE users ADD COLUMN age INTEGER;
```

#### 2. Make Migrations Reversible When Possible

While SQLx doesn't automatically handle reversions (down migrations), document how to reverse changes in comments:

```sql
-- Add user avatar column
-- To revert: ALTER TABLE users DROP COLUMN avatar_url;

ALTER TABLE users ADD COLUMN avatar_url TEXT;
```

#### 3. Use Transactions Implicitly

SQLx runs each migration file in a transaction by default, ensuring atomicity.

#### 4. Include Indexes

Always add relevant indexes for foreign keys and frequently queried columns:

```sql
CREATE TABLE posts (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_posts_user_id ON posts(user_id);
CREATE INDEX idx_posts_created_at ON posts(created_at DESC);
```

#### 5. Use PostgreSQL-Specific Features

Take advantage of PostgreSQL features:

```sql
-- Use TIMESTAMPTZ instead of TIMESTAMP
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()

-- Use UUID instead of TEXT
id UUID PRIMARY KEY

-- Use CHECK constraints for validation
state TEXT NOT NULL CHECK (state IN ('new', 'processing', 'ready', 'failed'))
```

#### 6. Document Your Migrations

Include comments explaining what and why:

```sql
-- Add link processing state machine
-- States: new -> processing -> ready/failed
-- This allows tracking link processing progress

ALTER TABLE links ADD COLUMN state TEXT NOT NULL DEFAULT 'new';
```

### Schema Verification

#### Compile-Time Checks

SQLx verifies queries at compile time. To enable this:

1. Set `DATABASE_URL` environment variable
2. Run `cargo build` - SQLx will check queries against your database

```bash
export DATABASE_URL=postgres://user:pass@localhost/hamrah
cargo build
```

#### Offline Mode (CI/CD)

For CI/CD without database access:

```bash
# Prepare cached query metadata
cargo sqlx prepare

# Build using cached metadata
cargo build
```

This creates `.sqlx/` directory with query metadata for offline compilation.

### Database Setup

#### Local Development

```bash
# Start PostgreSQL (Docker)
docker run --name hamrah-postgres \
  -e POSTGRES_PASSWORD=dev \
  -e POSTGRES_DB=hamrah \
  -p 5432:5432 \
  -d postgres:16

# Set DATABASE_URL
export DATABASE_URL=postgres://postgres:dev@localhost:5432/hamrah

# Run migrations
cd server && cargo run
```

#### Production

Set `DATABASE_URL` environment variable pointing to your PostgreSQL instance. Migrations run automatically on startup.

### Troubleshooting

#### Migration Failed Mid-Way

If a migration fails, SQLx's transaction handling means partial changes are rolled back. Fix the SQL and retry.

#### Schema Drift

If manual changes were made to the database:

```bash
# Check current migration state
sqlx migrate info --database-url $DATABASE_URL

# If needed, mark specific migrations as applied
# (Be careful with this)
sqlx migrate run --database-url $DATABASE_URL
```

#### Type Mismatches

If you see compile errors about type mismatches:

1. Verify migration matches Rust struct
2. Check that PostgreSQL types map correctly:
   - `UUID` ↔ `uuid::Uuid`
   - `TEXT` ↔ `String`
   - `TIMESTAMPTZ` ↔ `chrono::DateTime<Utc>`
   - `INTEGER` ↔ `i32`
   - `BIGINT` ↔ `i64`

### Migration History

| Version | Date | Description |
|---------|------|-------------|
| 20250101000000 | 2025-01-01 | Initial schema: users and sessions |
| 20250101000001 | 2025-01-01 | Links, tags, and summaries |

### Resources

- [SQLx Documentation](https://github.com/launchbadge/sqlx)
- [SQLx CLI Guide](https://github.com/launchbadge/sqlx/tree/main/sqlx-cli)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)

## Links

- Detailed architecture and AI agents: ./agents.md
- License: ./LICENSE
