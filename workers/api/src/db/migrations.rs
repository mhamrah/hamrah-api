use crate::db::Database;
use sqlx_d1::query;

// Use D1 error type for WASM
type SqlError = sqlx_d1::Error;

pub trait Migration {
    fn up(&self) -> &'static str;
    fn down(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn name(&self) -> &'static str;
}

pub struct MigrationRunner<'a> {
    db: &'a mut Database,
}

impl<'a> MigrationRunner<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub async fn run_migrations(&mut self, migrations: &[&dyn Migration]) -> Result<(), SqlError> {
        // Create migrations table if it doesn't exist
        self.ensure_migrations_table().await?;

        for &migration in migrations {
            if !self.is_migration_applied(migration.version()).await? {
                self.apply_migration(migration).await?;
            }
        }
        Ok(())
    }

    async fn ensure_migrations_table(&mut self) -> Result<(), SqlError> {
        query(
            r#"
            CREATE TABLE IF NOT EXISTS migrations (
                version TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at INTEGER NOT NULL
            );
        "#,
        )
        .execute(&mut self.db.conn)
        .await?;
        Ok(())
    }

    async fn is_migration_applied(&mut self, version: &str) -> Result<bool, SqlError> {
        let result = query("SELECT version FROM migrations WHERE version = ?")
            .bind(version)
            .fetch_optional(&mut self.db.conn)
            .await?;
        Ok(result.is_some())
    }

    async fn apply_migration(&mut self, migration: &dyn Migration) -> Result<(), SqlError> {
        // Run the migration
        query(migration.up()).execute(&mut self.db.conn).await?;

        // Record that we applied it
        let now = chrono::Utc::now().timestamp_millis();
        query("INSERT INTO migrations (version, name, applied_at) VALUES (?, ?, ?)")
            .bind(migration.version())
            .bind(migration.name())
            .bind(now)
            .execute(&mut self.db.conn)
            .await?;

        Ok(())
    }
}

/// Single initial migration that creates the entire schema with:
/// - INTEGER timestamps everywhere (ms since epoch)
/// - Soft delete via deleted_at INTEGER (nullable) where applicable
/// - Necessary unique constraints
/// - Sensible composite indexes for query patterns
pub struct InitialMigration;

impl Migration for InitialMigration {
    fn version(&self) -> &'static str {
        "001"
    }

    fn name(&self) -> &'static str {
        "initial_schema"
    }

    fn up(&self) -> &'static str {
        r#"
        -- USERS & AUTH

        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            name TEXT,
            picture TEXT,
            email_verified INTEGER,
            auth_method TEXT,
            provider TEXT,
            provider_id TEXT,
            last_login_platform TEXT,
            last_login_at INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX sessions_user_expires_idx ON sessions(user_id, expires_at);

        CREATE TABLE auth_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            refresh_token_hash TEXT NOT NULL,
            access_expires_at INTEGER NOT NULL,
            refresh_expires_at INTEGER NOT NULL,
            platform TEXT NOT NULL,
            user_agent TEXT,
            ip_address TEXT,
            revoked INTEGER NOT NULL DEFAULT 0,
            last_used INTEGER,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX auth_tokens_user_revoked_expires_idx ON auth_tokens(user_id, revoked, access_expires_at);
        CREATE INDEX auth_tokens_expiration_idx ON auth_tokens(access_expires_at);
        CREATE INDEX auth_tokens_refresh_expiration_idx ON auth_tokens(refresh_expires_at);
        CREATE INDEX auth_tokens_user_platform_idx ON auth_tokens(user_id, platform);
        CREATE INDEX auth_tokens_token_hash_idx ON auth_tokens(token_hash);
        CREATE INDEX auth_tokens_refresh_token_hash_idx ON auth_tokens(refresh_token_hash);

        -- APP ATTESTATION

        CREATE TABLE app_attest_challenges (
            id TEXT PRIMARY KEY,
            challenge TEXT NOT NULL,
            bundle_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX app_attest_challenges_expires_idx ON app_attest_challenges(expires_at);

        CREATE TABLE app_attest_keys (
            key_id TEXT PRIMARY KEY,
            bundle_id TEXT NOT NULL,
            -- Store binary key material as BLOB
            public_key BLOB,
            -- Optional receipt/payload
            attestation_receipt TEXT,
            counter INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            last_used_at INTEGER NOT NULL
        );
        CREATE INDEX app_attest_keys_bundle_idx ON app_attest_keys(bundle_id);

        -- LINKS PIPELINE (DELTA SYNC, TAGS, SUMMARIES, JOBS, PUSH, PREFS, IDEMPOTENCY)

        CREATE TABLE links (
            id TEXT PRIMARY KEY, -- ULID/UUID
            user_id TEXT NOT NULL,
            client_id TEXT, -- optional client-provided id
            original_url TEXT NOT NULL,
            canonical_url TEXT NOT NULL,
            host TEXT,
            state TEXT NOT NULL CHECK (state IN ('active','archived')) DEFAULT 'active', -- soft-delete managed via deleted_at
            failure_reason TEXT,
            title TEXT,
            description TEXT,
            site_name TEXT,
            favicon_url TEXT,
            image_url TEXT,
            summary_short TEXT,
            summary_long TEXT,
            primary_summary_model_id TEXT,
            lang TEXT,
            word_count INTEGER,
            reading_time_sec INTEGER,
            content_hash TEXT,
            save_count INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            ready_at INTEGER,
            deleted_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Uniqueness per user on canonical URL to avoid duplicates; enables upsert
        CREATE UNIQUE INDEX links_user_canonical_unique ON links(user_id, canonical_url);
        -- Common query access patterns
        CREATE INDEX links_user_deleted_updated_idx ON links(user_id, deleted_at, updated_at);
        CREATE INDEX links_canonical_idx ON links(canonical_url);

        CREATE TABLE link_saves (
            id TEXT PRIMARY KEY,
            link_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            source_app TEXT,
            shared_text TEXT,
            shared_at INTEGER,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        -- Speed up "latest shared_at" subqueries
        CREATE INDEX link_saves_link_shared_idx ON link_saves(link_id, shared_at DESC);

        CREATE TABLE tags (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE
        );

        CREATE TABLE link_tags (
            link_id TEXT NOT NULL,
            tag_id TEXT NOT NULL,
            confidence REAL,
            PRIMARY KEY (link_id, tag_id),
            FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
        );
        CREATE INDEX link_tags_tag_idx ON link_tags(tag_id);

        CREATE TABLE link_summaries (
            id TEXT PRIMARY KEY,
            link_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            model_id TEXT NOT NULL, -- e.g., "@cf/meta/llama-3.1-8b-instruct"
            prompt_version TEXT,
            prompt_text TEXT NOT NULL,
            short_summary TEXT NOT NULL,
            long_summary TEXT,
            tags_json TEXT,
            usage_json TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE UNIQUE INDEX link_summaries_link_model_unique ON link_summaries(link_id, model_id);
        CREATE INDEX link_summaries_link_idx ON link_summaries(link_id);

        CREATE TABLE jobs (
            id TEXT PRIMARY KEY,
            link_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            kind TEXT NOT NULL, -- e.g., "process_link"
            run_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX jobs_link_idx ON jobs(link_id);
        CREATE INDEX jobs_user_run_at_idx ON jobs(user_id, run_at);

        CREATE TABLE push_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            device_token TEXT NOT NULL,
            platform TEXT NOT NULL CHECK (platform IN ('ios','android','web')),
            created_at INTEGER NOT NULL,
            last_seen INTEGER,
            UNIQUE(device_token),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX push_tokens_lookup_idx ON push_tokens(user_id, platform, device_token);
        CREATE INDEX push_tokens_user_last_seen_idx ON push_tokens(user_id, last_seen);

        CREATE TABLE user_prefs (
            user_id TEXT PRIMARY KEY,
            preferred_models TEXT,
            summary_models TEXT,
            summary_prompt_override TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE idempotency_keys (
            key TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            response_body BLOB,
            status INTEGER,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX idempotency_keys_user_created_idx ON idempotency_keys(user_id, created_at);
        "#
    }

    fn down(&self) -> &'static str {
        r#"
        -- Drop in reverse order of dependency to satisfy FKs and cleanup indexes.

        DROP INDEX IF EXISTS idempotency_keys_user_created_idx;
        DROP TABLE IF EXISTS idempotency_keys;

        DROP TABLE IF EXISTS user_prefs;

        DROP INDEX IF EXISTS push_tokens_user_last_seen_idx;
        DROP INDEX IF EXISTS push_tokens_lookup_idx;
        DROP TABLE IF EXISTS push_tokens;

        DROP INDEX IF EXISTS jobs_user_run_at_idx;
        DROP INDEX IF EXISTS jobs_link_idx;
        DROP TABLE IF EXISTS jobs;

        DROP INDEX IF EXISTS link_summaries_link_idx;
        DROP INDEX IF EXISTS link_summaries_link_model_unique;
        DROP TABLE IF EXISTS link_summaries;

        DROP INDEX IF EXISTS link_tags_tag_idx;
        DROP TABLE IF EXISTS link_tags;
        DROP TABLE IF EXISTS tags;

        DROP INDEX IF EXISTS link_saves_link_shared_idx;
        DROP TABLE IF EXISTS link_saves;

        DROP INDEX IF EXISTS links_canonical_idx;
        DROP INDEX IF EXISTS links_user_deleted_updated_idx;
        DROP INDEX IF EXISTS links_user_canonical_unique;
        DROP TABLE IF EXISTS links;

        DROP INDEX IF EXISTS app_attest_keys_bundle_idx;
        DROP TABLE IF EXISTS app_attest_keys;

        DROP INDEX IF EXISTS app_attest_challenges_expires_idx;
        DROP TABLE IF EXISTS app_attest_challenges;

        DROP INDEX IF EXISTS auth_tokens_refresh_token_hash_idx;
        DROP INDEX IF EXISTS auth_tokens_token_hash_idx;
        DROP INDEX IF EXISTS auth_tokens_user_platform_idx;
        DROP INDEX IF EXISTS auth_tokens_refresh_expiration_idx;
        DROP INDEX IF EXISTS auth_tokens_expiration_idx;
        DROP INDEX IF EXISTS auth_tokens_user_revoked_expires_idx;
        DROP TABLE IF EXISTS auth_tokens;

        DROP INDEX IF EXISTS sessions_user_expires_idx;
        DROP TABLE IF EXISTS sessions;

        DROP TABLE IF EXISTS users;
        "#
    }
}

pub fn get_migrations() -> Vec<&'static dyn Migration> {
    vec![&InitialMigration]
}
