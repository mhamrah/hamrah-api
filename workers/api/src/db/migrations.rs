use crate::db::Database;
use sqlx_d1::query;

// Use D1 error type for WASM
type SqlError = sqlx_d1::Error;

pub trait Migration {
    fn up(&self) -> &'static str;
    #[allow(dead_code)] // May be used for migration rollbacks in the future
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
            )
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

// Initial migration to create all tables
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

        CREATE TABLE webauthn_credentials (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            counter INTEGER NOT NULL DEFAULT 0,
            transports TEXT,
            aaguid TEXT,
            credential_type TEXT NOT NULL DEFAULT 'public-key',
            user_verified INTEGER NOT NULL DEFAULT 0,
            credential_device_type TEXT,
            credential_backed_up INTEGER NOT NULL DEFAULT 0,
            name TEXT,
            last_used INTEGER,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE webauthn_challenges (
            id TEXT PRIMARY KEY,
            challenge TEXT NOT NULL,
            user_id TEXT,
            type TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );

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
        "#
    }

    fn down(&self) -> &'static str {
        r#"
        DROP INDEX IF EXISTS auth_tokens_user_platform_idx;
        DROP INDEX IF EXISTS auth_tokens_refresh_expiration_idx;
        DROP INDEX IF EXISTS auth_tokens_expiration_idx;
        DROP INDEX IF EXISTS auth_tokens_user_revoked_expires_idx;
        DROP TABLE IF EXISTS auth_tokens;
        DROP TABLE IF EXISTS webauthn_challenges;
        DROP TABLE IF EXISTS webauthn_credentials;
        DROP TABLE IF EXISTS sessions;
        DROP TABLE IF EXISTS users;
        "#
    }
}

// App Attestation tables migration
pub struct AppAttestationMigration;

impl Migration for AppAttestationMigration {
    fn version(&self) -> &'static str {
        "002"
    }

    fn name(&self) -> &'static str {
        "app_attestation_tables"
    }

    fn up(&self) -> &'static str {
        r#"
        CREATE TABLE app_attest_challenges (
            id TEXT PRIMARY KEY,
            challenge TEXT NOT NULL,
            bundle_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE app_attest_keys (
            key_id TEXT PRIMARY KEY,
            bundle_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_used_at INTEGER NOT NULL
        );

        CREATE INDEX app_attest_challenges_expires_idx ON app_attest_challenges(expires_at);
        CREATE INDEX app_attest_keys_bundle_idx ON app_attest_keys(bundle_id);
        "#
    }

    fn down(&self) -> &'static str {
        r#"
        DROP INDEX IF EXISTS app_attest_keys_bundle_idx;
        DROP INDEX IF EXISTS app_attest_challenges_expires_idx;
        DROP TABLE IF EXISTS app_attest_keys;
        DROP TABLE IF EXISTS app_attest_challenges;
        "#
    }
}

pub struct PipelineMigration;

impl Migration for PipelineMigration {
    fn version(&self) -> &'static str {
        "003"
    }

    fn name(&self) -> &'static str {
        "pipeline_tables"
    }

    fn up(&self) -> &'static str {
        r#"
        CREATE TABLE links (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            client_id TEXT,
            original_url TEXT NOT NULL,
            canonical_url TEXT NOT NULL,
            host TEXT,
            state TEXT NOT NULL,
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
            archive_etag TEXT,
            archive_bytes INTEGER,
            archive_r2_key TEXT,
            save_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            ready_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE link_saves (
            id TEXT PRIMARY KEY,
            link_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            source_app TEXT,
            shared_text TEXT,
            shared_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

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

        CREATE TABLE link_summaries (
            id TEXT PRIMARY KEY,
            link_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            model_id TEXT NOT NULL,
            prompt_version TEXT,
            prompt_text TEXT NOT NULL,
            short_summary TEXT NOT NULL,
            long_summary TEXT,
            tags_json TEXT,
            usage_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE push_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            device_token TEXT NOT NULL,
            platform TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(device_token),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE user_prefs (
            user_id TEXT PRIMARY KEY,
            preferred_models TEXT,
            summary_models TEXT,
            summary_prompt_override TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE idempotency_keys (
            key TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            response_body BLOB,
            status INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX links_user_updated_idx ON links(user_id, updated_at);
        CREATE INDEX links_canonical_idx ON links(canonical_url);
        CREATE INDEX link_saves_link_idx ON link_saves(link_id);
        CREATE INDEX link_summaries_link_idx ON link_summaries(link_id);
        CREATE INDEX push_tokens_user_idx ON push_tokens(user_id);
        "#
    }

    fn down(&self) -> &'static str {
        r#"
        DROP INDEX IF EXISTS push_tokens_user_idx;
        DROP INDEX IF EXISTS link_summaries_link_idx;
        DROP INDEX IF EXISTS link_saves_link_idx;
        DROP INDEX IF EXISTS links_canonical_idx;
        DROP INDEX IF EXISTS links_user_updated_idx;

        DROP TABLE IF EXISTS idempotency_keys;
        DROP TABLE IF EXISTS user_prefs;
        DROP TABLE IF EXISTS push_tokens;
        DROP TABLE IF EXISTS link_summaries;
        DROP TABLE IF EXISTS link_tags;
        DROP TABLE IF EXISTS tags;
        DROP TABLE IF EXISTS link_saves;
        DROP TABLE IF EXISTS links;
        "#
    }
}

pub struct SoftDeleteMigration;

impl Migration for SoftDeleteMigration {
    fn version(&self) -> &'static str {
        "004"
    }

    fn name(&self) -> &'static str {
        "soft_delete_links"
    }

    fn up(&self) -> &'static str {
        r#"
        ALTER TABLE links ADD COLUMN deleted_at TEXT;
        CREATE INDEX links_user_deleted_idx ON links(user_id, deleted_at);
        "#
    }

    fn down(&self) -> &'static str {
        r#"
        DROP INDEX IF EXISTS links_user_deleted_idx;
        "#
    }
}

pub fn get_migrations() -> Vec<&'static dyn Migration> {
    vec![
        &InitialMigration,
        &AppAttestationMigration,
        &PipelineMigration,
        &SoftDeleteMigration,
    ]
}
