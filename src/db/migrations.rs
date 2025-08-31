use crate::db::Database;
use sqlx_d1::query;

// Type alias for SQL error that works across targets
#[cfg(not(target_arch = "wasm32"))]
type SqlError = sqlx::Error;

#[cfg(target_arch = "wasm32")]
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

pub fn get_migrations() -> Vec<&'static dyn Migration> {
    vec![&InitialMigration]
}
