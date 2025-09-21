pub mod migrations;
pub mod schema;

use sqlx_d1::{query, query_as, D1Connection};
use thiserror::Error;
use worker::{Env, Error as WorkerError};

#[derive(Error, Debug)]
#[allow(dead_code)] // Library error type - may be used by external consumers
pub enum DbError {
    #[error("Database operation failed: {0}")]
    OperationFailed(String),
    #[error("Record not found")]
    NotFound,
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),
}

#[derive(Clone)]
pub struct Database {
    pub conn: D1Connection,
}

use crate::db::schema::{
    IdempotencyKey, Link, LinkSave, LinkSummary, LinkTag, PushToken, Tag, UserPrefs,
};

// --- Pipeline Model Helpers ---

impl Database {
    // LINKS
    pub async fn get_link_by_id(&self, id: &str) -> Result<Option<Link>, DbError> {
        let row = query_as::<Link>("SELECT * FROM links WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.conn)
            .await?;
        Ok(row)
    }

    pub async fn insert_link(&self, link: &Link) -> Result<(), DbError> {
        query(
            r#"
            INSERT INTO links (
                id, user_id, client_id, original_url, canonical_url, host,
                state, failure_reason, title, description, site_name, favicon_url, image_url,
                summary_short, summary_long, primary_summary_model_id, lang,
                word_count, reading_time_sec, content_hash,
                archive_etag, archive_bytes, archive_r2_key,
                save_count, created_at, updated_at, ready_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&link.id)
        .bind(&link.user_id)
        .bind(&link.client_id)
        .bind(&link.original_url)
        .bind(&link.canonical_url)
        .bind(&link.host)
        .bind(&link.state)
        .bind(&link.failure_reason)
        .bind(&link.title)
        .bind(&link.description)
        .bind(&link.site_name)
        .bind(&link.favicon_url)
        .bind(&link.image_url)
        .bind(&link.summary_short)
        .bind(&link.summary_long)
        .bind(&link.primary_summary_model_id)
        .bind(&link.lang)
        .bind(link.word_count)
        .bind(link.reading_time_sec)
        .bind(&link.content_hash)
        .bind(&link.archive_etag)
        .bind(link.archive_bytes)
        .bind(&link.archive_r2_key)
        .bind(link.save_count)
        .bind(&link.created_at)
        .bind(&link.updated_at)
        .bind(&link.ready_at)
        .execute(&self.conn)
        .await?;
        Ok(())
    }

    // LINK_SAVES
    pub async fn insert_link_save(&self, save: &LinkSave) -> Result<(), DbError> {
        query(
            r#"
            INSERT INTO link_saves (id, link_id, user_id, source_app, shared_text, shared_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&save.id)
        .bind(&save.link_id)
        .bind(&save.user_id)
        .bind(&save.source_app)
        .bind(&save.shared_text)
        .bind(&save.shared_at)
        .bind(&save.created_at)
        .execute(&self.conn)
        .await?;
        Ok(())
    }

    // TAGS
    pub async fn get_tag_by_name(&self, name: &str) -> Result<Option<Tag>, DbError> {
        let row = query_as::<Tag>("SELECT * FROM tags WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.conn)
            .await?;
        Ok(row)
    }

    pub async fn insert_tag(&self, tag: &Tag) -> Result<(), DbError> {
        query("INSERT INTO tags (id, name) VALUES (?, ?)")
            .bind(&tag.id)
            .bind(&tag.name)
            .execute(&self.conn)
            .await?;
        Ok(())
    }

    // LINK_TAGS
    pub async fn insert_link_tag(&self, link_tag: &LinkTag) -> Result<(), DbError> {
        query(
            r#"
            INSERT INTO link_tags (link_id, tag_id, confidence)
            VALUES (?, ?, ?)
            ON CONFLICT(link_id, tag_id) DO UPDATE SET confidence = excluded.confidence
            "#,
        )
        .bind(&link_tag.link_id)
        .bind(&link_tag.tag_id)
        .bind(link_tag.confidence)
        .execute(&self.conn)
        .await?;
        Ok(())
    }

    // LINK_SUMMARIES
    pub async fn get_link_summary(
        &self,
        link_id: &str,
        model_id: &str,
    ) -> Result<Option<LinkSummary>, DbError> {
        let row = query_as::<LinkSummary>(
            r#"
            SELECT * FROM link_summaries
            WHERE link_id = ? AND model_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(link_id)
        .bind(model_id)
        .fetch_optional(&self.conn)
        .await?;
        Ok(row)
    }

    pub async fn insert_link_summary(&self, summary: &LinkSummary) -> Result<(), DbError> {
        query(
            r#"
            INSERT INTO link_summaries (
                id, link_id, user_id, model_id, prompt_version, prompt_text,
                short_summary, long_summary, tags_json, usage_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&summary.id)
        .bind(&summary.link_id)
        .bind(&summary.user_id)
        .bind(&summary.model_id)
        .bind(&summary.prompt_version)
        .bind(&summary.prompt_text)
        .bind(&summary.short_summary)
        .bind(&summary.long_summary)
        .bind(&summary.tags_json)
        .bind(&summary.usage_json)
        .bind(&summary.created_at)
        .bind(&summary.updated_at)
        .execute(&self.conn)
        .await?;
        Ok(())
    }

    // PUSH_TOKENS
    pub async fn insert_push_token(&self, token: &PushToken) -> Result<(), DbError> {
        query(
            r#"
            INSERT INTO push_tokens (id, user_id, device_token, platform, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(device_token) DO UPDATE SET
                user_id = excluded.user_id,
                platform = excluded.platform
            "#,
        )
        .bind(&token.id)
        .bind(&token.user_id)
        .bind(&token.device_token)
        .bind(&token.platform)
        .bind(&token.created_at)
        .execute(&self.conn)
        .await?;
        Ok(())
    }

    // USER_PREFS
    pub async fn get_user_prefs(&self, user_id: &str) -> Result<Option<UserPrefs>, DbError> {
        let row = query_as::<UserPrefs>("SELECT * FROM user_prefs WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(&self.conn)
            .await?;
        Ok(row)
    }

    pub async fn upsert_user_prefs(&self, prefs: &UserPrefs) -> Result<(), DbError> {
        query(
            r#"
            INSERT INTO user_prefs (
                user_id, preferred_models, summary_models, summary_prompt_override, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                preferred_models = excluded.preferred_models,
                summary_models = excluded.summary_models,
                summary_prompt_override = excluded.summary_prompt_override,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&prefs.user_id)
        .bind(&prefs.preferred_models)
        .bind(&prefs.summary_models)
        .bind(&prefs.summary_prompt_override)
        .bind(&prefs.created_at)
        .bind(&prefs.updated_at)
        .execute(&self.conn)
        .await?;
        Ok(())
    }

    // IDEMPOTENCY_KEYS
    pub async fn insert_idempotency_key(&self, key: &IdempotencyKey) -> Result<(), DbError> {
        query(
            r#"
            INSERT INTO idempotency_keys (key, user_id, response_body, status, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&key.key)
        .bind(&key.user_id)
        .bind(&key.response_body)
        .bind(key.status)
        .bind(&key.created_at)
        .execute(&self.conn)
        .await?;
        Ok(())
    }

    pub async fn get_idempotency_key(&self, key: &str) -> Result<Option<IdempotencyKey>, DbError> {
        let row = query_as::<IdempotencyKey>(
            "SELECT key, user_id, response_body, status, created_at FROM idempotency_keys WHERE key = ?",
        )
        .bind(key)
        .fetch_optional(&self.conn)
        .await?;
        Ok(row)
    }
}

impl Database {
    pub async fn new(env: &Env) -> Result<Self, WorkerError> {
        let d1 = env.d1("DB")?;
        let conn = D1Connection::new(d1);
        Ok(Self { conn })
    }
}

// D1 error conversion for WASM
impl From<sqlx_d1::Error> for DbError {
    fn from(err: sqlx_d1::Error) -> Self {
        // Map sqlx-d1 errors to our DbError type
        DbError::OperationFailed(err.to_string())
    }
}
