use anyhow::Context;
use chrono::{Duration, Utc};
use serde::Serialize;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

pub type DbPool = Pool<Postgres>;

pub async fn init_pool() -> anyhow::Result<DbPool> {
    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL environment variable must be set")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .context("failed to connect to Postgres")?;
    Ok(pool)
}

pub async fn run_migrations(pool: &DbPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

#[derive(sqlx::FromRow, Clone, Serialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
}

pub async fn upsert_user(pool: &DbPool, email: &str, name: Option<&str>) -> anyhow::Result<User> {
    // Try to get existing
    if let Some(u) = sqlx::query_as!(
        User,
        r#"SELECT id, email, name, created_at FROM users WHERE email = $1"#,
        email
    )
    .fetch_optional(pool)
    .await?
    {
        return Ok(u);
    }
    let id = Uuid::new_v4();
    let u = sqlx::query_as!(
        User,
        r#"INSERT INTO users (id, email, name) VALUES ($1, $2, $3)
           RETURNING id, email, name, created_at"#,
        id,
        email,
        name
    )
    .fetch_one(pool)
    .await?;
    Ok(u)
}

pub async fn get_user_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<User>> {
    let u = sqlx::query_as!(
        User,
        r#"SELECT id, email, name, created_at FROM users WHERE id = $1"#,
        id
    )
    .fetch_optional(pool)
    .await?;
    Ok(u)
}

#[derive(sqlx::FromRow, Clone)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    #[allow(dead_code)]
    pub refresh_token: String,
    #[allow(dead_code)]
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

pub async fn create_session(
    pool: &DbPool,
    user_id: Uuid,
    refresh_token: &str,
    ttl_hours: i64,
) -> anyhow::Result<Session> {
    let id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::hours(ttl_hours);
    let s = sqlx::query_as!(
        Session,
        r#"INSERT INTO sessions (id, user_id, refresh_token, expires_at)
           VALUES ($1, $2, $3, $4)
           RETURNING id, user_id, refresh_token, created_at, expires_at"#,
        id,
        user_id,
        refresh_token,
        expires_at
    )
    .fetch_one(pool)
    .await?;
    Ok(s)
}

pub async fn get_session_by_token(pool: &DbPool, token: &str) -> anyhow::Result<Option<Session>> {
    let s = sqlx::query_as!(
        Session,
        r#"SELECT id, user_id, refresh_token, created_at, expires_at FROM sessions WHERE refresh_token = $1"#,
        token
    )
    .fetch_optional(pool)
    .await?;
    Ok(s)
}

pub async fn rotate_session(
    pool: &DbPool,
    session_id: Uuid,
    new_token: &str,
    ttl_hours: i64,
) -> anyhow::Result<Session> {
    let expires_at = Utc::now() + Duration::hours(ttl_hours);
    let s = sqlx::query_as!(
        Session,
        r#"UPDATE sessions SET refresh_token = $1, expires_at = $2 WHERE id = $3
           RETURNING id, user_id, refresh_token, created_at, expires_at"#,
        new_token,
        expires_at,
        session_id
    )
    .fetch_one(pool)
    .await?;
    Ok(s)
}

#[derive(sqlx::FromRow, Clone, Serialize)]
pub struct Tag {
    pub id: Uuid,
    pub name: String,
}

pub async fn upsert_tag(pool: &DbPool, name: &str) -> anyhow::Result<Tag> {
    if let Some(t) = sqlx::query_as!(Tag, r#"SELECT id, name FROM tags WHERE name = $1"#, name)
        .fetch_optional(pool)
        .await?
    {
        return Ok(t);
    }
    let id = Uuid::new_v4();
    let t = sqlx::query_as!(
        Tag,
        r#"INSERT INTO tags (id, name) VALUES ($1, $2) RETURNING id, name"#,
        id,
        name
    )
    .fetch_one(pool)
    .await?;
    Ok(t)
}

#[derive(sqlx::FromRow, Clone, Serialize)]
pub struct Summary {
    pub id: Uuid,
    pub link_id: Uuid,
    pub content: Option<String>,
    pub model: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
}

pub async fn set_link_tags(
    pool: &DbPool,
    user_id: Uuid,
    link_id: Uuid,
    tag_names: &[String],
) -> anyhow::Result<()> {
    // Ensure link belongs to user
    let owner = sqlx::query_scalar!(
        r#"SELECT user_id as "user_id: Uuid" FROM links WHERE id = $1"#,
        link_id
    )
    .fetch_optional(pool)
    .await?;
    if owner != Some(user_id) {
        return Err(anyhow::anyhow!("link not found or access denied"));
    }
    // Upsert tags and attach
    for name in tag_names {
        let tag = upsert_tag(pool, name).await?;
        sqlx::query!(
            r#"INSERT INTO link_tags (link_id, tag_id) VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
            link_id,
            tag.id
        )
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn list_tags_for_user(pool: &DbPool, user_id: Uuid) -> anyhow::Result<Vec<Tag>> {
    let tags = sqlx::query_as!(
        Tag,
        r#"SELECT DISTINCT t.id, t.name
           FROM tags t
           JOIN link_tags lt ON lt.tag_id = t.id
           JOIN links l ON l.id = lt.link_id
           WHERE l.user_id = $1
           ORDER BY t.name"#,
        user_id
    )
    .fetch_all(pool)
    .await?;
    Ok(tags)
}

pub async fn get_summary_for_link(
    pool: &DbPool,
    user_id: Uuid,
    link_id: Uuid,
) -> anyhow::Result<Option<Summary>> {
    // Ensure ownership and select summary
    let s = sqlx::query_as!(
        Summary,
        r#"SELECT s.id, s.link_id, s.content, s.model, s.created_at
           FROM summaries s
           JOIN links l ON l.id = s.link_id
           WHERE s.link_id = $1 AND l.user_id = $2
           ORDER BY s.created_at DESC
           LIMIT 1"#,
        link_id,
        user_id
    )
    .fetch_optional(pool)
    .await?;
    Ok(s)
}
