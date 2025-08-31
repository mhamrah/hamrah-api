use crate::db::{
    schema::{Session, User},
    Database,
};
use crate::utils::datetime_to_timestamp;
use base32::{encode, Alphabet};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx_d1::{query, query_as};

// Conditional imports for FromRow trait
#[cfg(not(target_arch = "wasm32"))]
use sqlx::FromRow;

#[cfg(target_arch = "wasm32")]
use sqlx_d1::FromRow;

pub fn generate_session_token() -> String {
    let bytes = uuid::Uuid::new_v4().as_bytes().to_vec();
    encode(Alphabet::Rfc4648 { padding: false }, &bytes).to_lowercase()
}

pub fn create_session_id(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn create_session(
    db: &mut Database,
    token: &str,
    user_id: &str,
) -> Result<Session, worker::Error> {
    let session_id = create_session_id(token);
    let now = datetime_to_timestamp(Utc::now());
    let expires_at = datetime_to_timestamp(Utc::now() + Duration::days(30)); // 30 days

    query("INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
        .bind(&session_id)
        .bind(user_id)
        .bind(expires_at)
        .bind(now)
        .execute(&mut db.conn)
        .await
        .map_err(|e| worker::Error::from(format!("Database error: {}", e)))?;

    Ok(Session {
        id: session_id,
        user_id: user_id.to_string(),
        expires_at,
        created_at: now,
    })
}

// DTO for session validation query result
#[derive(FromRow)]
struct SessionUserRow {
    // User fields
    user_id: String,
    email: String,
    name: Option<String>,
    picture: Option<String>,
    email_verified: Option<i64>,
    auth_method: Option<String>,
    provider: Option<String>,
    provider_id: Option<String>,
    last_login_platform: Option<String>,
    last_login_at: Option<i64>,
    user_created_at: i64,
    user_updated_at: i64,
    // Session fields
    session_id: String,
    session_expires_at: i64,
    session_created_at: i64,
}

pub async fn validate_session_token(
    db: &mut Database,
    token: &str,
) -> Result<Option<(Session, User)>, worker::Error> {
    let session_id = create_session_id(token);

    let result = query_as::<SessionUserRow>(
        r#"
        SELECT
            u.id as user_id, u.email, u.name, u.picture, u.email_verified,
            u.auth_method, u.provider, u.provider_id, u.last_login_platform,
            u.last_login_at, u.created_at as user_created_at, u.updated_at as user_updated_at,
            s.id as session_id, s.expires_at as session_expires_at, s.created_at as session_created_at
        FROM sessions s
        INNER JOIN users u ON s.user_id = u.id
        WHERE s.id = ?
        "#
    )
    .bind(&session_id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| worker::Error::from(format!("Database error: {}", e)))?;

    if let Some(row) = result {
        let now = datetime_to_timestamp(Utc::now());

        // Check if session is expired
        if now >= row.session_expires_at {
            // Delete expired session
            invalidate_session(db, &session_id).await?;
            return Ok(None);
        }

        let session = Session {
            id: row.session_id,
            user_id: row.user_id.clone(),
            expires_at: row.session_expires_at,
            created_at: row.session_created_at,
        };

        let user = User {
            id: row.user_id,
            email: row.email,
            name: row.name,
            picture: row.picture,
            email_verified: row.email_verified,
            auth_method: row.auth_method,
            provider: row.provider,
            provider_id: row.provider_id,
            last_login_platform: row.last_login_platform,
            last_login_at: row.last_login_at,
            created_at: row.user_created_at,
            updated_at: row.user_updated_at,
        };

        // Extend session if it expires in less than 15 days
        let fifteen_days_from_now = datetime_to_timestamp(Utc::now() + Duration::days(15));
        if row.session_expires_at < fifteen_days_from_now {
            extend_session(db, &session_id).await?;
        }

        Ok(Some((session, user)))
    } else {
        Ok(None)
    }
}

pub async fn extend_session(db: &mut Database, session_id: &str) -> Result<(), worker::Error> {
    let new_expires_at = datetime_to_timestamp(Utc::now() + Duration::days(30));

    query("UPDATE sessions SET expires_at = ? WHERE id = ?")
        .bind(new_expires_at)
        .bind(session_id)
        .execute(&mut db.conn)
        .await
        .map_err(|e| worker::Error::from(format!("Database error: {}", e)))?;

    Ok(())
}

pub async fn invalidate_session(db: &mut Database, session_id: &str) -> Result<(), worker::Error> {
    query("DELETE FROM sessions WHERE id = ?")
        .bind(session_id)
        .execute(&mut db.conn)
        .await
        .map_err(|e| worker::Error::from(format!("Database error: {}", e)))?;

    Ok(())
}
