use super::AuthError;
use crate::db::{Database, schema::{Session, NewSession, User}};
use sha2::{Sha256, Digest};
use base32::{Alphabet, encode};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use sqlx::Row;

pub fn generate_session_token() -> String {
    let bytes = uuid::Uuid::new_v4().as_bytes().to_vec();
    encode(Alphabet::RFC4648 { padding: false }, &bytes).to_lowercase()
}

pub fn create_session_id(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn create_session(
    db: &Database, 
    token: &str, 
    user_id: &str
) -> Result<Session, sqlx::Error> {
    let session_id = create_session_id(token);
    let now = Utc::now();
    let expires_at = now + Duration::days(30); // 30 days
    
    let sql = r#"
        INSERT INTO sessions (id, user_id, expires_at, created_at) 
        VALUES (?, ?, ?, ?)
    "#;
    
    sqlx::query(sql)
        .bind(&session_id)
        .bind(user_id)
        .bind(expires_at)
        .bind(now)
        .execute(&db.pool)
        .await?;
    
    Ok(Session {
        id: session_id,
        user_id: user_id.to_string(),
        expires_at,
        created_at: now,
    })
}

pub async fn validate_session_token(
    db: &Database, 
    token: &str
) -> Result<Option<(Session, User)>, sqlx::Error> {
    let session_id = create_session_id(token);
    
    let sql = r#"
        SELECT 
            s.id, s.user_id, s.expires_at, s.created_at,
            u.id as user_id, u.email, u.name, u.picture, u.email_verified,
            u.auth_method, u.provider, u.provider_id, u.last_login_platform,
            u.last_login_at, u.created_at as user_created_at, u.updated_at
        FROM sessions s
        INNER JOIN users u ON s.user_id = u.id
        WHERE s.id = ?
    "#;
    
    let result = sqlx::query(sql)
        .bind(&session_id)
        .fetch_optional(&db.pool)
        .await?;
    
    if let Some(row) = result {
        let expires_at: DateTime<Utc> = row.get("expires_at");
            
        // Check if session is expired
        if Utc::now() >= expires_at {
            // Delete expired session
            invalidate_session(db, &session_id).await?;
            return Ok(None);
        }
        
        let session = Session {
            id: row.get("id"),
            user_id: row.get("user_id"),
            expires_at,
            created_at: row.get("created_at"),
        };
        
        let user = User {
            id: row.get("user_id"),
            email: row.get("email"),
            name: row.get("name"),
            picture: row.get("picture"),
            email_verified: row.get("email_verified"),
            auth_method: row.get("auth_method"),
            provider: row.get("provider"),
            provider_id: row.get("provider_id"),
            last_login_platform: row.get("last_login_platform"),
            last_login_at: row.get("last_login_at"),
            created_at: row.get("user_created_at"),
            updated_at: row.get("updated_at"),
        };
        
        // Extend session if it expires in less than 15 days
        if expires_at - Utc::now() < Duration::days(15) {
            extend_session(db, &session_id).await?;
        }
        
        Ok(Some((session, user)))
    } else {
        Ok(None)
    }
}

pub async fn extend_session(db: &Database, session_id: &str) -> Result<(), sqlx::Error> {
    let new_expires_at = Utc::now() + Duration::days(30);
    
    let sql = "UPDATE sessions SET expires_at = ? WHERE id = ?";
    sqlx::query(sql)
        .bind(new_expires_at)
        .bind(session_id)
        .execute(&db.pool)
        .await?;
    
    Ok(())
}

pub async fn invalidate_session(db: &Database, session_id: &str) -> Result<(), sqlx::Error> {
    let sql = "DELETE FROM sessions WHERE id = ?";
    sqlx::query(sql)
        .bind(session_id)
        .execute(&db.pool)
        .await?;
    
    Ok(())
}