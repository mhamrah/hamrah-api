use super::Platform;
use crate::db::{schema::AuthToken, Database};
use crate::utils::datetime_to_timestamp;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx_d1::{query, query_as};
use uuid::Uuid;
use worker::Result;

pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: i64,  // Unix timestamp in milliseconds
    pub refresh_expires_at: i64, // Unix timestamp in milliseconds
}

pub fn generate_token() -> String {
    Uuid::new_v4().to_string().replace("-", "")
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn create_token_pair(
    db: &mut Database,
    user_id: &str,
    platform: &Platform,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
) -> Result<TokenPair> {
    let access_token = generate_token();
    let refresh_token = generate_token();

    let access_token_hash = hash_token(&access_token);
    let refresh_token_hash = hash_token(&refresh_token);

    let now = Utc::now();
    let access_expires_at = now + Duration::hours(1); // 1 hour
    let refresh_expires_at = now + Duration::days(30); // 30 days

    let token_id = Uuid::new_v4().to_string();

    query(
        r#"
        INSERT INTO auth_tokens (
            id, user_id, token_hash, refresh_token_hash,
            access_expires_at, refresh_expires_at, platform,
            user_agent, ip_address, revoked, last_used, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    "#,
    )
    .bind(&token_id)
    .bind(user_id)
    .bind(&access_token_hash)
    .bind(&refresh_token_hash)
    .bind(datetime_to_timestamp(access_expires_at))
    .bind(datetime_to_timestamp(refresh_expires_at))
    .bind(platform.as_str())
    .bind(user_agent.as_deref())
    .bind(ip_address.unwrap_or(""))
    .bind(0)
    .bind(None::<i64>)
    .bind(datetime_to_timestamp(now))
    .execute(&mut db.conn)
    .await
    .map_err(|e| worker::Error::from(format!("Database error: {}", e)))?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        access_expires_at: datetime_to_timestamp(access_expires_at),
        refresh_expires_at: datetime_to_timestamp(refresh_expires_at),
    })
}

#[derive(sqlx::FromRow)]
struct AuthTokenRow {
    id: String,
    user_id: String,
    token_hash: String,
    refresh_token_hash: String,
    access_expires_at: i64,
    refresh_expires_at: i64,
    platform: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
    revoked: i64,
    last_used: Option<i64>,
    created_at: i64,
}

pub async fn validate_access_token(db: &mut Database, token: &str) -> Result<Option<AuthToken>> {
    let token_hash = hash_token(token);

    let result = query_as::<AuthTokenRow>(
        r#"
        SELECT id, user_id, token_hash, refresh_token_hash,
               access_expires_at, refresh_expires_at, platform,
               user_agent, ip_address, revoked, last_used, created_at
        FROM auth_tokens WHERE token_hash = ?
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| worker::Error::from(format!("Database error: {}", e)))?;

    if let Some(row) = result {
        // Convert AuthTokenRow to AuthToken
        let auth_token = AuthToken {
            id: row.id,
            user_id: row.user_id,
            token_hash: row.token_hash,
            refresh_token_hash: row.refresh_token_hash,
            access_expires_at: row.access_expires_at,
            refresh_expires_at: row.refresh_expires_at,
            platform: row.platform,
            user_agent: row.user_agent,
            ip_address: row.ip_address,
            revoked: row.revoked != 0,
            last_used: row.last_used,
            created_at: row.created_at,
        };

        // Check if token is expired or revoked
        let now_ts = datetime_to_timestamp(Utc::now());
        if now_ts >= auth_token.access_expires_at || auth_token.revoked {
            return Ok(None);
        }

        Ok(Some(auth_token))
    } else {
        Ok(None)
    }
}

#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    id: String,
    user_id: String,
    platform: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
    refresh_expires_at: i64,
}

pub async fn refresh_token(db: &mut Database, refresh_token: &str) -> Result<Option<TokenPair>> {
    let refresh_token_hash = hash_token(refresh_token);

    let result = query_as::<RefreshTokenRow>(
        r#"
        SELECT id, user_id, platform, user_agent, ip_address, refresh_expires_at
        FROM auth_tokens
        WHERE refresh_token_hash = ? AND revoked = 0
    "#,
    )
    .bind(refresh_token_hash)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| worker::Error::from(format!("Database error: {}", e)))?;

    if let Some(row) = result {
        // Check if refresh token is expired
        let now_ts = datetime_to_timestamp(Utc::now());
        if now_ts >= row.refresh_expires_at {
            return Ok(None);
        }

        // Revoke the old token
        revoke_token(db, &row.id).await?;

        // Create new token pair
        let new_token_pair = create_token_pair(
            db,
            &row.user_id,
            &row.platform,
            row.user_agent.as_deref(),
            row.ip_address.as_deref(),
        )
        .await?;

        Ok(Some(new_token_pair))
    } else {
        Ok(None)
    }
}

pub async fn revoke_token(db: &mut Database, token_id: &str) -> Result<()> {
    query("UPDATE auth_tokens SET revoked = 1 WHERE id = ?")
        .bind(token_id)
        .execute(&mut db.conn)
        .await
        .map_err(|e| worker::Error::from(format!("Database error: {}", e)))?;

    Ok(())
}

pub async fn revoke_all_user_tokens(db: &mut Database, user_id: &str) -> Result<()> {
    query("UPDATE auth_tokens SET revoked = 1 WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut db.conn)
        .await
        .map_err(|e| worker::Error::from(format!("Database error: {}", e)))?;

    Ok(())
}

pub async fn update_token_last_used(db: &mut Database, token_id: &str) -> Result<()> {
    let now = datetime_to_timestamp(Utc::now());
    query("UPDATE auth_tokens SET last_used = ? WHERE id = ?")
        .bind(now)
        .bind(token_id)
        .execute(&mut db.conn)
        .await
        .map_err(|e| worker::Error::from(format!("Database error: {}", e)))?;

    Ok(())
}

pub async fn cleanup_expired_tokens(db: &mut Database) -> Result<()> {
    let now = datetime_to_timestamp(Utc::now());

    query(
        r#"
        DELETE FROM auth_tokens
        WHERE access_expires_at < ? AND refresh_expires_at < ?
    "#,
    )
    .bind(now)
    .bind(now)
    .execute(&mut db.conn)
    .await
    .map_err(|e| worker::Error::from(format!("Database error: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let token1 = generate_token();
        let token2 = generate_token();

        assert_ne!(token1, token2);
        assert!(!token1.contains("-"));
        assert_eq!(token1.len(), 32); // UUID without hyphens
    }

    #[test]
    fn test_hash_token() {
        let token = "test_token";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, token);
        assert_eq!(hash1.len(), 64); // SHA256 hex string
    }
}
