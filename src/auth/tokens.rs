use super::{AuthError, Platform};
use crate::db::{Database, schema::{AuthToken, NewAuthToken}};
use sha2::{Sha256, Digest};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use worker::Result;

pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
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
    db: &Database,
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
    
    let new_token = NewAuthToken {
        user_id: user_id.to_string(),
        token_hash: access_token_hash,
        refresh_token_hash: refresh_token_hash.clone(),
        access_expires_at,
        refresh_expires_at,
        platform: platform.clone(),
        user_agent: user_agent.map(|s| s.to_string()),
        ip_address: ip_address.map(|s| s.to_string()),
    };
    
    let token_id = Uuid::new_v4().to_string();
    
    let sql = r#"
        INSERT INTO auth_tokens (
            id, user_id, token_hash, refresh_token_hash, 
            access_expires_at, refresh_expires_at, platform, 
            user_agent, ip_address, revoked, last_used, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
    "#;
    
    db.d1.prepare(sql)
        .bind(&[
            token_id.into(),
            user_id.into(),
            new_token.token_hash.into(),
            new_token.refresh_token_hash.into(),
            access_expires_at.timestamp_millis().into(),
            refresh_expires_at.timestamp_millis().into(),
            platform.clone().into(),
            user_agent.unwrap_or("").into(),
            ip_address.unwrap_or("").into(),
            now.timestamp_millis().into(),
            now.timestamp_millis().into(),
        ])?
        .run()
        .await?;
    
    Ok(TokenPair {
        access_token,
        refresh_token,
        access_expires_at,
        refresh_expires_at,
    })
}

pub async fn validate_access_token(
    db: &Database,
    token: &str,
) -> Result<Option<AuthToken>> {
    let token_hash = hash_token(token);
    
    let sql = r#"
        SELECT id, user_id, token_hash, refresh_token_hash, 
               access_expires_at, refresh_expires_at, platform, 
               user_agent, ip_address, revoked, last_used, created_at
        FROM auth_tokens 
        WHERE token_hash = ? AND revoked = 0
    "#;
    
    let result = db.d1.prepare(sql)
        .bind(&[token_hash.into()])?
        .first::<serde_json::Value>(None)
        .await?;
    
    if let Some(row) = result {
        let access_expires_at = DateTime::from_timestamp_millis(
            row["access_expires_at"].as_i64().unwrap_or(0)
        ).unwrap_or_else(|| Utc::now());
        
        // Check if token is expired
        if Utc::now() >= access_expires_at {
            return Ok(None);
        }
        
        let auth_token = AuthToken {
            id: row["id"].as_str().unwrap_or("").to_string(),
            user_id: row["user_id"].as_str().unwrap_or("").to_string(),
            token_hash: row["token_hash"].as_str().unwrap_or("").to_string(),
            refresh_token_hash: row["refresh_token_hash"].as_str().unwrap_or("").to_string(),
            access_expires_at,
            refresh_expires_at: DateTime::from_timestamp_millis(
                row["refresh_expires_at"].as_i64().unwrap_or(0)
            ).unwrap_or_else(|| Utc::now()),
            platform: row["platform"].as_str().unwrap_or("").to_string(),
            user_agent: row["user_agent"].as_str().map(|s| s.to_string()),
            ip_address: row["ip_address"].as_str().map(|s| s.to_string()),
            revoked: row["revoked"].as_bool().unwrap_or(false),
            last_used: row["last_used"].as_i64()
                .and_then(|ts| DateTime::from_timestamp_millis(ts)),
            created_at: DateTime::from_timestamp_millis(
                row["created_at"].as_i64().unwrap_or(0)
            ).unwrap_or_else(|| Utc::now()),
        };
        
        // Update last_used timestamp
        update_token_last_used(db, &auth_token.id).await?;
        
        Ok(Some(auth_token))
    } else {
        Ok(None)
    }
}

pub async fn refresh_token(
    db: &Database,
    refresh_token: &str,
) -> Result<Option<TokenPair>> {
    let refresh_token_hash = hash_token(refresh_token);
    
    let sql = r#"
        SELECT id, user_id, platform, user_agent, ip_address, refresh_expires_at
        FROM auth_tokens 
        WHERE refresh_token_hash = ? AND revoked = 0
    "#;
    
    let result = db.d1.prepare(sql)
        .bind(&[refresh_token_hash.into()])?
        .first::<serde_json::Value>(None)
        .await?;
    
    if let Some(row) = result {
        let refresh_expires_at = DateTime::from_timestamp_millis(
            row["refresh_expires_at"].as_i64().unwrap_or(0)
        ).unwrap_or_else(|| Utc::now());
        
        // Check if refresh token is expired
        if Utc::now() >= refresh_expires_at {
            return Ok(None);
        }
        
        let token_id = row["id"].as_str().unwrap_or("").to_string();
        let user_id = row["user_id"].as_str().unwrap_or("").to_string();
        let platform = row["platform"].as_str().unwrap_or("").to_string();
        let user_agent = row["user_agent"].as_str();
        let ip_address = row["ip_address"].as_str();
        
        // Revoke the old token
        revoke_token(db, &token_id).await?;
        
        // Create new token pair
        let new_token_pair = create_token_pair(
            db,
            &user_id,
            &platform,
            user_agent,
            ip_address,
        ).await?;
        
        Ok(Some(new_token_pair))
    } else {
        Ok(None)
    }
}

pub async fn revoke_token(db: &Database, token_id: &str) -> Result<()> {
    let sql = "UPDATE auth_tokens SET revoked = 1 WHERE id = ?";
    db.d1.prepare(sql)
        .bind(&[token_id.into()])?
        .run()
        .await?;
    
    Ok(())
}

pub async fn revoke_all_user_tokens(db: &Database, user_id: &str) -> Result<()> {
    let sql = "UPDATE auth_tokens SET revoked = 1 WHERE user_id = ?";
    db.d1.prepare(sql)
        .bind(&[user_id.into()])?
        .run()
        .await?;
    
    Ok(())
}

pub async fn update_token_last_used(db: &Database, token_id: &str) -> Result<()> {
    let now = Utc::now();
    let sql = "UPDATE auth_tokens SET last_used = ? WHERE id = ?";
    
    db.d1.prepare(sql)
        .bind(&[now.timestamp_millis().into(), token_id.into()])?
        .run()
        .await?;
    
    Ok(())
}

pub async fn cleanup_expired_tokens(db: &Database) -> Result<()> {
    let now = Utc::now().timestamp_millis();
    
    // Delete tokens where both access and refresh tokens are expired
    let sql = r#"
        DELETE FROM auth_tokens 
        WHERE access_expires_at < ? AND refresh_expires_at < ?
    "#;
    
    db.d1.prepare(sql)
        .bind(&[now.into(), now.into()])?
        .run()
        .await?;
    
    Ok(())
}