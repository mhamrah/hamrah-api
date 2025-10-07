use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{create_session, get_session_by_token, rotate_session, upsert_user, DbPool, User};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub email: String,
    pub iat: usize,
    pub exp: usize,
}

fn jwt_secret() -> anyhow::Result<String> {
    std::env::var("JWT_SECRET").map_err(|_| anyhow::anyhow!("JWT_SECRET must be set"))
}

fn issue_access_token(user: &User) -> anyhow::Result<String> {
    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + ChronoDuration::hours(1)).timestamp() as usize;
    let claims = Claims {
        sub: user.id,
        email: user.email.clone(),
        iat,
        exp,
    };
    let key = EncodingKey::from_secret(jwt_secret()?.as_bytes());
    let token = encode(&Header::default(), &claims, &key)?;
    Ok(token)
}

fn validate_token(token: &str) -> bool {
    let k = DecodingKey::from_secret(jwt_secret().ok().unwrap_or_default().as_bytes());
    let key = k;
    let validation = Validation::default();
    decode::<Claims>(token, &key, &validation).is_ok()
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer ").map(|t| t.to_string()))
}

#[derive(Deserialize)]
pub struct NativeLoginRequest {
    pub email: String,
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct TokensResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

pub async fn auth_native(
    State(pool): State<DbPool>,
    Json(req): Json<NativeLoginRequest>,
) -> impl IntoResponse {
    let user = match upsert_user(&pool, &req.email, req.name.as_deref()).await {
        Ok(u) => u,
        Err(_) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let refresh = Uuid::new_v4().to_string();
    let _session = match create_session(&pool, user.id, &refresh, 24 * 30).await {
        Ok(s) => s,
        Err(_e) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let access = match issue_access_token(&user) {
        Ok(t) => t,
        Err(_e) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let resp = TokensResponse {
        access_token: access,
        refresh_token: refresh,
        expires_in: 3600,
    };
    Json(resp).into_response()
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn auth_refresh(
    State(pool): State<DbPool>,
    Json(req): Json<RefreshRequest>,
) -> impl IntoResponse {
    let session = match get_session_by_token(&pool, &req.refresh_token).await {
        Ok(Some(s)) => s,
        Ok(None) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
        Err(_e) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if session.expires_at < Utc::now() {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
    let new_refresh = Uuid::new_v4().to_string();
    let rotated = match rotate_session(&pool, session.id, &new_refresh, 24 * 30).await {
        Ok(s) => s,
        Err(_e) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let user = User {
        id: rotated.user_id,
        email: String::new(),
        name: None,
        created_at: Utc::now(),
    };
    let access = match issue_access_token(&user) {
        Ok(t) => t,
        Err(_e) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let resp = TokensResponse {
        access_token: access,
        refresh_token: new_refresh,
        expires_in: 3600,
    };
    Json(resp).into_response()
}

pub async fn auth_validate(headers: HeaderMap) -> impl IntoResponse {
    let valid = bearer_token(&headers)
        .map(|t| validate_token(&t))
        .unwrap_or(false);
    Json(serde_json::json!({"valid": valid}))
}

pub fn require_claims(headers: &HeaderMap) -> anyhow::Result<Claims> {
    let token = bearer_token(headers).ok_or_else(|| anyhow::anyhow!("missing bearer token"))?;
    let key = DecodingKey::from_secret(jwt_secret()?.as_bytes());
    let validation = Validation::default();
    let data = decode::<Claims>(&token, &key, &validation)?;
    Ok(data.claims)
}
