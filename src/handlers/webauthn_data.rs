// WebAuthn data persistence handlers
// These endpoints only handle data storage/retrieval for WebAuthn operations
// The actual WebAuthn protocol logic is handled in hamrah-web

use super::{ApiError, ApiResult};
use crate::db::schema::{User, WebAuthnChallenge, WebAuthnCredential};
use crate::utils::datetime_to_timestamp;
use axum::{
    extract::{Path, State},
    response::Json,
    Json as JsonExtractor,
};
use base64::prelude::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx_d1::{query, query_as};

use crate::AppState;

// Request/Response types for WebAuthn data operations
#[derive(Debug, Deserialize, Serialize)]
pub struct StoreCredentialRequest {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>, // Serialized as array from web
    pub counter: i64,
    pub transports: Option<Vec<String>>,
    pub aaguid: Option<Vec<u8>>,
    pub credential_type: String,
    pub user_verified: bool,
    pub credential_device_type: Option<String>,
    pub credential_backed_up: bool,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateCredentialCounterRequest {
    pub counter: i64,
    pub last_used: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StoreChallengeRequest {
    pub id: String,
    pub challenge: String,
    pub user_id: Option<String>,
    pub challenge_type: String, // 'registration' | 'authentication'
    pub expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub counter: i64,
    pub transports: Option<Vec<String>>,
    pub aaguid: Option<Vec<u8>>,
    pub credential_type: String,
    pub user_verified: bool,
    pub credential_device_type: Option<String>,
    pub credential_backed_up: bool,
    pub name: Option<String>,
    pub last_used: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub id: String,
    pub challenge: String,
    pub user_id: Option<String>,
    pub challenge_type: String,
    pub expires_at: i64,
    pub created_at: i64,
}

/// POST /api/webauthn/credentials
/// Store a new WebAuthn credential
pub async fn store_webauthn_credential(
    State(mut state): State<AppState>,
    JsonExtractor(payload): JsonExtractor<StoreCredentialRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let now = datetime_to_timestamp(Utc::now());

    // Convert Vec<u8> to base64 string for storage
    let public_key_b64 = BASE64_STANDARD.encode(&payload.public_key);
    let aaguid_b64 = payload.aaguid.as_ref().map(|a| BASE64_STANDARD.encode(a));
    let transports_json = payload
        .transports
        .as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_default());

    query(
        r#"INSERT INTO webauthn_credentials 
           (id, user_id, public_key, counter, transports, aaguid, credential_type, 
            user_verified, credential_device_type, credential_backed_up, name, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(&payload.id)
    .bind(&payload.user_id)
    .bind(&public_key_b64)
    .bind(payload.counter)
    .bind(transports_json.as_deref())
    .bind(aaguid_b64.as_deref())
    .bind(&payload.credential_type)
    .bind(payload.user_verified)
    .bind(payload.credential_device_type.as_deref())
    .bind(payload.credential_backed_up)
    .bind(payload.name.as_deref())
    .bind(now)
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to store credential: {:?}", e)))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Credential stored successfully"
    })))
}

/// GET /api/webauthn/credentials/{credential_id}
/// Get a specific WebAuthn credential by ID
pub async fn get_webauthn_credential(
    State(mut state): State<AppState>,
    Path(credential_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let credential =
        query_as::<WebAuthnCredential>("SELECT * FROM webauthn_credentials WHERE id = ?")
            .bind(&credential_id)
            .fetch_optional(&mut state.db.conn)
            .await
            .map_err(|e| ApiError::DatabaseError(format!("Database error: {:?}", e)))?;

    match credential {
        Some(cred) => {
            // Convert base64 strings back to Vec<u8>
            let public_key = BASE64_STANDARD.decode(&cred.public_key).map_err(|e| {
                ApiError::InternalServerError(format!("Failed to decode public key: {:?}", e))
            })?;

            let aaguid = cred
                .aaguid
                .as_ref()
                .map(|a| BASE64_STANDARD.decode(a))
                .transpose()
                .map_err(|e| {
                    ApiError::InternalServerError(format!("Failed to decode aaguid: {:?}", e))
                })?;

            let transports: Option<Vec<String>> = cred
                .transports
                .as_ref()
                .map(|t| serde_json::from_str(t).unwrap_or_default());

            let response = CredentialResponse {
                id: cred.id,
                user_id: cred.user_id,
                public_key,
                counter: cred.counter,
                transports,
                aaguid,
                credential_type: cred.credential_type,
                user_verified: cred.user_verified,
                credential_device_type: cred.credential_device_type,
                credential_backed_up: cred.credential_backed_up,
                name: cred.name,
                last_used: cred.last_used,
                created_at: cred.created_at,
            };

            Ok(Json(serde_json::json!({
                "success": true,
                "credential": response
            })))
        }
        None => Ok(Json(serde_json::json!({
            "success": false,
            "error": "Credential not found"
        }))),
    }
}

/// GET /api/webauthn/users/{user_id}/credentials
/// Get all WebAuthn credentials for a user
pub async fn get_user_webauthn_credentials(
    State(mut state): State<AppState>,
    Path(user_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let credentials = query_as::<WebAuthnCredential>(
        "SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(&user_id)
    .fetch_all(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Database error: {:?}", e)))?;

    let credential_responses: Vec<CredentialResponse> = credentials
        .into_iter()
        .filter_map(|cred| {
            // Convert base64 strings back to Vec<u8>
            let public_key = BASE64_STANDARD.decode(&cred.public_key).ok()?;
            let aaguid = cred
                .aaguid
                .as_ref()
                .map(|a| BASE64_STANDARD.decode(a))
                .transpose()
                .ok()?;
            let transports: Option<Vec<String>> = cred
                .transports
                .as_ref()
                .map(|t| serde_json::from_str(t).unwrap_or_default());

            Some(CredentialResponse {
                id: cred.id,
                user_id: cred.user_id,
                public_key,
                counter: cred.counter,
                transports,
                aaguid,
                credential_type: cred.credential_type,
                user_verified: cred.user_verified,
                credential_device_type: cred.credential_device_type,
                credential_backed_up: cred.credential_backed_up,
                name: cred.name,
                last_used: cred.last_used,
                created_at: cred.created_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "success": true,
        "credentials": credential_responses
    })))
}

/// PATCH /api/webauthn/credentials/{credential_id}/counter
/// Update credential counter and last used timestamp
pub async fn update_webauthn_credential_counter(
    State(mut state): State<AppState>,
    Path(credential_id): Path<String>,
    JsonExtractor(payload): JsonExtractor<UpdateCredentialCounterRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    query("UPDATE webauthn_credentials SET counter = ?, last_used = ? WHERE id = ?")
        .bind(payload.counter)
        .bind(payload.last_used)
        .bind(&credential_id)
        .execute(&mut state.db.conn)
        .await
        .map_err(|e| {
            ApiError::DatabaseError(format!("Failed to update credential counter: {:?}", e))
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Credential counter updated successfully"
    })))
}

/// DELETE /api/webauthn/credentials/{credential_id}
/// Delete a WebAuthn credential
pub async fn delete_webauthn_credential(
    State(mut state): State<AppState>,
    Path(credential_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    query("DELETE FROM webauthn_credentials WHERE id = ?")
        .bind(&credential_id)
        .execute(&mut state.db.conn)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to delete credential: {:?}", e)))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Credential deleted successfully"
    })))
}

/// PATCH /api/webauthn/credentials/{credential_id}/name
/// Update credential name
pub async fn update_webauthn_credential_name(
    State(mut state): State<AppState>,
    Path(credential_id): Path<String>,
    JsonExtractor(payload): JsonExtractor<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let name = payload
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| ApiError::ValidationError("Name is required".to_string()))?;

    query("UPDATE webauthn_credentials SET name = ? WHERE id = ?")
        .bind(name)
        .bind(&credential_id)
        .execute(&mut state.db.conn)
        .await
        .map_err(|e| {
            ApiError::DatabaseError(format!("Failed to update credential name: {:?}", e))
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Credential name updated successfully"
    })))
}

/// POST /api/webauthn/challenges
/// Store a WebAuthn challenge
pub async fn store_webauthn_challenge(
    State(mut state): State<AppState>,
    JsonExtractor(payload): JsonExtractor<StoreChallengeRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let now = datetime_to_timestamp(Utc::now());

    query(
        "INSERT INTO webauthn_challenges (id, challenge, user_id, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&payload.id)
    .bind(&payload.challenge)
    .bind(payload.user_id.as_deref())
    .bind(&payload.challenge_type)
    .bind(payload.expires_at)
    .bind(now)
    .execute(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Failed to store challenge: {:?}", e)))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Challenge stored successfully"
    })))
}

/// GET /api/webauthn/challenges/{challenge_id}
/// Get a WebAuthn challenge
pub async fn get_webauthn_challenge(
    State(mut state): State<AppState>,
    Path(challenge_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let challenge = query_as::<WebAuthnChallenge>(
        "SELECT id, challenge, user_id, type as challenge_type, expires_at, created_at FROM webauthn_challenges WHERE id = ?"
    )
    .bind(&challenge_id)
    .fetch_optional(&mut state.db.conn)
    .await
    .map_err(|e| ApiError::DatabaseError(format!("Database error: {:?}", e)))?;

    match challenge {
        Some(chal) => {
            let response = ChallengeResponse {
                id: chal.id,
                challenge: chal.challenge,
                user_id: chal.user_id,
                challenge_type: chal.challenge_type,
                expires_at: chal.expires_at,
                created_at: chal.created_at,
            };

            Ok(Json(serde_json::json!({
                "success": true,
                "challenge": response
            })))
        }
        None => Ok(Json(serde_json::json!({
            "success": false,
            "error": "Challenge not found"
        }))),
    }
}

/// DELETE /api/webauthn/challenges/{challenge_id}
/// Delete a WebAuthn challenge
pub async fn delete_webauthn_challenge(
    State(mut state): State<AppState>,
    Path(challenge_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    query("DELETE FROM webauthn_challenges WHERE id = ?")
        .bind(&challenge_id)
        .execute(&mut state.db.conn)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to delete challenge: {:?}", e)))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Challenge deleted successfully"
    })))
}

/// GET /api/users/by-email/{email}
/// Get user by email address
pub async fn get_user_by_email(
    State(mut state): State<AppState>,
    Path(email): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let user = query_as::<User>("SELECT * FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(&mut state.db.conn)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Database error: {:?}", e)))?;

    match user {
        Some(u) => Ok(Json(serde_json::json!({
            "success": true,
            "user": u
        }))),
        None => Ok(Json(serde_json::json!({
            "success": false,
            "error": "User not found"
        }))),
    }
}
