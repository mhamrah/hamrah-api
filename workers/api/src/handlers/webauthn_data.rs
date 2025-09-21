// WebAuthn data persistence handlers
// These endpoints only handle data storage/retrieval for WebAuthn operations
// The actual WebAuthn protocol logic is handled in hamrah-web

use crate::db::schema::{WebAuthnChallenge, WebAuthnCredential};
use crate::utils::datetime_to_timestamp;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Json,
    Json as JsonExtractor,
};
use base64::prelude::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx_d1::{query, query_as};

use crate::error::{AppError, AppResult};
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
) -> AppResult<Json<serde_json::Value>> {
    let now = datetime_to_timestamp(Utc::now());

    // Pre-base64 summary log (raw lengths)
    worker::console_log!(
        "🛠️ WEBAUTHN/API store_webauthn_credential: START id={}; user_id={}; counter={}; transports_count={}; aaguid_len={}; credential_type={}; user_verified={}; credential_device_type={:?}; credential_backed_up={}; name_present={}; public_key_raw_len={}",
        payload.id,
        payload.user_id,
        payload.counter,
        payload.transports.as_ref().map(|t| t.len()).unwrap_or(0),
        payload.aaguid.as_ref().map(|a| a.len()).unwrap_or(0),
        payload.credential_type,
        payload.user_verified,
        payload.credential_device_type,
        payload.credential_backed_up,
        payload.name.is_some(),
        payload.public_key.len()
    );

    // Convert Vec<u8> to base64 string for storage
    let public_key_b64 = BASE64_STANDARD.encode(&payload.public_key);
    let aaguid_b64 = payload.aaguid.as_ref().map(|a| BASE64_STANDARD.encode(a));
    let transports_json = payload
        .transports
        .as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_default());

    // Detailed transformed log including full base64 (DEV INTENTIONAL - requested full verbosity)
    worker::console_log!(
        "🛠️ WEBAUTHN/API store_webauthn_credential: TRANSFORM id={}; public_key_b64_len={}; public_key_b64={}; aaguid_b64_len={}; aaguid_b64={:?}; transports_json_len={}; transports_json={:?}; name={:?}",
        payload.id,
        public_key_b64.len(),
        public_key_b64,
        aaguid_b64.as_ref().map(|s| s.len()).unwrap_or(0),
        aaguid_b64,
        transports_json.as_ref().map(|s| s.len()).unwrap_or(0),
        transports_json,
        payload.name
    );

    let insert_start = datetime_to_timestamp(Utc::now());
    let result = query(
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
    .bind(if payload.user_verified { 1i64 } else { 0i64 }) // Convert bool to i64
    .bind(payload.credential_device_type.as_deref())
    .bind(if payload.credential_backed_up {
        1i64
    } else {
        0i64
    }) // Convert bool to i64
    .bind(payload.name.as_deref())
    .bind(now)
    .execute(&mut state.db.conn)
    .await;

    match result {
        Ok(_) => {
            let end = datetime_to_timestamp(Utc::now());
            worker::console_log!(
                "💽 WEBAUTHN/DB store_webauthn_credential: SUCCESS id={}; duration_ms={}",
                payload.id,
                end - insert_start
            );
        }
        Err(e) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB store_webauthn_credential: ERROR id={}; error={:?}",
                payload.id,
                e
            );
            return Err(Box::new(AppError::from(e)));
        }
    }

    worker::console_log!(
        "🛠️ WEBAUTHN/API store_webauthn_credential: COMPLETE id={}",
        payload.id
    );

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
) -> AppResult<Json<serde_json::Value>> {
    worker::console_log!(
        "🛠️ WEBAUTHN/API get_webauthn_credential: START id={}",
        credential_id
    );
    let query_start = datetime_to_timestamp(Utc::now());
    let credential =
        query_as::<WebAuthnCredential>("SELECT * FROM webauthn_credentials WHERE id = ?")
            .bind(&credential_id)
            .fetch_optional(&mut state.db.conn)
            .await
            .map_err(|e| {
                worker::console_log!(
                    "💽 WEBAUTHN/DB get_webauthn_credential: ERROR id={}; error={:?}",
                    credential_id,
                    e
                );
                format!("Database error: {:?}", e)
            })
            .map_err(AppError::from)?;
    let query_end = datetime_to_timestamp(Utc::now());
    worker::console_log!(
        "💽 WEBAUTHN/DB get_webauthn_credential: SUCCESS id={}; found={}; duration_ms={}",
        credential_id,
        credential.is_some(),
        query_end - query_start
    );

    match credential {
        Some(cred) => {
            worker::console_log!(
                "🛠️ WEBAUTHN/API get_webauthn_credential: FOUND id={}; user_id={}; counter={}; transports_len={}; aaguid_len={}; name_present={}",
                cred.id,
                cred.user_id,
                cred.counter,
                cred.transports.as_ref().map(|s| s.len()).unwrap_or(0),
                cred.aaguid.as_ref().map(|s| s.len()).unwrap_or(0),
                cred.name.is_some()
            );
            // Convert base64 strings back to Vec<u8>
            let public_key = BASE64_STANDARD
                .decode(&cred.public_key)
                .map_err(|e| format!("Failed to decode public key: {:?}", e))?;

            let aaguid = cred
                .aaguid
                .as_ref()
                .map(|a| BASE64_STANDARD.decode(a))
                .transpose()
                .map_err(|e| format!("Failed to decode aaguid: {:?}", e))?;

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
                user_verified: cred.user_verified != 0, // Convert i64 to bool
                credential_device_type: cred.credential_device_type,
                credential_backed_up: cred.credential_backed_up != 0, // Convert i64 to bool
                name: cred.name,
                last_used: cred.last_used,
                created_at: cred.created_at,
            };

            Ok(Json(serde_json::json!({
                "success": true,
                "credential": response
            })))
        }
        None => {
            worker::console_log!(
                "🛠️ WEBAUTHN/API get_webauthn_credential: NOT_FOUND id={}",
                credential_id
            );
            Err(Box::new(AppError::not_found("Credential not found")))
        }
    }
}

/// GET /api/webauthn/users/{user_id}/credentials
/// Get all WebAuthn credentials for a user
pub async fn get_user_webauthn_credentials(
    State(mut state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    worker::console_log!(
        "🔑 WEBAUTHN: Starting get_user_webauthn_credentials for user_id: {}",
        user_id
    );

    // Authenticate user
    worker::console_log!("🔑 WEBAUTHN: Attempting to authenticate user...");
    let current_user = match crate::handlers::users::get_current_user_from_request(
        &mut state.db,
        &headers,
    )
    .await
    {
        Ok(user) => {
            worker::console_log!(
                "🔑 WEBAUTHN: ✅ Authentication successful for user: {}",
                user.id
            );
            user
        }
        Err(e) => {
            worker::console_log!("🔑 WEBAUTHN: ❌ Authentication failed: {:?}", e);
            return Err(e);
        }
    };

    // Authorization: users can only access their own credentials
    worker::console_log!(
        "🔑 WEBAUTHN: Checking authorization - current_user.id: {}, requested_user_id: {}",
        current_user.id,
        user_id
    );
    if current_user.id != user_id {
        worker::console_log!(
            "🔑 WEBAUTHN: ❌ Authorization failed - user {} cannot access credentials for user {}",
            current_user.id,
            user_id
        );
        return Err(Box::new(AppError::forbidden(
            "Unauthorized: cannot access other user's credentials",
        )));
    }

    worker::console_log!(
        "🔑 WEBAUTHN: ✅ Authorization successful - fetching credentials from database..."
    );
    let credentials = match query_as::<WebAuthnCredential>(
        "SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(&user_id)
    .fetch_all(&mut state.db.conn)
    .await
    {
        Ok(creds) => {
            worker::console_log!(
                "🔑 WEBAUTHN: ✅ Database query successful - found {} credentials",
                creds.len()
            );
            for (i, cred) in creds.iter().enumerate() {
                worker::console_log!(
                    "🔑 WEBAUTHN: Credential {}: id={}, user_verified={}, credential_backed_up={}",
                    i,
                    cred.id,
                    cred.user_verified,
                    cred.credential_backed_up
                );
            }
            creds
        }
        Err(e) => {
            worker::console_log!("🔑 WEBAUTHN: ❌ Database query failed: {:?}", e);
            return Err(Box::new(AppError::from(e)));
        }
    };

    worker::console_log!(
        "🔑 WEBAUTHN: Processing {} credentials for response...",
        credentials.len()
    );
    let mut credential_responses: Vec<CredentialResponse> = Vec::new();

    for (i, cred) in credentials.into_iter().enumerate() {
        worker::console_log!("🔑 WEBAUTHN: Processing credential {}: {}", i, cred.id);

        // Convert base64 strings back to Vec<u8>
        let public_key = match BASE64_STANDARD.decode(&cred.public_key) {
            Ok(key) => {
                worker::console_log!(
                    "🔑 WEBAUTHN: ✅ Public key decoded successfully for credential {}",
                    cred.id
                );
                key
            }
            Err(e) => {
                worker::console_log!(
                    "🔑 WEBAUTHN: ❌ Failed to decode public key for credential {}: {:?}",
                    cred.id,
                    e
                );
                continue; // Skip this credential
            }
        };

        let aaguid = match cred.aaguid.as_ref() {
            Some(a) => match BASE64_STANDARD.decode(a) {
                Ok(decoded) => {
                    worker::console_log!(
                        "🔑 WEBAUTHN: ✅ AAGUID decoded successfully for credential {}",
                        cred.id
                    );
                    Some(decoded)
                }
                Err(e) => {
                    worker::console_log!(
                        "🔑 WEBAUTHN: ❌ Failed to decode AAGUID for credential {}: {:?}",
                        cred.id,
                        e
                    );
                    continue; // Skip this credential
                }
            },
            None => {
                worker::console_log!("🔑 WEBAUTHN: No AAGUID for credential {}", cred.id);
                None
            }
        };

        let transports: Option<Vec<String>> = cred
            .transports
            .as_ref()
            .map(|t| serde_json::from_str(t).unwrap_or_default());

        worker::console_log!("🔑 WEBAUTHN: Converting boolean fields - user_verified: {} -> {}, credential_backed_up: {} -> {}",
            cred.user_verified, cred.user_verified != 0, cred.credential_backed_up, cred.credential_backed_up != 0);

        credential_responses.push(CredentialResponse {
            id: cred.id.clone(),
            user_id: cred.user_id,
            public_key,
            counter: cred.counter,
            transports,
            aaguid,
            credential_type: cred.credential_type,
            user_verified: cred.user_verified != 0, // Convert i64 to bool
            credential_device_type: cred.credential_device_type,
            credential_backed_up: cred.credential_backed_up != 0, // Convert i64 to bool
            name: cred.name,
            last_used: cred.last_used,
            created_at: cred.created_at,
        });

        worker::console_log!(
            "🔑 WEBAUTHN: ✅ Successfully processed credential {}",
            cred.id
        );
    }

    worker::console_log!(
        "🔑 WEBAUTHN: ✅ Returning {} processed credentials",
        credential_responses.len()
    );
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
) -> AppResult<Json<serde_json::Value>> {
    worker::console_log!(
        "🛠️ WEBAUTHN/API update_webauthn_credential_counter: START id={}; new_counter={}; last_used={}",
        credential_id,
        payload.counter,
        payload.last_used
    );
    let start_ts = datetime_to_timestamp(Utc::now());

    let result = query("UPDATE webauthn_credentials SET counter = ?, last_used = ? WHERE id = ?")
        .bind(payload.counter)
        .bind(payload.last_used)
        .bind(&credential_id)
        .execute(&mut state.db.conn)
        .await;

    match result {
        Ok(_) => {
            let end_ts = datetime_to_timestamp(Utc::now());
            worker::console_log!(
                "💽 WEBAUTHN/DB update_webauthn_credential_counter: SUCCESS id={}; duration_ms={}",
                credential_id,
                end_ts - start_ts
            );
        }
        Err(e) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB update_webauthn_credential_counter: ERROR id={}; error={:?}",
                credential_id,
                e
            );
            return Err(Box::new(AppError::from(e)));
        }
    }

    worker::console_log!(
        "🛠️ WEBAUTHN/API update_webauthn_credential_counter: COMPLETE id={}",
        credential_id
    );

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
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    worker::console_log!(
        "🛠️ WEBAUTHN/API delete_webauthn_credential: START id={}",
        credential_id
    );
    // Authenticate user
    let current_user_res =
        crate::handlers::users::get_current_user_from_request(&mut state.db, &headers).await;
    let current_user = match current_user_res {
        Ok(u) => {
            worker::console_log!(
                "🛠️ WEBAUTHN/API delete_webauthn_credential: AUTH_OK user_id={}",
                u.id
            );
            u
        }
        Err(e) => {
            worker::console_log!(
                "🛠️ WEBAUTHN/API delete_webauthn_credential: AUTH_ERR id={}; error={:?}",
                credential_id,
                e
            );
            return Err(e);
        }
    };

    // Check if credential exists and belongs to the current user
    worker::console_log!(
        "🛠️ WEBAUTHN/API delete_webauthn_credential: FETCH_CREDENTIAL id={}",
        credential_id
    );
    let fetch_start = datetime_to_timestamp(Utc::now());
    let credential_res =
        query_as::<WebAuthnCredential>("SELECT * FROM webauthn_credentials WHERE id = ?")
            .bind(&credential_id)
            .fetch_optional(&mut state.db.conn)
            .await;
    let fetch_end = datetime_to_timestamp(Utc::now());

    let credential = match credential_res {
        Ok(c) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB delete_webauthn_credential: FETCH_OK id={}; found={}; duration_ms={}",
                credential_id,
                c.is_some(),
                fetch_end - fetch_start
            );
            c
        }
        Err(e) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB delete_webauthn_credential: FETCH_ERR id={}; error={:?}",
                credential_id,
                e
            );
            return Err(Box::new(AppError::from(e)));
        }
    };

    match credential {
        Some(cred) => {
            worker::console_log!(
                "🛠️ WEBAUTHN/API delete_webauthn_credential: CREDENTIAL_FOUND id={}; user_id={}; counter={}",
                cred.id,
                cred.user_id,
                cred.counter
            );
            if cred.user_id != current_user.id {
                worker::console_log!(
                    "🛠️ WEBAUTHN/API delete_webauthn_credential: UNAUTHORIZED id={}; requester_user_id={}; owner_user_id={}",
                    credential_id,
                    current_user.id,
                    cred.user_id
                );
                return Err(Box::new(AppError::forbidden(
                    "Unauthorized: cannot delete other user's credential",
                )));
            }
        }
        None => {
            worker::console_log!(
                "🛠️ WEBAUTHN/API delete_webauthn_credential: NOT_FOUND id={}",
                credential_id
            );
            return Err(Box::new(AppError::not_found("Credential not found")));
        }
    }

    worker::console_log!(
        "🛠️ WEBAUTHN/API delete_webauthn_credential: DELETING id={}",
        credential_id
    );
    let delete_start = datetime_to_timestamp(Utc::now());
    let delete_res = query("DELETE FROM webauthn_credentials WHERE id = ?")
        .bind(&credential_id)
        .execute(&mut state.db.conn)
        .await;
    let delete_end = datetime_to_timestamp(Utc::now());

    match delete_res {
        Ok(_) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB delete_webauthn_credential: DELETE_OK id={}; duration_ms={}",
                credential_id,
                delete_end - delete_start
            );
        }
        Err(e) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB delete_webauthn_credential: DELETE_ERR id={}; error={:?}",
                credential_id,
                e
            );
            return Err(Box::new(AppError::from(e)));
        }
    }

    worker::console_log!(
        "🛠️ WEBAUTHN/API delete_webauthn_credential: COMPLETE id={}",
        credential_id
    );

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
    headers: HeaderMap,
    JsonExtractor(payload): JsonExtractor<serde_json::Value>,
) -> AppResult<Json<serde_json::Value>> {
    worker::console_log!(
        "🛠️ WEBAUTHN/API update_webauthn_credential_name: START id={}",
        credential_id
    );

    // Authenticate user
    let auth_start = datetime_to_timestamp(Utc::now());
    let current_user_res =
        crate::handlers::users::get_current_user_from_request(&mut state.db, &headers).await;
    let current_user = match current_user_res {
        Ok(u) => {
            let auth_end = datetime_to_timestamp(Utc::now());
            worker::console_log!(
                "🛠️ WEBAUTHN/API update_webauthn_credential_name: AUTH_OK user_id={}; duration_ms={}",
                u.id,
                auth_end - auth_start
            );
            u
        }
        Err(e) => {
            worker::console_log!(
                "🛠️ WEBAUTHN/API update_webauthn_credential_name: AUTH_ERR id={}; error={:?}",
                credential_id,
                e
            );
            return Err(e);
        }
    };

    let name = payload
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| AppError::bad_request("Name is required"))?;
    worker::console_log!(
        "🛠️ WEBAUTHN/API update_webauthn_credential_name: NAME_EXTRACTED id={}; new_name_len={}; new_name=\"{}\"",
        credential_id,
        name.len(),
        name
    );

    // Fetch credential
    worker::console_log!(
        "🛠️ WEBAUTHN/API update_webauthn_credential_name: FETCH_CREDENTIAL id={}",
        credential_id
    );
    let fetch_start = datetime_to_timestamp(Utc::now());
    let credential_res =
        query_as::<WebAuthnCredential>("SELECT * FROM webauthn_credentials WHERE id = ?")
            .bind(&credential_id)
            .fetch_optional(&mut state.db.conn)
            .await;
    let fetch_end = datetime_to_timestamp(Utc::now());

    let credential = match credential_res {
        Ok(c) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB update_webauthn_credential_name: FETCH_OK id={}; found={}; duration_ms={}",
                credential_id,
                c.is_some(),
                fetch_end - fetch_start
            );
            c
        }
        Err(e) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB update_webauthn_credential_name: FETCH_ERR id={}; error={:?}",
                credential_id,
                e
            );
            return Err(Box::new(AppError::from(e)));
        }
    };

    match credential {
        Some(cred) => {
            worker::console_log!(
                "🛠️ WEBAUTHN/API update_webauthn_credential_name: CREDENTIAL_FOUND id={}; owner_user_id={}; requester_user_id={}; existing_name_present={}",
                cred.id,
                cred.user_id,
                current_user.id,
                cred.name.is_some()
            );
            if cred.user_id != current_user.id {
                worker::console_log!(
                    "🛠️ WEBAUTHN/API update_webauthn_credential_name: UNAUTHORIZED id={}; requester_user_id={}; owner_user_id={}",
                    credential_id,
                    current_user.id,
                    cred.user_id
                );
                return Err(Box::new(AppError::forbidden(
                    "Unauthorized: cannot update other user's credential",
                )));
            }
        }
        None => {
            worker::console_log!(
                "🛠️ WEBAUTHN/API update_webauthn_credential_name: NOT_FOUND id={}",
                credential_id
            );
            return Err(Box::new(AppError::not_found("Credential not found")));
        }
    }

    worker::console_log!(
        "🛠️ WEBAUTHN/API update_webauthn_credential_name: UPDATING id={}; new_name=\"{}\"",
        credential_id,
        name
    );
    let update_start = datetime_to_timestamp(Utc::now());
    let update_res = query("UPDATE webauthn_credentials SET name = ? WHERE id = ?")
        .bind(name)
        .bind(&credential_id)
        .execute(&mut state.db.conn)
        .await;
    let update_end = datetime_to_timestamp(Utc::now());

    match update_res {
        Ok(_) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB update_webauthn_credential_name: UPDATE_OK id={}; duration_ms={}",
                credential_id,
                update_end - update_start
            );
        }
        Err(e) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB update_webauthn_credential_name: UPDATE_ERR id={}; error={:?}",
                credential_id,
                e
            );
            return Err(Box::new(AppError::from(e)));
        }
    }

    worker::console_log!(
        "🛠️ WEBAUTHN/API update_webauthn_credential_name: COMPLETE id={}; new_name=\"{}\"",
        credential_id,
        name
    );

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
) -> AppResult<Json<serde_json::Value>> {
    let now = datetime_to_timestamp(Utc::now());
    worker::console_log!(
        "🛠️ WEBAUTHN/API store_webauthn_challenge: START id={}; type={}; user_id_present={}; expires_at={}",
        payload.id,
        payload.challenge_type,
        payload.user_id.is_some(),
        payload.expires_at
    );

    let insert_start = datetime_to_timestamp(Utc::now());
    let result = query(
        "INSERT INTO webauthn_challenges (id, challenge, user_id, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&payload.id)
    .bind(&payload.challenge)
    .bind(payload.user_id.as_deref())
    .bind(&payload.challenge_type)
    .bind(payload.expires_at)
    .bind(now)
    .execute(&mut state.db.conn)
    .await;

    match result {
        Ok(_) => {
            let insert_end = datetime_to_timestamp(Utc::now());
            worker::console_log!(
                "💽 WEBAUTHN/DB store_webauthn_challenge: SUCCESS id={}; duration_ms={}; challenge_len={}",
                payload.id,
                insert_end - insert_start,
                payload.challenge.len()
            );
        }
        Err(e) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB store_webauthn_challenge: ERROR id={}; error={:?}",
                payload.id,
                e
            );
            return Err(Box::new(AppError::from(e)));
        }
    }

    worker::console_log!(
        "🛠️ WEBAUTHN/API store_webauthn_challenge: COMPLETE id={}",
        payload.id
    );

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
) -> AppResult<Json<serde_json::Value>> {
    worker::console_log!(
        "🛠️ WEBAUTHN/API get_webauthn_challenge: START id={}",
        challenge_id
    );
    let query_start = datetime_to_timestamp(Utc::now());
    let challenge_res = query_as::<WebAuthnChallenge>(
        "SELECT id, challenge, user_id, type as challenge_type, expires_at, created_at FROM webauthn_challenges WHERE id = ?"
    )
    .bind(&challenge_id)
    .fetch_optional(&mut state.db.conn)
    .await;
    let query_end = datetime_to_timestamp(Utc::now());

    let challenge = match challenge_res {
        Ok(c) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB get_webauthn_challenge: SUCCESS id={}; found={}; duration_ms={}",
                challenge_id,
                c.is_some(),
                query_end - query_start
            );
            c
        }
        Err(e) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB get_webauthn_challenge: ERROR id={}; error={:?}",
                challenge_id,
                e
            );
            return Err(Box::new(AppError::from(e)));
        }
    };

    match challenge {
        Some(chal) => {
            worker::console_log!(
                "🛠️ WEBAUTHN/API get_webauthn_challenge: FOUND id={}; type={}; user_id_present={}; expires_at={}; challenge_len={}",
                chal.id,
                chal.challenge_type,
                chal.user_id.is_some(),
                chal.expires_at,
                chal.challenge.len()
            );
            let response = ChallengeResponse {
                id: chal.id,
                challenge: chal.challenge,
                user_id: chal.user_id,
                challenge_type: chal.challenge_type,
                expires_at: chal.expires_at,
                created_at: chal.created_at,
            };

            worker::console_log!(
                "🛠️ WEBAUTHN/API get_webauthn_challenge: COMPLETE id={}",
                response.id
            );

            Ok(Json(serde_json::json!({
                "success": true,
                "challenge": response
            })))
        }
        None => {
            worker::console_log!(
                "🛠️ WEBAUTHN/API get_webauthn_challenge: NOT_FOUND id={}",
                challenge_id
            );
            Err(Box::new(AppError::not_found("Challenge not found")))
        }
    }
}

/// DELETE /api/webauthn/challenges/{challenge_id}
/// Delete a WebAuthn challenge
pub async fn delete_webauthn_challenge(
    State(mut state): State<AppState>,
    Path(challenge_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    worker::console_log!(
        "🛠️ WEBAUTHN/API delete_webauthn_challenge: START id={}",
        challenge_id
    );
    let delete_start = datetime_to_timestamp(Utc::now());
    let delete_res = query("DELETE FROM webauthn_challenges WHERE id = ?")
        .bind(&challenge_id)
        .execute(&mut state.db.conn)
        .await;
    let delete_end = datetime_to_timestamp(Utc::now());

    match delete_res {
        Ok(_) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB delete_webauthn_challenge: SUCCESS id={}; duration_ms={}",
                challenge_id,
                delete_end - delete_start
            );
        }
        Err(e) => {
            worker::console_log!(
                "💽 WEBAUTHN/DB delete_webauthn_challenge: ERROR id={}; error={:?}",
                challenge_id,
                e
            );
            return Err(Box::new(AppError::from(e)));
        }
    }

    worker::console_log!(
        "🛠️ WEBAUTHN/API delete_webauthn_challenge: COMPLETE id={}",
        challenge_id
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Challenge deleted successfully"
    })))
}

// REMOVED: get_user_by_email endpoint for security reasons
// Public user enumeration endpoint removed to prevent user discovery attacks
