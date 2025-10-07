use crate::db::DbPool;
use appattest_rs::{assertion::Assertion, attestation::Attestation};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AttestationChallengeRequest {
    pub platform: String,
    pub bundle_id: String,
}

#[derive(Debug, Serialize)]
pub struct AttestationChallengeResponse {
    pub success: bool,
    pub challenge: Option<String>,
    pub challenge_id: String,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AttestationVerifyRequest {
    pub challenge_id: String,
    pub key_id: String,
    pub attestation_object: String,
    pub bundle_id: String,
}

#[derive(Debug, Serialize)]
pub struct AttestationVerifyResponse {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssertionRequest {
    pub key_id: String,
    pub bundle_id: String,
    pub assertion: String,
    pub client_data: String,
}

#[derive(Debug, Serialize)]
pub struct AssertionResponse {
    pub success: bool,
    pub error: Option<String>,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn is_ios_simulator(user_agent: Option<&str>) -> bool {
    if let Some(ua) = user_agent {
        ua.contains("Simulator")
            || ua.contains("x86_64")
            || ua.contains("i386")
            || ua.contains("arm64-sim")
            || ua.contains("iPhone Simulator")
            || ua.contains("iPad Simulator")
    } else {
        false
    }
}

fn get_team_id() -> Result<String, String> {
    std::env::var("APPLE_TEAM_ID")
        .map_err(|_| "APPLE_TEAM_ID environment variable not set".to_string())
}

// ============================================================================
// Database Types
// ============================================================================

#[derive(sqlx::FromRow)]
struct StoredChallenge {
    challenge: String,
    bundle_id: String,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct StoredKey {
    public_key: Vec<u8>,
    counter: i64,
}

// ============================================================================
// Database Functions
// ============================================================================

async fn store_challenge(
    pool: &DbPool,
    challenge_id: &Uuid,
    challenge: &str,
    bundle_id: &str,
    platform: &str,
) -> Result<(), sqlx::Error> {
    let expires_at = Utc::now() + Duration::minutes(10);

    sqlx::query(
        "INSERT INTO app_attest_challenges (id, challenge, bundle_id, platform, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(challenge_id)
    .bind(challenge)
    .bind(bundle_id)
    .bind(platform)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(())
}

async fn get_challenge(
    pool: &DbPool,
    challenge_id: &str,
) -> Result<Option<StoredChallenge>, sqlx::Error> {
    sqlx::query_as::<_, StoredChallenge>(
        "SELECT challenge, bundle_id, expires_at FROM app_attest_challenges WHERE id = $1",
    )
    .bind(challenge_id)
    .fetch_optional(pool)
    .await
}

async fn delete_challenge(pool: &DbPool, challenge_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM app_attest_challenges WHERE id = $1")
        .bind(challenge_id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn store_key(
    pool: &DbPool,
    key_id: &str,
    bundle_id: &str,
    public_key: &[u8],
    counter: i64,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO app_attest_keys (key_id, bundle_id, public_key, counter, created_at, last_used_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (key_id)
         DO UPDATE SET last_used_at = $6, counter = $4",
    )
    .bind(key_id)
    .bind(bundle_id)
    .bind(public_key)
    .bind(counter)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

async fn get_key(
    pool: &DbPool,
    key_id: &str,
    bundle_id: &str,
) -> Result<Option<StoredKey>, sqlx::Error> {
    sqlx::query_as::<_, StoredKey>(
        "SELECT public_key, counter FROM app_attest_keys WHERE key_id = $1 AND bundle_id = $2",
    )
    .bind(key_id)
    .bind(bundle_id)
    .fetch_optional(pool)
    .await
}

async fn update_key_counter(
    pool: &DbPool,
    key_id: &str,
    new_counter: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE app_attest_keys SET counter = $1, last_used_at = $2 WHERE key_id = $3")
        .bind(new_counter)
        .bind(Utc::now())
        .bind(key_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// API Endpoints
// ============================================================================

/// Generate a challenge for iOS App Attestation
pub async fn challenge(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Json(request): Json<AttestationChallengeRequest>,
) -> impl IntoResponse {
    tracing::info!(
        platform = %request.platform,
        bundle_id = %request.bundle_id,
        "App Attestation challenge request"
    );

    // Validate platform
    if request.platform != "ios" {
        return Json(AttestationChallengeResponse {
            success: false,
            challenge: None,
            challenge_id: String::new(),
            error: Some("Only iOS platform is supported".to_string()),
        });
    }

    // Check for simulator
    let user_agent = headers.get("user-agent").and_then(|h| h.to_str().ok());
    if is_ios_simulator(user_agent) {
        tracing::info!("Simulator detected - returning dummy challenge");
        let challenge_id = Uuid::new_v4().to_string();
        return Json(AttestationChallengeResponse {
            success: true,
            challenge: Some("c2ltdWxhdG9yLWNoYWxsZW5nZQ==".to_string()),
            challenge_id,
            error: None,
        });
    }

    // Generate cryptographically secure challenge
    use rand::RngCore;
    let mut challenge_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);

    let challenge_base64 = base64::engine::general_purpose::STANDARD.encode(challenge_bytes);
    let challenge_id = Uuid::new_v4();

    // Store challenge
    match store_challenge(
        &pool,
        &challenge_id,
        &challenge_base64,
        &request.bundle_id,
        &request.platform,
    )
    .await
    {
        Ok(_) => {
            tracing::info!(challenge_id = %challenge_id, "Generated attestation challenge");
            Json(AttestationChallengeResponse {
                success: true,
                challenge: Some(challenge_base64),
                challenge_id: challenge_id.to_string(),
                error: None,
            })
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to store challenge");
            Json(AttestationChallengeResponse {
                success: false,
                challenge: None,
                challenge_id: String::new(),
                error: Some("Internal server error".to_string()),
            })
        }
    }
}

/// Verify iOS App Attestation
#[axum::debug_handler]
pub async fn verify_attestation(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Json(request): Json<AttestationVerifyRequest>,
) -> impl IntoResponse {
    tracing::info!(
        challenge_id = %request.challenge_id,
        key_id = %request.key_id,
        bundle_id = %request.bundle_id,
        "App Attestation verify request"
    );

    // Check for simulator
    let user_agent = headers.get("user-agent").and_then(|h| h.to_str().ok());
    if is_ios_simulator(user_agent) {
        tracing::info!("Simulator detected - skipping Apple verification");

        // Store dummy key for simulator
        let dummy_key = vec![0u8; 65];
        if let Err(e) = store_key(&pool, &request.key_id, &request.bundle_id, &dummy_key, 0).await
        {
            tracing::error!(error = %e, "Failed to store simulator key");
        }
        let _ = delete_challenge(&pool, &request.challenge_id).await;

        return (
            StatusCode::OK,
            Json(AttestationVerifyResponse {
                success: true,
                error: None,
            }),
        );
    }

    // Fetch challenge
    let stored_challenge = match get_challenge(&pool, &request.challenge_id).await {
        Ok(Some(ch)) => ch,
        Ok(None) => {
            tracing::warn!(challenge_id = %request.challenge_id, "Challenge not found");
            return (
                StatusCode::BAD_REQUEST,
                Json(AttestationVerifyResponse {
                    success: false,
                    error: Some("Invalid challenge".to_string()),
                }),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AttestationVerifyResponse {
                    success: false,
                    error: Some("Internal server error".to_string()),
                }),
            );
        }
    };

    // Validate challenge
    if stored_challenge.expires_at < Utc::now() {
        tracing::warn!("Challenge expired");
        return (
            StatusCode::BAD_REQUEST,
            Json(AttestationVerifyResponse {
                success: false,
                error: Some("Challenge expired".to_string()),
            }),
        );
    }

    if stored_challenge.bundle_id != request.bundle_id {
        tracing::warn!(
            expected = %stored_challenge.bundle_id,
            got = %request.bundle_id,
            "Bundle ID mismatch"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(AttestationVerifyResponse {
                success: false,
                error: Some("Bundle ID mismatch".to_string()),
            }),
        );
    }

    // Get team ID
    let team_id = match get_team_id() {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("Team ID configuration error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AttestationVerifyResponse {
                    success: false,
                    error: Some("Server configuration error".to_string()),
                }),
            );
        }
    };

    let app_id = format!("{}.{}", team_id, request.bundle_id);

    // Decode challenge
    let challenge_bytes = match base64::engine::general_purpose::STANDARD.decode(&stored_challenge.challenge) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = %e, "Failed to decode challenge");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AttestationVerifyResponse {
                    success: false,
                    error: Some("Internal server error".to_string()),
                }),
            );
        }
    };

    let challenge_str = std::str::from_utf8(&challenge_bytes).unwrap_or(&stored_challenge.challenge);

    // Parse and verify attestation
    let attestation = match Attestation::from_base64(&request.attestation_object) {
        Ok(att) => att,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to parse attestation");
            return (
                StatusCode::BAD_REQUEST,
                Json(AttestationVerifyResponse {
                    success: false,
                    error: Some("Invalid attestation object".to_string()),
                }),
            );
        }
    };

    // Verify attestation
    let (public_key, _receipt) = match attestation.verify(challenge_str, &app_id, &request.key_id) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = ?e, "Attestation verification failed");
            return (
                StatusCode::BAD_REQUEST,
                Json(AttestationVerifyResponse {
                    success: false,
                    error: Some(format!("Attestation verification failed: {:?}", e)),
                }),
            );
        }
    };

    tracing::info!(
        key_id = %request.key_id,
        public_key_len = public_key.len(),
        "Attestation verification successful"
    );

    // Store verified key
    if let Err(e) = store_key(&pool, &request.key_id, &request.bundle_id, &public_key, 0).await {
        tracing::error!(error = %e, "Failed to store verified key");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AttestationVerifyResponse {
                success: false,
                error: Some("Internal server error".to_string()),
            }),
        );
    }

    // Clean up challenge
    let _ = delete_challenge(&pool, &request.challenge_id).await;

    (
        StatusCode::OK,
        Json(AttestationVerifyResponse {
            success: true,
            error: None,
        }),
    )
}

/// Verify an assertion for an already-attested key
#[axum::debug_handler]
pub async fn verify_assertion(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Json(request): Json<AssertionRequest>,
) -> impl IntoResponse {
    tracing::info!(
        key_id = %request.key_id,
        bundle_id = %request.bundle_id,
        "App Attestation assertion request"
    );

    // Check for simulator
    let user_agent = headers.get("user-agent").and_then(|h| h.to_str().ok());
    if is_ios_simulator(user_agent) {
        tracing::info!("Simulator detected - skipping assertion verification");
        return (
            StatusCode::OK,
            Json(AssertionResponse {
                success: true,
                error: None,
            }),
        );
    }

    // Get stored key
    let stored_key = match get_key(&pool, &request.key_id, &request.bundle_id).await {
        Ok(Some(key)) => key,
        Ok(None) => {
            tracing::warn!(
                key_id = %request.key_id,
                bundle_id = %request.bundle_id,
                "Key not found"
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(AssertionResponse {
                    success: false,
                    error: Some("Unknown key ID or bundle ID mismatch".to_string()),
                }),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AssertionResponse {
                    success: false,
                    error: Some("Internal server error".to_string()),
                }),
            );
        }
    };

    // Get team ID
    let team_id = match get_team_id() {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("Team ID configuration error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AssertionResponse {
                    success: false,
                    error: Some("Server configuration error".to_string()),
                }),
            );
        }
    };

    let app_id = format!("{}.{}", team_id, request.bundle_id);

    // Decode client data
    let client_data_bytes = match base64::engine::general_purpose::STANDARD.decode(&request.client_data) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = %e, "Failed to decode client data");
            return (
                StatusCode::BAD_REQUEST,
                Json(AssertionResponse {
                    success: false,
                    error: Some("Invalid client data encoding".to_string()),
                }),
            );
        }
    };

    // Parse assertion
    let assertion = match Assertion::from_base64(&request.assertion) {
        Ok(ass) => ass,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to parse assertion");
            return (
                StatusCode::BAD_REQUEST,
                Json(AssertionResponse {
                    success: false,
                    error: Some("Invalid assertion object".to_string()),
                }),
            );
        }
    };

    // Verify assertion
    if let Err(e) = assertion.verify(
        client_data_bytes,
        &app_id,
        stored_key.public_key,
        stored_key.counter as u32,
        &request.client_data,
    ) {
        tracing::error!(error = ?e, "Assertion verification failed");
        return (
            StatusCode::BAD_REQUEST,
            Json(AssertionResponse {
                success: false,
                error: Some(format!("Assertion verification failed: {:?}", e)),
            }),
        );
    }

    tracing::info!(
        key_id = %request.key_id,
        old_counter = stored_key.counter,
        "Assertion verification successful"
    );

    // Update counter
    let new_counter = stored_key.counter + 1;
    if let Err(e) = update_key_counter(&pool, &request.key_id, new_counter).await {
        tracing::error!(error = %e, "Failed to update key counter");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AssertionResponse {
                success: false,
                error: Some("Internal server error".to_string()),
            }),
        );
    }

    (
        StatusCode::OK,
        Json(AssertionResponse {
            success: true,
            error: None,
        }),
    )
}
