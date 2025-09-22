use crate::db::Database;
use crate::shared_handles::SharedHandles;
use crate::utils::datetime_to_timestamp;
use axum::extract::Request as AxumRequest;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::{middleware::Next, response::Response};
use chrono::Utc;
use ciborium::value::Value as CborValue;
use ciborium::{de::from_reader as cbor_from_reader, ser::into_writer as cbor_into_writer};
use jwt_simple::prelude::*;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use sqlx_d1::query;
use worker::{console_log, Env, Fetch, Method, Request, RequestInit};

/// JWT Claims for Apple App Attest API authentication
#[derive(Debug, Serialize, Deserialize)]
struct AppAttestJWTClaims {
    pub iss: String, // Team ID
    pub aud: String, // Apple's App Attest audience
    pub sub: String, // Bundle ID
}

/// Apple App Attestation request payload
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AttestationPayload {
    attestation_object: String,
    challenge: String,
    key_id: String,
}

/// Apple App Attestation response
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AppleAttestResponse {
    receipt: Option<String>,
    error: Option<AppleAttestError>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AppleAttestError {
    code: i32,
    message: String,
}

/// Checks if the request is coming from iOS Simulator
pub fn is_ios_simulator(user_agent: Option<&str>) -> bool {
    let ua = user_agent.unwrap_or("");

    // Check for simulator indicators in user agent
    ua.contains("Simulator")
        || ua.contains("x86_64")
        || ua.contains("arm64-sim")
        || ua.contains("i386")
        || ua.contains("iPhone Simulator")
        || ua.contains("iPad Simulator")
}

/// Validates Apple App Attestation token against Apple's service
pub async fn validate_app_attestation(
    attestation_token: &str,
    env: &Env,
) -> Result<Option<String>, String> {
    // Parse the attestation token (should be base64 encoded JSON)
    let attestation_data = parse_attestation_token(attestation_token)?;

    // Create JWT for Apple API authentication
    let jwt_token = create_apple_jwt(env).await?;

    // Verify against Apple's App Attest service
    let receipt = verify_with_apple(&attestation_data, &jwt_token).await?;

    Ok(receipt)
}

/// Parse and validate the attestation token format
fn parse_attestation_token(token: &str) -> Result<AttestationPayload, String> {
    use base64::Engine;

    // Parse the attestation token (should be base64 encoded JSON)
    let attestation_data = base64::engine::general_purpose::STANDARD
        .decode(token)
        .map_err(|_| {
            console_log!("App Attestation: Invalid base64 token");
            "Invalid attestation token format".to_string()
        })?;

    let attestation_json = String::from_utf8(attestation_data).map_err(|_| {
        console_log!("App Attestation: Invalid UTF-8 in token");
        "Invalid attestation token encoding".to_string()
    })?;

    let payload: AttestationPayload = serde_json::from_str(&attestation_json).map_err(|e| {
        console_log!("App Attestation: Failed to parse JSON: {}", e);
        "Invalid attestation token structure".to_string()
    })?;
    Ok(payload)
}

/// Creates a JWT token for authenticating with Apple's App Attest API using jwt-simple
async fn create_apple_jwt(env: &Env) -> Result<String, String> {
    // Get required environment variables
    let bundle_id = env
        .var("APPLE_BUNDLE_ID")
        .map_err(|_| "APPLE_BUNDLE_ID not configured".to_string())?
        .to_string();

    let team_id = env
        .var("APPLE_TEAM_ID")
        .map_err(|_| "APPLE_TEAM_ID not configured".to_string())?
        .to_string();

    let _key_id = env
        .var("APPLE_KEY_ID")
        .map_err(|_| "APPLE_KEY_ID not configured".to_string())?
        .to_string();

    let private_key = env
        .var("APPLE_PRIVATE_KEY")
        .map_err(|_| "APPLE_PRIVATE_KEY not configured".to_string())?
        .to_string();

    // Parse the private key using jwt-simple
    let key_pair = ES256KeyPair::from_pem(&private_key).map_err(|e| {
        console_log!("App Attestation: Failed to parse private key: {}", e);
        "Invalid private key format".to_string()
    })?;

    // Create JWT claims
    let claims = AppAttestJWTClaims {
        iss: team_id,
        aud: "https://api.devicecheck.apple.com/v1".to_string(),
        sub: bundle_id,
    };

    // Create token with custom header including key ID
    let claims_with_expiry = Claims::with_custom_claims(claims, Duration::from_hours(1));
    let token = key_pair.sign(claims_with_expiry).map_err(|e| {
        console_log!("App Attestation: Failed to sign JWT: {}", e);
        "Failed to sign JWT token".to_string()
    })?;

    Ok(token)
}

/// Verifies attestation with Apple's App Attest service
async fn verify_with_apple(
    attestation: &AttestationPayload,
    jwt_token: &str,
) -> Result<Option<String>, String> {
    // Construct Apple's App Attest verification URL
    let verify_url = "https://api.devicecheck.apple.com/v1/attestation";

    // Prepare the payload for Apple
    let payload = serde_json::json!({
        "attestation_object": attestation.attestation_object,
        "challenge": attestation.challenge,
        "key_id": attestation.key_id,
    });

    // Prepare the request
    #[allow(unused_mut)]
    let mut h = worker::Headers::new();
    h.set("Content-Type", "application/json")
        .map_err(|e| format!("Header creation failed: {:?}", e))?;
    h.set("Authorization", &format!("Bearer {}", jwt_token))
        .map_err(|e| format!("Header creation failed: {:?}", e))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(serde_json::to_string(&payload).unwrap().into()));
    init.with_headers(h);

    let request = Request::new_with_init(verify_url, &init)
        .map_err(|e| format!("Request creation failed: {:?}", e))?;

    let mut response = Fetch::Request(request).send().await.map_err(|e| {
        console_log!("App Attestation: Request failed: {:?}", e);
        format!("Apple verification request failed: {:?}", e)
    })?;

    let status = response.status_code();

    if status == 200 {
        // Success: parse receipt from Apple's response
        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {:?}", e))?;
        let parsed: AppleAttestResponse = serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse Apple response: {:?}", e))?;
        Ok(parsed.receipt)
    } else {
        // Parse error response
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| format!("HTTP {}", status));

        console_log!("App Attestation: Apple verification failed: {}", error_text);

        Err(format!(
            "Apple attestation verification failed ({}): {}",
            status, error_text
        ))
    }
}

// --- Begin per-request App Attestation enforcement helpers ---

/// Enforce iOS App Attestation headers for "sensitive" routes.
/// - Accepts simulator/dev bypass when APP_ATTEST_DEV_BYPASS is true and X-iOS-Development is present
/// - Requires X-iOS-App-Attest-Key, X-iOS-App-Attest-Assertion, and X-Request-Challenge
/// - Verifies that the key is known (stored) and that the challenge is fresh
/// - Placeholder assertion validation (TODO: implement full App Attest assertion verification)
pub async fn enforce_request_attestation_from_headers(
    headers: &HeaderMap,
    db: &mut Database,
    dev_bypass: bool,
    strict_verify: bool,
) -> Result<(), String> {
    // Dev/simulator bypass (opt-in via env)
    let dev_bypass = dev_bypass;

    // Simulator detection via UA or explicit header from app
    let user_agent = headers.get("user-agent").and_then(|h| h.to_str().ok());
    let is_sim = is_ios_simulator(user_agent);
    let has_dev_header = headers
        .get("X-iOS-Development")
        .and_then(|h| h.to_str().ok())
        .is_some();

    if dev_bypass && (is_sim || has_dev_header) {
        console_log!("App Attestation: dev/simulator bypass accepted");
        return Ok(());
    }

    // Required headers
    let key_id = headers
        .get("X-iOS-App-Attest-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| "Missing X-iOS-App-Attest-Key header".to_string())?;

    let assertion_b64 = headers
        .get("X-iOS-App-Attest-Assertion")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| "Missing X-iOS-App-Attest-Assertion header".to_string())?;

    let challenge_b64 = headers
        .get("X-Request-Challenge")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| "Missing X-Request-Challenge header".to_string())?;

    // Ensure key exists in storage (from prior init/verify flow) and bundle ID matches
    // Require bundle ID header (device uses X-iOS-App-Bundle-ID, simulator uses X-iOS-Bundle-ID)
    let bundle_id = headers
        .get("X-iOS-App-Bundle-ID")
        .or_else(|| headers.get("X-iOS-Bundle-ID"))
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| "Missing X-iOS-App-Bundle-ID header".to_string())?;

    let row = query("SELECT 1 FROM app_attest_keys WHERE key_id = ? AND bundle_id = ? LIMIT 1")
        .bind(key_id)
        .bind(bundle_id)
        .fetch_optional(&mut db.conn)
        .await
        .map_err(|e| format!("Database error checking App Attest key: {}", e))?;

    if row.is_none() {
        return Err("Unknown App Attest key id or bundle ID mismatch".to_string());
    }

    // Verify challenge freshness
    // The iOS client creates a deterministic challenge that ends with a timestamp: ...:<seconds_since_epoch>
    use base64::Engine;
    let challenge_bytes = base64::engine::general_purpose::STANDARD
        .decode(challenge_b64)
        .map_err(|_| "Invalid X-Request-Challenge (not base64)".to_string())?;
    let challenge_str = String::from_utf8(challenge_bytes)
        .map_err(|_| "Invalid X-Request-Challenge (not UTF-8)".to_string())?;

    let ts_part = challenge_str
        .rsplit(':')
        .next()
        .ok_or_else(|| "Invalid X-Request-Challenge format".to_string())?;

    let ts_secs: f64 = ts_part
        .parse()
        .map_err(|_| "Invalid X-Request-Challenge timestamp".to_string())?;

    let now_secs = (Utc::now().timestamp_millis() as f64) / 1000.0;
    let max_skew_secs = 120.0; // 2 minutes window
    if now_secs - ts_secs > max_skew_secs {
        return Err("Stale request challenge".to_string());
    }
    if ts_secs - now_secs > 30.0 {
        // guard against far-future timestamps
        return Err("Request challenge timestamp is in the future".to_string());
    }

    // Decode assertion (COSE_Sign1) for verification
    let assertion_bytes = base64::engine::general_purpose::STANDARD
        .decode(assertion_b64)
        .map_err(|_| "Invalid X-iOS-App-Attest-Assertion (not base64)".to_string())?;
    if assertion_bytes.len() < 16 {
        return Err("Invalid App Attest assertion".to_string());
    }

    // Signature verification using stored XY (base64 of X||Y) when available.
    // When APP_ATTEST_VERIFY_SIGNATURE_STRICT=true/1/yes, enforce verification; otherwise best-effort/log-only.
    let strict_verify = strict_verify;

    if let Ok(Some((public_key_opt,))) = sqlx_d1::query_as::<(Option<String>,)>(
        "SELECT public_key FROM app_attest_keys WHERE key_id = ? LIMIT 1",
    )
    .bind(key_id)
    .fetch_optional(&mut db.conn)
    .await
    {
        if let Some(pub_xy_b64) = public_key_opt {
            // Decode stored base64(X||Y) and construct uncompressed SEC1 pubkey
            let pub_xy = base64::engine::general_purpose::STANDARD
                .decode(pub_xy_b64.as_bytes())
                .map_err(|_| "Stored App Attest public key invalid base64".to_string())?;
            if pub_xy.len() != 64 {
                return Err("Stored App Attest public key must be 64 bytes (X||Y)".to_string());
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&pub_xy);

            // Parse COSE_Sign1: [protected: bstr, unprotected: map, payload: bstr, signature: bstr]
            let cose_val: CborValue = cbor_from_reader(&*assertion_bytes)
                .map_err(|_| "Invalid COSE_Sign1 CBOR".to_string())?;
            let arr = match cose_val {
                CborValue::Array(v) if v.len() == 4 => v,
                _ => return Err("COSE_Sign1 must be array of 4 items".to_string()),
            };
            let protected = match &arr[0] {
                CborValue::Bytes(b) => b.clone(),
                _ => return Err("COSE_Sign1 protected header must be bytes".to_string()),
            };
            let payload = match &arr[2] {
                CborValue::Bytes(b) => b.clone(),
                _ => return Err("COSE_Sign1 payload must be bytes".to_string()),
            };
            let signature = match &arr[3] {
                CborValue::Bytes(b) => b.clone(),
                _ => return Err("COSE_Sign1 signature must be bytes".to_string()),
            };

            // Build Sig_structure = ["Signature1", protected, external_aad: bstr(""), payload]
            let sig_structure = CborValue::Array(vec![
                CborValue::Text("Signature1".to_string()),
                CborValue::Bytes(protected.clone()),
                CborValue::Bytes(Vec::new()),
                CborValue::Bytes(payload.clone()),
            ]);
            let mut tbs = Vec::new();
            cbor_into_writer(&sig_structure, &mut tbs)
                .map_err(|_| "Failed to encode COSE Sig_structure".to_string())?;

            // Verify ECDSA over tbs with raw (r||s) signature and ensure payload == SHA256(challenge)
            let vk = P256VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| "Stored App Attest public key is invalid".to_string())?;
            let sig = P256Signature::from_slice(&signature)
                .map_err(|_| "Invalid App Attest signature".to_string())?;

            let payload_matches = {
                let ch_hash = Sha256::digest(challenge_str.as_bytes());
                payload.as_slice() == ch_hash.as_slice()
            };

            if strict_verify {
                if vk.verify(&tbs, &sig).is_err() {
                    return Err("Invalid App Attest assertion signature".to_string());
                }
                if !payload_matches {
                    return Err("App Attest payload does not match challenge hash".to_string());
                }
            } else {
                if vk.verify(&tbs, &sig).is_ok() {
                    if !payload_matches {
                        console_log!("App Attestation: payload != SHA256(challenge) (non-strict)");
                    }
                } else {
                    console_log!("App Attestation: signature verification failed (non-strict). Set APP_ATTEST_VERIFY_SIGNATURE_STRICT=true to enforce.");
                }
            }
        } else {
            console_log!("App Attestation: no public_key stored; skipping signature verification (TODO: extract and store from attestation).");
        }
    } else {
        console_log!("App Attestation: could not fetch public_key for key_id; skipping signature verification.");
    }

    // Update key last_used_at
    let _ = query("UPDATE app_attest_keys SET last_used_at = ? WHERE key_id = ?")
        .bind(datetime_to_timestamp(Utc::now()))
        .bind(key_id)
        .execute(&mut db.conn)
        .await;

    Ok(())
}

/// Axum middleware to enforce iOS App Attestation on protected routes.
/// To enable dev/simulator bypass, set APP_ATTEST_DEV_BYPASS=true in the environment.
/// Axum middleware to enforce iOS App Attestation on protected routes.
/// To enable dev/simulator bypass, set APP_ATTEST_DEV_BYPASS=true in the environment.
pub async fn require_ios_app_attestation(req: AxumRequest, next: Next) -> Response {
    if let Some(handles) = req.extensions().get::<SharedHandles>().cloned() {
        // Resolve flags via Env handle
        let dev_bypass = {
            let res = handles
                .env
                .run(|env| async move {
                    let v = env
                        .var("APP_ATTEST_DEV_BYPASS")
                        .ok()
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    let s = v;
                    Ok::<bool, ()>(
                        s == "1" || s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("yes"),
                    )
                })
                .await;
            match res {
                Ok(b) => b,
                Err(_) => false,
            }
        };

        let strict_verify = {
            let res = handles
                .env
                .run(|env| async move {
                    let v = env
                        .var("APP_ATTEST_VERIFY_SIGNATURE_STRICT")
                        .ok()
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    let s = v;
                    Ok::<bool, ()>(
                        s == "1" || s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("yes"),
                    )
                })
                .await;
            match res {
                Ok(b) => b,
                Err(_) => false,
            }
        };

        // Capture headers as owned (String, String) pairs for the DB task
        let header_pairs: Vec<(String, String)> = req
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_string(), s.to_string()))
            })
            .collect();

        let result: Result<(), String> = handles
            .db
            .run(move |mut db| async move {
                let mut hdrs = HeaderMap::new();
                for (k, v) in header_pairs {
                    if let (Ok(name), Ok(value)) = (
                        axum::http::header::HeaderName::from_bytes(k.as_bytes()),
                        HeaderValue::from_str(&v),
                    ) {
                        hdrs.insert(name, value);
                    }
                }
                enforce_request_attestation_from_headers(&hdrs, &mut db, dev_bypass, strict_verify)
                    .await
            })
            .await;

        match result {
            Ok(()) => next.run(req).await,
            Err(message) => {
                let body = serde_json::json!({
                    "error": {
                        "code": "unauthorized",
                        "message": message
                    }
                });
                let mut resp = Response::new(axum::body::Body::from(
                    serde_json::to_string(&body).unwrap_or_else(|_| {
                        "{\"error\":{\"code\":\"unauthorized\",\"message\":\"unauthorized\"}}"
                            .to_string()
                    }),
                ));
                *resp.status_mut() = StatusCode::UNAUTHORIZED;
                resp.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                resp
            }
        }
    } else {
        // If handles are not present (unexpected), proceed without enforcement.
        next.run(req).await
    }
}

// --- End per-request App Attestation enforcement helpers ---

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    use axum::{
        http::{header::CONTENT_TYPE, HeaderValue, Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn protected() -> &'static str {
        "ok"
    }

    // Test-only middleware that mimics attestation requirement by checking headers presence.
    async fn test_attestation_mw(
        req: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        let has_key = req.headers().get("x-ios-app-attest-key").is_some();
        let has_assert = req.headers().get("x-ios-app-attest-assertion").is_some();
        if !has_key || !has_assert {
            let mut resp = axum::response::Response::new(axum::body::Body::from(
                "{\"error\":{\"code\":\"unauthorized\",\"message\":\"unauthorized\"}}",
            ));
            *resp.status_mut() = StatusCode::UNAUTHORIZED;
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            return resp;
        }
        next.run(req).await
    }

    #[tokio::test]
    async fn rejects_missing_attestation_headers() {
        // Build a router with the test attestation middleware guarding /v1 routes
        let app = Router::new()
            .route("/v1/links", get(protected))
            .layer(middleware::from_fn(test_attestation_mw));

        // No attestation headers -> expect 401 Unauthorized
        let req = Request::builder()
            .uri("/v1/links")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
