use crate::db::Database;
use crate::shared_handles::SharedHandles;
use crate::utils::datetime_to_timestamp;
use appattest_rs::{assertion::Assertion, attestation::Attestation};
use axum::extract::Request as AxumRequest;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::{middleware::Next, response::Response};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::Utc;
use worker::{console_log, Env};

// Apple App Attestation Root CA certificate is handled internally by appattest-rs

/// Checks if the request is coming from iOS Simulator.
pub fn is_ios_simulator(user_agent: Option<&str>) -> bool {
    let ua = user_agent.unwrap_or("");
    ua.contains("Simulator")
        || ua.contains("x86_64")
        || ua.contains("arm64-sim")
        || ua.contains("i386")
        || ua.contains("iPhone Simulator")
        || ua.contains("iPad Simulator")
}

/// Validates an Apple App Attestation object using the appattest-rs crate.
pub fn perform_attestation_validation(
    attestation_b64: &str,
    challenge_b64: &str,
    team_id: &str,
    bundle_id: &str,
) -> Result<Vec<u8>, String> {
    console_log!("[Debug] perform_attestation_validation: starting");

    let challenge_bytes = BASE64_STANDARD
        .decode(challenge_b64)
        .map_err(|e| format!("Failed to decode challenge: {}", e))?;
    let challenge_str = std::str::from_utf8(&challenge_bytes)
        .map_err(|e| format!("Challenge is not valid UTF-8: {}", e))?;

    let app_id = format!("{}.{}", team_id, bundle_id);
    console_log!("[Debug] App ID for validation: {}", app_id);

    // Create attestation from base64
    let attestation = Attestation::from_base64(attestation_b64)
        .map_err(|e| format!("Failed to parse attestation: {:?}", e))?;

    // Note: For key_id, we'll need to generate or extract it from the attestation
    // For now, using a placeholder - this may need to be adjusted based on your specific requirements
    let key_id = "placeholder_key_id";

    let result = attestation.verify(challenge_str, &app_id, key_id);

    match result {
        Ok((public_key, _receipt)) => {
            console_log!("[Debug] appattest-rs validation successful");
            Ok(public_key)
        }
        Err(e) => {
            console_log!("[Error] appattest-rs validation failed: {:?}", e);
            Err(format!("App Attestation validation failed: {:?}", e))
        }
    }
}

/// Enforce iOS App Attestation headers for "sensitive" routes.
pub async fn enforce_request_attestation_from_headers(
    headers: &HeaderMap,
    db: &mut Database,
    env: &Env,
) -> Result<(), String> {
    let dev_bypass = env
        .var("APP_ATTEST_DEV_BYPASS")
        .map(|v| v.to_string() == "1")
        .unwrap_or(false);
    let strict_verify = env
        .var("APP_ATTEST_VERIFY_SIGNATURE_STRICT")
        .map(|v| v.to_string() == "1")
        .unwrap_or(false);

    console_log!(
        "[Debug] enforce_request_attestation_from_headers: starting with dev_bypass={}, strict_verify={}",
        dev_bypass,
        strict_verify
    );

    let user_agent = headers.get("user-agent").and_then(|h| h.to_str().ok());
    if dev_bypass && is_ios_simulator(user_agent) {
        console_log!(
            "[Debug] enforce_request_attestation_from_headers: dev/simulator bypass accepted"
        );
        return Ok(());
    }

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

    let bundle_id = headers
        .get("X-iOS-App-Bundle-ID")
        .or_else(|| headers.get("X-iOS-Bundle-ID"))
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| "Missing X-iOS-App-Bundle-ID header".to_string())?;

    let row: Option<(Vec<u8>, i64)> = sqlx_d1::query_as(
        "SELECT public_key, counter FROM app_attest_keys WHERE key_id = ? AND bundle_id = ? LIMIT 1",
    )
    .bind(key_id)
    .bind(bundle_id)
    .fetch_optional(&mut db.conn)
    .await
    .map_err(|e| format!("Database error checking App Attest key: {}", e))?;

    let (public_key_bytes, db_counter) = match row {
        Some(r) => r,
        None => {
            console_log!(
                "[Debug] enforce_request_attestation_from_headers: key_id not found in database"
            );
            return Err("Unknown App Attest key id or bundle ID mismatch".to_string());
        }
    };

    let _challenge_bytes = BASE64_STANDARD
        .decode(challenge_b64)
        .map_err(|_| "Invalid X-Request-Challenge (not base64)".to_string())?;

    let team_id = env
        .var("APPLE_TEAM_ID")
        .map_err(|_| "APPLE_TEAM_ID not configured".to_string())?;
    let app_id = format!("{}.{}", team_id, bundle_id);

    let _assertion_bytes = BASE64_STANDARD
        .decode(assertion_b64)
        .map_err(|_| "Invalid X-iOS-App-Attest-Assertion (not base64)".to_string())?;

    // Create assertion from base64
    let assertion = Assertion::from_base64(assertion_b64)
        .map_err(|e| format!("Failed to parse assertion: {:?}", e))?;

    // Create client data for assertion verification
    let client_data = serde_json::json!({
        "challenge": challenge_b64,
        "origin": app_id
    });
    let client_data_bytes = serde_json::to_vec(&client_data)
        .map_err(|e| format!("Failed to serialize client data: {}", e))?;

    let verification_result = assertion.verify(
        client_data_bytes,
        &app_id,
        public_key_bytes,
        db_counter as u32,
        challenge_b64,
    );

    let new_counter = match verification_result {
        Ok(()) => {
            console_log!("[Debug] Assertion validation successful");
            // Since the verification succeeded, increment the counter
            (db_counter + 1) as u32
        }
        Err(e) => {
            console_log!("[Error] Assertion validation failed: {:?}", e);
            if strict_verify {
                return Err(format!("Invalid App Attest assertion: {:?}", e));
            }
            db_counter as u32 // Don't update counter if verification fails in non-strict mode
        }
    };

    if new_counter > db_counter as u32 {
        sqlx_d1::query("UPDATE app_attest_keys SET last_used_at = ?, counter = ? WHERE key_id = ?")
            .bind(datetime_to_timestamp(Utc::now()))
            .bind(new_counter as i64)
            .bind(key_id)
            .execute(&mut db.conn)
            .await
            .map_err(|e| format!("Failed to update key counter: {}", e))?;
    }

    Ok(())
}

/// Axum middleware to enforce iOS App Attestation on protected routes.
pub async fn require_ios_app_attestation(req: AxumRequest, next: Next) -> Response {
    if let Some(handles) = req.extensions().get::<SharedHandles>().cloned() {
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
            .run(move |mut db| {
                let env = handles.env.clone();
                async move {
                    let mut hdrs = HeaderMap::new();
                    for (k, v) in header_pairs {
                        if let (Ok(name), Ok(value)) = (
                            axum::http::header::HeaderName::from_bytes(k.as_bytes()),
                            HeaderValue::from_str(&v),
                        ) {
                            hdrs.insert(name, value);
                        }
                    }
                    // Run the actual enforcement function inside the closure with access to `db` and `env`
                    env.run(move |env| async move {
                        enforce_request_attestation_from_headers(&hdrs, &mut db, &env).await
                    })
                    .await
                }
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
        next.run(req).await
    }
}
