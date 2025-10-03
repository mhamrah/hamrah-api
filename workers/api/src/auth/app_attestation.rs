use crate::db::Database;
use crate::shared_handles::SharedHandles;
use crate::utils::datetime_to_timestamp;
use appattest_rs::{validate_assertion, validate_attestation};
use axum::extract::Request as AxumRequest;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::{middleware::Next, response::Response};
use chrono::{Duration, Utc};
use worker::{console_log, Env};

// Apple App Attestation Root CA certificate, downloaded from https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
const APPLE_APP_ATTESTATION_ROOT_CA_PEM: &str = r###"-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3NhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
"###;

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
///
/// Returns the public key of the attested key if validation is successful.
pub fn perform_attestation_validation(
    attestation_b64: &str,
    challenge_b64: &str,
    team_id: &str,
    bundle_id: &str,
) -> Result<Vec<u8>, String> {
    console_log!("[Debug] perform_attestation_validation: starting");

    let attestation_bytes = match base64::decode(attestation_b64) {
        Ok(b) => b,
        Err(e) => return Err(format!("Failed to decode attestation object: {}", e)),
    };

    let challenge_bytes = match base64::decode(challenge_b64) {
        Ok(b) => b,
        Err(e) => return Err(format!("Failed to decode challenge: {}", e)),
    };

    let app_id = format!("{}.", team_id, bundle_id);
    console_log!("[Debug] App ID for validation: {}", app_id);

    // The `validate_attestation` function performs the entire validation flow:
    // 1. Verifies the certificate chain, checking it against the provided root CA.
    // 2. Ensures the attestation statement has a valid signature.
    // 3. Checks that the challenge hash in the authenticator data matches the provided challenge.
    // 4. Verifies that the RP ID hash in the authenticator data matches the provided app_id.
    let result = validate_attestation(
        &app_id,
        &challenge_bytes,
        &attestation_bytes,
        APPLE_APP_ATTESTATION_ROOT_CA_PEM.as_bytes(),
        // TODO: Check current time against the attestation timestamp.
        // The library requires a `max_age` for the attestation statement.
        // We'll allow a generous window for now.
        Duration::days(90).to_std().unwrap(),
    );

    match result {
        Ok(data) => {
            console_log!("[Debug] appattest-rs validation successful");
            // The public key is returned as part of the validated data.
            Ok(data.public_key)
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
    dev_bypass: bool,
    strict_verify: bool,
    env: &Env,
) -> Result<(), String> {
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

    let row: Option<(Vec<u8>, i64)> = match sqlx_d1::query_as(
        "SELECT public_key, counter FROM app_attest_keys WHERE key_id = ? AND bundle_id = ? LIMIT 1",
    )
    .bind(key_id)
    .bind(bundle_id)
    .fetch_optional(&mut db.conn)
    .await {
        Ok(r) => r,
        Err(e) => return Err(format!("Database error checking App Attest key: {}", e)),
    };

    let (public_key_bytes, db_counter) = match row {
        Some(r) => r,
        None => {
            console_log!(
                "[Debug] enforce_request_attestation_from_headers: key_id not found in database"
            );
            return Err("Unknown App Attest key id or bundle ID mismatch".to_string());
        }
    };

    let challenge_bytes = match base64::decode(challenge_b64) {
        Ok(b) => b,
        Err(_) => return Err("Invalid X-Request-Challenge (not base64)".to_string()),
    };

    let team_id = match env.var("APPLE_TEAM_ID") {
        Ok(v) => v.to_string(),
        Err(_) => return Err("APPLE_TEAM_ID not configured".to_string()),
    };
    let app_id = format!("{}.", team_id, bundle_id);

    let assertion_bytes = match base64::decode(assertion_b64) {
        Ok(b) => b,
        Err(_) => return Err("Invalid X-iOS-App-Attest-Assertion (not base64)".to_string()),
    };

    let verification_result = validate_assertion(
        &public_key_bytes,
        &assertion_bytes,
        &app_id,
        &challenge_bytes,
        db_counter as u32,
    );

    let new_counter = match verification_result {
        Ok(counter) => {
            console_log!(
                "[Debug] Assertion validation successful with new counter: {}",
                counter
            );
            counter
        }
        Err(e) => {
            console_log!("[Error] Assertion validation failed: {:?}", e);
            if strict_verify {
                return Err(format!("Invalid App Attest assertion: {:?}", e));
            }
            0 // Don't update counter if verification fails in non-strict mode
        }
    };

    if new_counter > db_counter as u32 {
        if let Err(e) = sqlx_d1::query(
            "UPDATE app_attest_keys SET last_used_at = ?, counter = ? WHERE key_id = ?",
        )
        .bind(datetime_to_timestamp(Utc::now()))
        .bind(new_counter as i64)
        .bind(key_id)
        .execute(&mut db.conn)
        .await
        {
            console_log!("[Error] Failed to update key counter: {}", e);
        }
    }

    Ok(())
}

/// Axum middleware to enforce iOS App Attestation on protected routes.
pub async fn require_ios_app_attestation(req: AxumRequest, next: Next) -> Response {
    if let Some(handles) = req.extensions().get::<SharedHandles>().cloned() {
        let dev_bypass = handles
            .env
            .var("APP_ATTEST_DEV_BYPASS")
            .map(|v| v.to_string() == "1" || v.to_string().eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let strict_verify = handles
            .env
            .var("APP_ATTEST_VERIFY_SIGNATURE_STRICT")
            .map(|v| v.to_string() == "1" || v.to_string().eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let header_pairs: Vec<(String, String)> = req
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_string(), s.to_string()))
            })
            .collect();

        let env_clone = handles.env.clone();

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
                enforce_request_attestation_from_headers(
                    &hdrs,
                    &mut db,
                    dev_bypass,
                    strict_verify,
                    &env_clone,
                )
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
        next.run(req).await
    }
}
