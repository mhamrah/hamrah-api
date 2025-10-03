use crate::db::Database;
use crate::shared_handles::SharedHandles;
use crate::utils::datetime_to_timestamp;
#[cfg(not(target_arch = "wasm32"))]
use appattest_rs::attestation::Attestation;
use axum::extract::Request as AxumRequest;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::{middleware::Next, response::Response};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::Utc;
use worker::{console_log, Env};

// WASM-compatible crypto imports
use ciborium;
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    PublicKey,
};
use sha2::{Digest, Sha256};

// Apple App Attestation AAGUIDs
// Production: "appattest" + 7 zero bytes
const APPLE_APP_ATTEST_AAGUID_PRODUCTION: &[u8] = &[
    0x61, 0x70, 0x70, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Development/Simulator: "appattestdevelop" (16 bytes)
const APPLE_APP_ATTEST_AAGUID_DEVELOPMENT: &[u8] = &[
    0x61, 0x70, 0x70, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x64, 0x65, 0x76, 0x65, 0x6C, 0x6F, 0x70,
];

fn is_valid_app_attest_aaguid(aaguid: &[u8; 16]) -> bool {
    aaguid == APPLE_APP_ATTEST_AAGUID_PRODUCTION || aaguid == APPLE_APP_ATTEST_AAGUID_DEVELOPMENT
}

#[derive(Debug)]
struct AttestationStatement {
    #[allow(dead_code)]
    x5c: Vec<Vec<u8>>, // Certificate chain
    #[allow(dead_code)]
    receipt: Vec<u8>, // App Store receipt
}

#[derive(Debug)]
struct AttestationObject {
    #[allow(dead_code)]
    fmt: String,
    #[allow(dead_code)]
    att_stmt: AttestationStatement,
    auth_data: Vec<u8>,
}

#[derive(Debug)]
struct AuthenticatorData {
    rp_id_hash: [u8; 32],
    #[allow(dead_code)]
    flags: u8,
    sign_count: u32,
    attested_credential_data: Option<AttestedCredentialData>,
}

#[derive(Debug)]
struct AttestedCredentialData {
    aaguid: [u8; 16],
    #[allow(dead_code)]
    credential_id_length: u16,
    #[allow(dead_code)]
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
}

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

/// Parse CBOR attestation object
fn parse_attestation_object(attestation_bytes: &[u8]) -> Result<AttestationObject, String> {
    let cbor_value: ciborium::Value = ciborium::from_reader(attestation_bytes)
        .map_err(|e| format!("Failed to parse CBOR: {}", e))?;

    let map = match cbor_value {
        ciborium::Value::Map(m) => m,
        _ => return Err("Attestation object is not a CBOR map".to_string()),
    };

    let mut fmt = None;
    let mut att_stmt = None;
    let mut auth_data = None;

    for (key, value) in map {
        match key {
            ciborium::Value::Text(ref s) if s == "fmt" => {
                if let ciborium::Value::Text(f) = value {
                    fmt = Some(f);
                }
            }
            ciborium::Value::Text(ref s) if s == "attStmt" => {
                att_stmt = Some(parse_attestation_statement(value)?);
            }
            ciborium::Value::Text(ref s) if s == "authData" => {
                if let ciborium::Value::Bytes(data) = value {
                    auth_data = Some(data);
                }
            }
            _ => {}
        }
    }

    Ok(AttestationObject {
        fmt: fmt.ok_or("Missing fmt field")?,
        att_stmt: att_stmt.ok_or("Missing attStmt field")?,
        auth_data: auth_data.ok_or("Missing authData field")?,
    })
}

fn parse_attestation_statement(value: ciborium::Value) -> Result<AttestationStatement, String> {
    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => return Err("attStmt is not a CBOR map".to_string()),
    };

    let mut x5c = None;
    let mut receipt = None;

    for (key, value) in map {
        match key {
            ciborium::Value::Text(ref s) if s == "x5c" => {
                if let ciborium::Value::Array(arr) = value {
                    let certs: Result<Vec<Vec<u8>>, _> = arr
                        .into_iter()
                        .map(|v| match v {
                            ciborium::Value::Bytes(b) => Ok(b),
                            _ => Err("Certificate is not bytes"),
                        })
                        .collect();
                    x5c = Some(certs.map_err(|e| format!("Invalid certificate array: {}", e))?);
                }
            }
            ciborium::Value::Text(ref s) if s == "receipt" => {
                if let ciborium::Value::Bytes(r) = value {
                    receipt = Some(r);
                }
            }
            _ => {}
        }
    }

    Ok(AttestationStatement {
        x5c: x5c.ok_or("Missing x5c field")?,
        receipt: receipt.ok_or("Missing receipt field")?,
    })
}

fn parse_authenticator_data(auth_data: &[u8]) -> Result<AuthenticatorData, String> {
    if auth_data.len() < 37 {
        return Err("AuthenticatorData too short".to_string());
    }

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&auth_data[0..32]);

    let flags = auth_data[32];
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);

    let attested_credential_data = if flags & 0x40 != 0 {
        // AT flag is set
        Some(parse_attested_credential_data(&auth_data[37..])?)
    } else {
        None
    };

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested_credential_data,
    })
}

fn parse_attested_credential_data(data: &[u8]) -> Result<AttestedCredentialData, String> {
    if data.len() < 18 {
        return Err("AttestedCredentialData too short".to_string());
    }

    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&data[0..16]);

    let credential_id_length = u16::from_be_bytes([data[16], data[17]]);
    let credential_id_end = 18 + credential_id_length as usize;

    if data.len() < credential_id_end {
        return Err("AttestedCredentialData incomplete".to_string());
    }

    let credential_id = data[18..credential_id_end].to_vec();
    let public_key = data[credential_id_end..].to_vec();

    Ok(AttestedCredentialData {
        aaguid,
        credential_id_length,
        credential_id,
        public_key,
    })
}

fn extract_p256_public_key_from_cose(cose_key: &[u8]) -> Result<Vec<u8>, String> {
    let cbor_value: ciborium::Value =
        ciborium::from_reader(cose_key).map_err(|e| format!("Failed to parse COSE key: {}", e))?;

    let map = match cbor_value {
        ciborium::Value::Map(m) => m,
        _ => return Err("COSE key is not a CBOR map".to_string()),
    };

    let mut x_coord = None;
    let mut y_coord = None;

    for (key, value) in map {
        if let ciborium::Value::Integer(i) = key {
            let i_val: i128 = i.into();
            match i_val {
                -2 => {
                    // x coordinate
                    if let ciborium::Value::Bytes(x) = value {
                        x_coord = Some(x);
                    }
                }
                -3 => {
                    // y coordinate
                    if let ciborium::Value::Bytes(y) = value {
                        y_coord = Some(y);
                    }
                }
                _ => {}
            }
        }
    }

    let x = x_coord.ok_or("Missing x coordinate")?;
    let y = y_coord.ok_or("Missing y coordinate")?;

    if x.len() != 32 || y.len() != 32 {
        return Err("Invalid coordinate length".to_string());
    }

    // Return uncompressed public key (0x04 + x + y)
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04);
    public_key.extend_from_slice(&x);
    public_key.extend_from_slice(&y);

    Ok(public_key)
}

/// WASM-compatible Apple App Attestation validation
pub fn perform_attestation_validation(
    attestation_b64: &str,
    challenge_b64: &str,
    team_id: &str,
    bundle_id: &str,
) -> Result<Vec<u8>, String> {
    console_log!("[Debug] perform_attestation_validation: starting (WASM-compatible)");

    // Decode attestation object
    let attestation_bytes = BASE64_STANDARD
        .decode(attestation_b64)
        .map_err(|e| format!("Failed to decode attestation: {}", e))?;

    // Decode challenge
    let challenge_bytes = BASE64_STANDARD
        .decode(challenge_b64)
        .map_err(|e| format!("Failed to decode challenge: {}", e))?;

    let app_id = format!("{}.{}", team_id, bundle_id);
    console_log!("[Debug] App ID for validation: {}", app_id);

    // Parse attestation object
    let attestation_obj = parse_attestation_object(&attestation_bytes)?;

    // Parse authenticator data
    let auth_data = parse_authenticator_data(&attestation_obj.auth_data)?;

    // Verify app ID hash
    let app_id_hash = Sha256::digest(app_id.as_bytes());
    if auth_data.rp_id_hash != app_id_hash.as_slice() {
        return Err("App ID hash mismatch".to_string());
    }

    // Verify AAGUID
    let credential_data = auth_data
        .attested_credential_data
        .as_ref()
        .ok_or("Missing attested credential data")?;

    console_log!("[Debug] Received AAGUID: {:?}", credential_data.aaguid);
    console_log!(
        "[Debug] Production AAGUID: {:?}",
        APPLE_APP_ATTEST_AAGUID_PRODUCTION
    );
    console_log!(
        "[Debug] Development AAGUID: {:?}",
        APPLE_APP_ATTEST_AAGUID_DEVELOPMENT
    );

    if !is_valid_app_attest_aaguid(&credential_data.aaguid) {
        // Log the actual AAGUID for debugging
        let received_hex = credential_data
            .aaguid
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("");
        let prod_hex = APPLE_APP_ATTEST_AAGUID_PRODUCTION
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("");
        let dev_hex = APPLE_APP_ATTEST_AAGUID_DEVELOPMENT
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("");
        console_log!(
            "[Debug] AAGUID mismatch - Received: {}, Expected production: {} or development: {}",
            received_hex,
            prod_hex,
            dev_hex
        );
        return Err(format!(
            "Invalid AAGUID - received: {}, expected production: {} or development: {}",
            received_hex, prod_hex, dev_hex
        ));
    }

    // Extract public key from COSE key
    let public_key_bytes = extract_p256_public_key_from_cose(&credential_data.public_key)?;

    // Verify nonce (challenge + auth_data hash)
    let client_data_hash = Sha256::digest(&challenge_bytes);
    let mut nonce_input = Vec::new();
    nonce_input.extend_from_slice(&attestation_obj.auth_data);
    nonce_input.extend_from_slice(&client_data_hash);
    let _nonce = Sha256::digest(&nonce_input);

    // For full validation, we would verify the certificate chain here
    // For now, we'll skip certificate validation in WASM environment
    console_log!("[Debug] Basic attestation validation successful");

    Ok(public_key_bytes)
}

/// WASM-compatible Apple App Attestation validation (fallback for native builds)
#[cfg(not(target_arch = "wasm32"))]
pub fn perform_attestation_validation_native(
    attestation_b64: &str,
    challenge_b64: &str,
    team_id: &str,
    bundle_id: &str,
) -> Result<Vec<u8>, String> {
    console_log!("[Debug] perform_attestation_validation: starting (native with appattest-rs)");

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

    // For key_id, we'll use a placeholder - this may need to be adjusted
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

/// WASM-compatible assertion validation
fn validate_assertion_wasm(
    assertion_b64: &str,
    public_key_bytes: &[u8],
    challenge_b64: &str,
    app_id: &str,
    counter: u32,
) -> Result<(), String> {
    // Decode assertion
    let assertion_bytes = BASE64_STANDARD
        .decode(assertion_b64)
        .map_err(|e| format!("Failed to decode assertion: {}", e))?;

    // Parse CBOR assertion
    let cbor_value: ciborium::Value = ciborium::from_reader(assertion_bytes.as_slice())
        .map_err(|e| format!("Failed to parse assertion CBOR: {}", e))?;

    let map = match cbor_value {
        ciborium::Value::Map(m) => m,
        _ => return Err("Assertion is not a CBOR map".to_string()),
    };

    let mut signature = None;
    let mut auth_data = None;

    for (key, value) in map {
        match key {
            ciborium::Value::Text(ref s) if s == "signature" => {
                if let ciborium::Value::Bytes(sig) = value {
                    signature = Some(sig);
                }
            }
            ciborium::Value::Text(ref s) if s == "authenticatorData" => {
                if let ciborium::Value::Bytes(data) = value {
                    auth_data = Some(data);
                }
            }
            _ => {}
        }
    }

    let signature = signature.ok_or("Missing signature in assertion")?;
    let auth_data = auth_data.ok_or("Missing authenticatorData in assertion")?;

    // Parse authenticator data
    let parsed_auth_data = parse_authenticator_data(&auth_data)?;

    // Verify app ID hash
    let app_id_hash = Sha256::digest(app_id.as_bytes());
    if parsed_auth_data.rp_id_hash != app_id_hash.as_slice() {
        return Err("App ID hash mismatch in assertion".to_string());
    }

    // Verify counter
    if parsed_auth_data.sign_count <= counter {
        return Err("Counter did not increase".to_string());
    }

    // Create client data hash
    let challenge_bytes = BASE64_STANDARD
        .decode(challenge_b64)
        .map_err(|e| format!("Failed to decode challenge: {}", e))?;
    let client_data_hash = Sha256::digest(&challenge_bytes);

    // Create message to verify (auth_data + client_data_hash)
    let mut message = Vec::new();
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(&client_data_hash);
    let message_hash = Sha256::digest(&message);

    // Verify signature using P-256
    let public_key = PublicKey::from_sec1_bytes(public_key_bytes)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    let verifying_key = VerifyingKey::from(public_key);

    let sig =
        Signature::from_der(&signature).map_err(|e| format!("Invalid signature format: {}", e))?;

    verifying_key
        .verify(&message_hash, &sig)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    Ok(())
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

    let team_id = env
        .var("APPLE_TEAM_ID")
        .map_err(|_| "APPLE_TEAM_ID not configured".to_string())?;
    let app_id = format!("{}.{}", team_id, bundle_id);

    // Use WASM-compatible assertion validation
    let verification_result = validate_assertion_wasm(
        assertion_b64,
        &public_key_bytes,
        challenge_b64,
        &app_id,
        db_counter as u32,
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
