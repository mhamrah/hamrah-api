use crate::handlers::ApiError;
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
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
pub async fn validate_app_attestation(attestation_token: &str, env: &Env) -> Result<(), ApiError> {
    console_log!("App Attestation: Starting validation process");

    // Parse the attestation token (should be base64 encoded JSON)
    let attestation_data = parse_attestation_token(attestation_token)?;

    console_log!("App Attestation: Token parsed successfully");

    // Create JWT for Apple API authentication
    let jwt_token = create_apple_jwt(env).await?;

    // Verify against Apple's App Attest service
    verify_with_apple(&attestation_data, &jwt_token).await?;

    console_log!("App Attestation: Successfully validated with Apple");
    Ok(())
}

/// Parse and validate the attestation token format
fn parse_attestation_token(token: &str) -> Result<AttestationPayload, ApiError> {
    use base64::Engine;

    // Parse the attestation token (should be base64 encoded JSON)
    let attestation_data = base64::engine::general_purpose::STANDARD
        .decode(token)
        .map_err(|_| {
            console_log!("App Attestation: Invalid base64 token");
            ApiError::ValidationError("Invalid attestation token format".to_string())
        })?;

    let attestation_json = String::from_utf8(attestation_data).map_err(|_| {
        console_log!("App Attestation: Invalid UTF-8 in token");
        ApiError::ValidationError("Invalid attestation token encoding".to_string())
    })?;

    let attestation_payload: AttestationPayload =
        serde_json::from_str(&attestation_json).map_err(|e| {
            console_log!("App Attestation: Failed to parse JSON: {}", e);
            ApiError::ValidationError("Invalid attestation token structure".to_string())
        })?;

    console_log!(
        "App Attestation: Token parsed successfully, key_id: {}",
        attestation_payload.key_id
    );
    Ok(attestation_payload)
}

/// Creates a JWT token for authenticating with Apple's App Attest API using jwt-simple
async fn create_apple_jwt(env: &Env) -> Result<String, ApiError> {
    // Get required environment variables
    let bundle_id = env
        .var("APPLE_BUNDLE_ID")
        .map_err(|_| ApiError::ValidationError("APPLE_BUNDLE_ID not configured".to_string()))?
        .to_string();

    let team_id = env
        .var("APPLE_TEAM_ID")
        .map_err(|_| ApiError::ValidationError("APPLE_TEAM_ID not configured".to_string()))?
        .to_string();

    let _key_id = env
        .var("APPLE_KEY_ID")
        .map_err(|_| ApiError::ValidationError("APPLE_KEY_ID not configured".to_string()))?
        .to_string();

    let private_key = env
        .var("APPLE_PRIVATE_KEY")
        .map_err(|_| ApiError::ValidationError("APPLE_PRIVATE_KEY not configured".to_string()))?
        .to_string();

    console_log!("App Attestation: Environment variables loaded successfully");

    // Parse the private key using jwt-simple
    let key_pair = ES256KeyPair::from_pem(&private_key).map_err(|e| {
        console_log!("App Attestation: Failed to parse private key: {}", e);
        ApiError::ValidationError("Invalid private key format".to_string())
    })?;

    console_log!("App Attestation: Private key parsed successfully");

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
        ApiError::ValidationError("Failed to sign JWT token".to_string())
    })?;

    console_log!("App Attestation: JWT created successfully with jwt-simple");
    Ok(token)
}

/// Verifies attestation with Apple's App Attest service
async fn verify_with_apple(
    attestation: &AttestationPayload,
    jwt_token: &str,
) -> Result<(), ApiError> {
    // Construct Apple's App Attest verification URL
    let verify_url = "https://api.devicecheck.apple.com/v1/attestation";

    // Prepare the payload for Apple
    let payload = serde_json::json!({
        "attestation_object": attestation.attestation_object,
        "challenge": attestation.challenge,
        "key_id": attestation.key_id
    });

    // Create request to Apple's service
    let mut init = RequestInit::new();
    init.method = Method::Post;

    let headers = {
        let h = worker::Headers::new();
        h.set("Content-Type", "application/json")
            .map_err(|e| ApiError::ValidationError(format!("Header creation failed: {:?}", e)))?;
        h.set("Authorization", &format!("Bearer {}", jwt_token))
            .map_err(|e| ApiError::ValidationError(format!("Header creation failed: {:?}", e)))?;
        h
    };
    init.headers = headers;

    init.body = Some(payload.to_string().into());

    let request = Request::new_with_init(verify_url, &init)
        .map_err(|e| ApiError::ValidationError(format!("Request creation failed: {:?}", e)))?;

    console_log!("App Attestation: Sending request to Apple's service");

    // Make the request
    let mut response = Fetch::Request(request).send().await.map_err(|e| {
        console_log!("App Attestation: Request failed: {:?}", e);
        ApiError::ValidationError(format!("Apple verification request failed: {:?}", e))
    })?;

    let status = response.status_code();
    console_log!("App Attestation: Apple responded with status: {}", status);

    if status == 200 {
        // Parse successful response
        let response_text = response
            .text()
            .await
            .map_err(|e| ApiError::ValidationError(format!("Failed to read response: {:?}", e)))?;

        console_log!("App Attestation: Apple verification successful");
        console_log!("App Attestation: Response: {}", response_text);

        Ok(())
    } else {
        // Parse error response
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| format!("HTTP {}", status));

        console_log!("App Attestation: Apple verification failed: {}", error_text);

        Err(ApiError::ValidationError(format!(
            "Apple attestation verification failed ({}): {}",
            status, error_text
        )))
    }
}
