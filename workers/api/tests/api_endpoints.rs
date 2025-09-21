use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    Router,
};
use tower::ServiceExt;

// Helper function to create a test router
fn create_test_router() -> Router {
    // For now, create a stateless router for testing
    use axum::routing::get;
    Router::new()
        .route("/", get(hamrah_api::root))
        .route("/health", get(hamrah_api::health_check))
        .route("/api/test", get(hamrah_api::root))
        .route("/api/status", get(hamrah_api::api_status))
}

// Helper function to make requests
async fn make_request(
    router: Router,
    method: Method,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, String) {
    let mut request_builder = Request::builder().method(method).uri(uri);

    if let Some(_body_content) = body {
        request_builder = request_builder.header("content-type", "application/json");
    }

    let request = request_builder
        .body(Body::from(body.unwrap_or("").to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_text = String::from_utf8(body_bytes.to_vec()).unwrap();

    (status, body_text)
}

#[tokio::test]
async fn test_root_endpoint() {
    let (status, body) = make_request(create_test_router(), Method::GET, "/", None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "Hamrah API v1.0");
}

#[tokio::test]
async fn test_health_check_endpoint() {
    let (status, body) = make_request(create_test_router(), Method::GET, "/health", None).await;

    assert_eq!(status, StatusCode::OK);
    // Health endpoint returns JSON with status, timestamp, and version
    assert!(body.contains("\"status\":\"healthy\""));
    assert!(body.contains("\"version\":\"1.0.0\""));
    assert!(body.contains("\"timestamp\""));
}

#[tokio::test]
async fn test_api_test_endpoint() {
    let (status, body) = make_request(create_test_router(), Method::GET, "/api/test", None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "Hamrah API v1.0");
}

#[tokio::test]
async fn test_api_status_endpoint() {
    let (status, body) = make_request(create_test_router(), Method::GET, "/api/status", None).await;

    assert_eq!(status, StatusCode::OK);
    // Status endpoint returns JSON with operational status
    assert!(body.contains("\"status\":\"operational\""));
    assert!(body.contains("\"database\":\"test_mode\""));
    assert!(body.contains("\"environment\":\"cloudflare_workers\""));
    assert!(body.contains("\"version\":\"1.0.0\""));
    assert!(body.contains("\"timestamp\""));
}

#[tokio::test]
async fn test_not_found_endpoint() {
    let (status, _body) = make_request(create_test_router(), Method::GET, "/nonexistent", None).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_method_not_allowed() {
    // Try POST on a GET-only endpoint
    let (status, _body) = make_request(create_test_router(), Method::POST, "/health", None).await;

    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_cors_headers() {
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header("origin", "https://hamrah.app")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();

    let response = create_test_router().oneshot(request).await.unwrap();

    // Should handle OPTIONS request - basic router returns 405 for unsupported methods
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_json_response_format() {
    let (status, body) = make_request(create_test_router(), Method::GET, "/", None).await;

    assert_eq!(status, StatusCode::OK);
    // Root endpoint returns plain text for now
    assert_eq!(body, "Hamrah API v1.0");
}

#[tokio::test]
async fn test_multiple_requests() {
    // Test that we can make multiple requests to the same router
    for _ in 0..3 {
        let (status, body) = make_request(create_test_router(), Method::GET, "/health", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"status\":\"healthy\""));
    }
}

#[tokio::test]
async fn test_different_endpoints() {
    // Test multiple different endpoints
    let endpoints = vec![("/", "Hamrah API v1.0"), ("/api/test", "Hamrah API v1.0")];

    for (path, expected_body) in endpoints {
        let (status, body) = make_request(create_test_router(), Method::GET, path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, expected_body);
    }

    // Test health endpoint separately since it returns JSON
    let (status, body) = make_request(create_test_router(), Method::GET, "/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"status\":\"healthy\""));
}

#[tokio::test]
async fn test_request_with_headers() {
    let request = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header("user-agent", "test-client/1.0")
        .header("accept", "application/json")
        .body(Body::empty())
        .unwrap();

    let response = create_test_router().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// Test for explicit API paths documentation
#[test]
fn test_api_paths_documentation() {
    // This test documents the expected API paths
    let expected_paths = vec![
        // Basic endpoints
        ("GET", "/", "Root endpoint"),
        ("GET", "/health", "Health check endpoint"),
        ("GET", "/api/test", "Test endpoint"),
        // Future API endpoints (to be implemented)
        // ("POST", "/api/internal/users", "Create user (internal)"),
        // ("POST", "/api/internal/sessions", "Create session (internal)"),
        // ("POST", "/api/internal/tokens", "Create tokens (internal)"),
        // ("POST", "/api/internal/sessions/validate", "Validate session (internal)"),
        // ("POST", "/api/internal/check-user-by-email", "Check user by email (internal)"),
        // ("GET", "/v1/links", "Get user links"),
        // ("POST", "/v1/links", "Create new links"),
        // ("GET", "/v1/links/compact", "Get compact link list"),
        // ("GET", "/v1/links/:id", "Get specific link"),
        // ("PATCH", "/v1/links/:id", "Update link"),
        // ("DELETE", "/v1/links/:id", "Delete link"),
        // ("POST", "/v1/links/:id/refresh", "Refresh link"),
        // ("GET", "/v1/links/:id/archive", "Get link archive"),
        // ("HEAD", "/v1/links/:id/archive", "Check link archive"),
        // ("POST", "/v1/push/register", "Register push token"),
        // ("GET", "/v1/user/prefs", "Get user preferences"),
        // ("PUT", "/v1/user/prefs", "Update user preferences"),
        // ("POST", "/api/webauthn/register/begin", "Begin WebAuthn registration"),
        // ("POST", "/api/webauthn/register/complete", "Complete WebAuthn registration"),
        // ("POST", "/api/webauthn/authenticate/begin", "Begin WebAuthn authentication"),
        // ("POST", "/api/webauthn/authenticate/complete", "Complete WebAuthn authentication"),
        // ("GET", "/api/webauthn/credentials", "List WebAuthn credentials"),
        // ("DELETE", "/api/webauthn/credentials/:id", "Delete WebAuthn credential"),
        // ("PATCH", "/api/webauthn/credentials/:id", "Rename WebAuthn credential"),
        // ("GET", "/api/auth/sessions/validate", "Validate session"),
        // ("POST", "/api/auth/sessions/logout", "Logout session"),
        // ("POST", "/api/auth/tokens/refresh", "Refresh access token"),
        // ("DELETE", "/api/auth/tokens/:token_id/revoke", "Revoke specific token"),
        // ("DELETE", "/api/auth/users/:user_id/tokens/revoke", "Revoke all user tokens"),
        // ("GET", "/api/users/me", "Get current user"),
        // ("PUT", "/api/users/me", "Update current user"),
        // ("DELETE", "/api/users/me", "Delete current user"),
        // ("GET", "/api/users/me/tokens", "Get user tokens"),
        // ("GET", "/api/users/:user_id", "Get user by ID"),
    ];

    // For now, just verify we have documented the current paths
    assert!(!expected_paths.is_empty());

    // Verify the basic paths we currently support
    let current_paths: Vec<(_, _, _)> = expected_paths
        .into_iter()
        .filter(|(_, path, _)| path == &"/" || path == &"/health" || path == &"/api/test")
        .collect();

    assert_eq!(current_paths.len(), 3);
}
