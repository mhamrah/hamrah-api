use worker::{console_log, Env, Headers, Method, RequestInit};

/// Pipeline shim: helper to call the pipeline service worker via a service binding
/// from the API worker. This sends a JSON POST to `/processLink` on the bound
/// service, which should route to the pipeline worker's `fetch` handler.
///
/// Wrangler config requirements (already set up in this repository's wrangler files):
/// - A service binding named `PIPELINE_SERVICE` that points to the pipeline worker
/// - The pipeline worker must expose a POST /processLink endpoint that accepts:
///     { "linkId": "<link-id>", "userId": "<user-id>" }
///
/// Usage:
///   if let Err(e) = trigger_pipeline_for_link(&env, &link_id, &user_id).await {
///       // log or handle error
///   }
pub async fn trigger_pipeline_for_link(
    env: &Env,
    link_id: &str,
    user_id: &str,
) -> Result<(), String> {
    // Get the bound service (the pipeline worker)
    let fetcher = env
        .service("PIPELINE_SERVICE")
        .map_err(|e| format!("PIPELINE_SERVICE binding not available: {}", e))?;

    // Build the JSON payload
    let payload = serde_json::json!({
        "linkId": link_id,
        "userId": user_id,
    });

    // Prepare request init with POST and JSON body
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(
        serde_json::to_string(&payload)
            .map_err(|e| format!("Failed to serialize pipeline payload: {}", e))?
            .into(),
    ));

    // Add JSON header
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| format!("Failed to set header: {:?}", e))?;
    init.with_headers(headers);

    // Perform the request against the service binding
    let resp = fetcher
        .fetch("http://pipeline/processLink", Some(init))
        .await
        .map_err(|e| format!("Pipeline service fetch failed: {}", e))?;

    let status = resp.status();
    if status.is_success() {
        console_log!(
            "pipeline_shim: successfully triggered pipeline for link_id={} user_id={}",
            link_id,
            user_id
        );
        Ok(())
    } else {
        Err(format!(
            "pipeline_shim: pipeline returned non-2xx ({})",
            status
        ))
    }
}

/// Best-effort fire-and-forget variant. Intended for use in non-critical paths.
/// Logs any error and returns ().
pub async fn try_trigger_pipeline_for_link(env: &Env, link_id: &str, user_id: &str) {
    if let Err(e) = trigger_pipeline_for_link(env, link_id, user_id).await {
        console_log!(
            "pipeline_shim: non-fatal error triggering pipeline: link_id={} user_id={} err={}",
            link_id,
            user_id,
            e
        );
    }
}
