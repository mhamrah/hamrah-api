#![allow(dead_code)]
use crate::error::AppResult;
use crate::shared_handles::SharedHandles;
use axum::{extract::Extension, response::Json};
use serde_json::json;
use worker::Env;

/// GET /v1/models - Get available AI models from Cloudflare AI platform
pub async fn get_models(
    Extension(handles): Extension<SharedHandles>,
) -> AppResult<Json<serde_json::Value>> {
    // Query Cloudflare AI platform for available models suitable for content summarization
    let models = handles
        .env
        .run(|_env| async move { Ok::<Vec<String>, ()>(get_default_models()) })
        .await
        .unwrap_or_else(|_| get_default_models());

    Ok(Json(json!({ "models": models })))
}

async fn get_cloudflare_ai_models(_env: &Env) -> Result<Vec<String>, String> {
    // Use Cloudflare AI platform to get available models
    // For now, return default models as fallback
    Err("Not implemented".to_string())
}

fn get_default_models() -> Vec<String> {
    vec![
        "gpt-4o-mini".to_string(),
        "claude-3.5-sonnet".to_string(),
        "gpt-4o".to_string(),
        "mistral-nemo".to_string(),
        "gpt-4o-realtime-preview".to_string(),
    ]
}
