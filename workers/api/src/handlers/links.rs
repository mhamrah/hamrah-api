use crate::error::{AppError, AppResult};
use crate::handlers::common::{PostLinkItem, PostLinksBody};
use crate::handlers::users::get_current_user_from_request;
use crate::shared_handles::SharedHandles;
use crate::utils::{url_canonicalize, url_is_valid_public_http};
use axum::{
    extract::{Extension, Json as JsonExtractor},
    http::HeaderMap,
    response::Json,
};
use chrono::Utc;
use serde_json::json;
use sqlx_d1::{query, query_as};
use uuid::Uuid;

/* PostLinkItem moved to handlers::common::types */

/* PostLinksBody moved to handlers::common::types */

/* LinkCompactItem moved to handlers::common::types */

/* LinkListItem moved to handlers::common::types */

/// POST /v1/links - create or upsert links for current user
///
/// Contract:
/// - Authentication: Authorization: Bearer <access_token>
/// - Content-Type: application/json
/// - App Attestation headers required (enforced by middleware):
///   X-iOS-App-Attest-Key, X-iOS-App-Attest-Assertion, X-Request-Challenge, X-iOS-App-Bundle-ID
///
/// Request body (single link):
/// {
///   "url": "https://example.com/article",
///   "client_id": "A1D520AA-F4C3-4946-9D38-F09BF9B2BB8A",
///   "source_app": "ios_app",                 // optional
///   "shared_text": "note from share sheet",  // optional
///   "shared_at": "2025-10-04T14:37:39Z"      // optional, RFC3339/ISO-8601
/// }
///
/// Response:
/// {
///   "id": "<server_link_id>",
///   "canonical_url": "https://example.com/article"
/// }
pub async fn post_links(
    Extension(handles): Extension<SharedHandles>,
    headers: HeaderMap,
    JsonExtractor(body): JsonExtractor<PostLinksBody>,
) -> AppResult<Json<serde_json::Value>> {
    // Convert headers to owned string pairs to avoid borrowing non-Send types across await
    let header_pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();
    let user = handles
        .db
        .run(move |mut db| async move {
            // Rebuild a HeaderMap inside the DB executor from owned string pairs
            let mut hdrs = HeaderMap::new();
            for (k, v) in header_pairs {
                if let (Ok(name), Ok(value)) = (
                    axum::http::header::HeaderName::from_bytes(k.as_bytes()),
                    axum::http::HeaderValue::from_str(&v),
                ) {
                    hdrs.insert(name, value);
                }
            }
            get_current_user_from_request(&mut db, &hdrs).await
        })
        .await?;

    // Convert body to items array
    let items: Vec<PostLinkItem> = match body {
        PostLinksBody::Single(item) => vec![item],
        PostLinksBody::Batch { links } => links,
    };

    // Validate inputs
    if items.is_empty() {
        return Err(Box::new(AppError::bad_request("No links provided")));
    }

    let mut results = Vec::new();
    let now_ts = crate::utils::datetime_to_timestamp(Utc::now());

    for item in items {
        // Validate URL
        if !url_is_valid_public_http(&item.url) {
            results.push(json!({
                "url": item.url,
                "error": "Invalid or unsupported URL"
            }));
            continue;
        }

        // Canonicalize URL
        let (canonical_url, host) = match url_canonicalize(&item.url) {
            Some((canon, host)) => (canon, host),
            None => {
                results.push(json!({
                    "url": item.url,
                    "error": "Failed to canonicalize URL"
                }));
                continue;
            }
        };

        // Upsert link and record save transactionally (INTEGER timestamps)
        let user_id_q = user.id.clone();
        let url_q = item.url.clone();
        let canonical_q = canonical_url.clone();
        let host_q = host.clone();
        let client_id_q = item.client_id.clone();
        let source_app_q = item.source_app.clone();
        let shared_text_q = item.shared_text.clone();
        let save_id = Uuid::new_v4().to_string();
        let now_q = now_ts;
        let shared_at_q: Option<i64> = item
            .shared_at
            .as_ref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| crate::utils::datetime_to_timestamp(dt.with_timezone(&chrono::Utc)));

        let link_id: String = handles
                    .db
                    .run(move |mut db| async move {
                        // Begin transaction
                        query("BEGIN").execute(&mut db.conn).await?;

                        // Upsert link (revive if soft-deleted)
                        let new_id = Uuid::new_v4().to_string();
                        query(
                            r#"
                        INSERT INTO links (
                            id, user_id, client_id, original_url, canonical_url, host,
                            state, save_count, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 'new', 1, ?, ?)
                        ON CONFLICT(user_id, canonical_url) DO UPDATE SET
                            save_count = links.save_count + 1,
                            updated_at = excluded.updated_at,
                            state = CASE WHEN links.deleted_at IS NOT NULL THEN 'new' ELSE links.state END,
                            deleted_at = NULL,
                            client_id = COALESCE(links.client_id, excluded.client_id)
                        "#,
                        )
                        .bind(&new_id)
                        .bind(&user_id_q)
                        .bind(&client_id_q)
                        .bind(&url_q)
                        .bind(&canonical_q)
                        .bind(&host_q)
                        .bind(now_q)
                        .bind(now_q)
                        .execute(&mut db.conn)
                        .await?;

                        // Resolve link_id after upsert
                        let (resolved_id,): (String,) =
                            query_as("SELECT id FROM links WHERE user_id = ? AND canonical_url = ?")
                                .bind(&user_id_q)
                                .bind(&canonical_q)
                                .fetch_one(&mut db.conn)
                                .await?;

                        // Insert save
                        query(
                            r#"
                        INSERT INTO link_saves (
                            id, link_id, user_id, source_app, shared_text, shared_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        "#,
                        )
                        .bind(&save_id)
                        .bind(&resolved_id)
                        .bind(&user_id_q)
                        .bind(&source_app_q)
                        .bind(&shared_text_q)
                        .bind(shared_at_q)
                        .bind(now_q)
                        .execute(&mut db.conn)
                        .await?;

                        // Commit transaction
                        query("COMMIT").execute(&mut db.conn).await?;

                        Ok::<String, sqlx_d1::Error>(resolved_id)
                    })
                    .await
                    .map_err(AppError::from)?;

        // Trigger background processing immediately (fire-and-forget)
        {
            let link_id2 = link_id.clone();
            let user_id2 = user.id.clone();
            let _ = handles
                .env
                .run(move |env| async move {
                    crate::pipeline_shim::try_trigger_pipeline_for_link(&env, &link_id2, &user_id2)
                        .await;
                    Ok::<(), ()>(())
                })
                .await;
        }

        // Minimal response entry
        results.push(json!({
            "id": link_id,
            "canonical_url": canonical_url
        }));
    }

    // Always return single-link shape
    Ok(Json(results.remove(0)))
}
