use serde::{Deserialize, Serialize};

// Link-related types
#[derive(Debug, Deserialize)]
pub struct PostLinkItem {
    pub url: String,
    #[serde(rename = "clientId")]
    pub client_id: Option<String>,
    #[serde(rename = "sourceApp")]
    pub source_app: Option<String>,
    #[serde(rename = "sharedText")]
    pub shared_text: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PostLinksBody {
    Single(PostLinkItem),
    Batch { links: Vec<PostLinkItem> },
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct LinkListItem {
    pub id: String,
    pub canonical_url: String,
    pub original_url: String,
    pub state: String,
    pub save_count: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub title: Option<String>,
    pub description: Option<String>,
    pub site_name: Option<String>,
    pub image_url: Option<String>,
    pub favicon_url: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct LinkCompactItem {
    pub id: String,
    pub canonical_url: String,
    pub updated_at: i64,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct LinkPatchRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub site_name: Option<String>,
    pub image_url: Option<String>,
    pub favicon_url: Option<String>,
    pub state: Option<String>,
}

// User preferences types
#[derive(Debug, Deserialize)]
pub struct UserPrefsRequest {
    pub preferred_models: Option<String>,
    pub summary_models: Option<String>,
    pub summary_prompt_override: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UserPrefsRow {
    pub user_id: String,
    pub preferred_models: Option<String>,
    pub summary_models: Option<String>,
    pub summary_prompt_override: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

// Push notification types
#[derive(Debug, Deserialize)]
pub struct PushRegisterRequest {
    pub device_token: String,
    pub platform: String,
}

// Internal helper types
#[derive(sqlx::FromRow)]
pub struct IdemRow {
    pub response_body: Option<Vec<u8>>,
    pub status: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct LinkTagView {
    pub tag_name: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TagSummary {
    pub tag_name: String,
    pub count: i64,
}

#[derive(sqlx::FromRow)]
pub struct AggRow {
    pub count: i64,
}
