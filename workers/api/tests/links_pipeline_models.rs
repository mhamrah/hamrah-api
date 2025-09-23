use hamrah_api::db::schema::*;

#[test]
fn test_link_struct_serialization() {
    let link = Link {
        id: "01HXYZ".to_string(),
        user_id: "user1".to_string(),
        client_id: Some("client-uuid".to_string()),
        original_url: "https://example.com/path".to_string(),
        canonical_url: "https://example.com/path".to_string(),
        host: Some("example.com".to_string()),
        state: "queued".to_string(),
        failure_reason: None,
        title: Some("Example".to_string()),
        description: Some("desc".to_string()),
        site_name: Some("ExampleSite".to_string()),
        favicon_url: Some("https://example.com/favicon.ico".to_string()),
        image_url: Some("https://example.com/image.png".to_string()),
        summary_short: Some("Short summary".to_string()),
        summary_long: Some("Long summary".to_string()),
        primary_summary_model_id: Some("@cf/meta/llama-3.1-8b-instruct".to_string()),
        lang: Some("en".to_string()),
        word_count: Some(100),
        reading_time_sec: Some(30),
        content_hash: Some("abcdef".to_string()),

        save_count: 2,
        created_at: "2024-06-01T12:00:00Z".to_string(),
        updated_at: "2024-06-01T12:01:00Z".to_string(),
        ready_at: Some("2024-06-01T12:02:00Z".to_string()),
        deleted_at: None,
    };
    let json = serde_json::to_string(&link).unwrap();
    let link2: Link = serde_json::from_str(&json).unwrap();
    assert_eq!(link.id, link2.id);
    assert_eq!(link.user_id, link2.user_id);
    assert_eq!(link.state, link2.state);
    assert_eq!(link.save_count, link2.save_count);
    assert_eq!(link.ready_at, link2.ready_at);
}

#[test]
fn test_link_save_struct() {
    let save = LinkSave {
        id: "save1".to_string(),
        link_id: "link1".to_string(),
        user_id: "user1".to_string(),
        source_app: Some("ios".to_string()),
        shared_text: Some("shared".to_string()),
        shared_at: Some("2024-06-01T12:00:00Z".to_string()),
        created_at: "2024-06-01T12:00:01Z".to_string(),
    };
    let json = serde_json::to_string(&save).unwrap();
    let save2: LinkSave = serde_json::from_str(&json).unwrap();
    assert_eq!(save.id, save2.id);
    assert_eq!(save.link_id, save2.link_id);
}

#[test]
fn test_tag_and_link_tag_structs() {
    let tag = Tag {
        id: "tag1".to_string(),
        name: "news".to_string(),
    };
    let link_tag = LinkTag {
        link_id: "link1".to_string(),
        tag_id: "tag1".to_string(),
        confidence: Some(0.95),
    };
    let tag_json = serde_json::to_string(&tag).unwrap();
    let tag2: Tag = serde_json::from_str(&tag_json).unwrap();
    assert_eq!(tag.id, tag2.id);
    assert_eq!(tag.name, tag2.name);

    let link_tag_json = serde_json::to_string(&link_tag).unwrap();
    let link_tag2: LinkTag = serde_json::from_str(&link_tag_json).unwrap();
    assert_eq!(link_tag.link_id, link_tag2.link_id);
    assert_eq!(link_tag.confidence, link_tag2.confidence);
}

#[test]
fn test_link_summary_struct() {
    let summary = LinkSummary {
        id: "sum1".to_string(),
        link_id: "link1".to_string(),
        user_id: "user1".to_string(),
        model_id: "@cf/meta/llama-3.1-8b-instruct".to_string(),
        prompt_version: Some("default:v1".to_string()),
        prompt_text: "Summarize this".to_string(),
        short_summary: "Short".to_string(),
        long_summary: Some("Long summary".to_string()),
        tags_json: Some(r#"[{"name":"news","confidence":0.9}]"#.to_string()),
        usage_json: Some(r#"{"tokens":100}"#.to_string()),
        created_at: "2024-06-01T12:00:00Z".to_string(),
        updated_at: "2024-06-01T12:01:00Z".to_string(),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let summary2: LinkSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary.id, summary2.id);
    assert_eq!(summary.model_id, summary2.model_id);
    assert_eq!(summary.short_summary, summary2.short_summary);
}

#[test]
fn test_job_struct() {
    let job = Job {
        id: "job1".to_string(),
        link_id: "link1".to_string(),
        user_id: "user1".to_string(),
        kind: "process_link".to_string(),
        run_at: "2024-06-01T12:00:00Z".to_string(),
        attempts: 1,
        last_error: Some("timeout".to_string()),
        created_at: "2024-06-01T12:00:00Z".to_string(),
        updated_at: "2024-06-01T12:01:00Z".to_string(),
    };
    let json = serde_json::to_string(&job).unwrap();
    let job2: Job = serde_json::from_str(&json).unwrap();
    assert_eq!(job.id, job2.id);
    assert_eq!(job.kind, job2.kind);
    assert_eq!(job.attempts, job2.attempts);
}

#[test]
fn test_push_token_struct() {
    let token = PushToken {
        id: "pt1".to_string(),
        user_id: "user1".to_string(),
        device_token: "devtoken".to_string(),
        platform: "ios".to_string(),
        created_at: "2024-06-01T12:00:00Z".to_string(),
    };
    let json = serde_json::to_string(&token).unwrap();
    let token2: PushToken = serde_json::from_str(&json).unwrap();
    assert_eq!(token.id, token2.id);
    assert_eq!(token.platform, token2.platform);
}

#[test]
fn test_user_prefs_struct() {
    let prefs = UserPrefs {
        user_id: "user1".to_string(),
        preferred_models: Some(r#"["@cf/meta/llama-3.1-8b-instruct"]"#.to_string()),
        summary_models: Some(r#"["@cf/meta/llama-3.1-8b-instruct"]"#.to_string()),
        summary_prompt_override: Some("Summarize in 3 sentences.".to_string()),
        created_at: "2024-06-01T12:00:00Z".to_string(),
        updated_at: "2024-06-01T12:01:00Z".to_string(),
    };
    let json = serde_json::to_string(&prefs).unwrap();
    let prefs2: UserPrefs = serde_json::from_str(&json).unwrap();
    assert_eq!(prefs.user_id, prefs2.user_id);
    assert_eq!(
        prefs.summary_prompt_override,
        prefs2.summary_prompt_override
    );
}

#[test]
fn test_idempotency_key_struct() {
    let key = IdempotencyKey {
        key: "idem1".to_string(),
        user_id: "user1".to_string(),
        response_body: Some(vec![1, 2, 3, 4]),
        status: Some(200),
        created_at: "2024-06-01T12:00:00Z".to_string(),
    };
    let json = serde_json::to_string(&key).unwrap();
    let key2: IdempotencyKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key.key, key2.key);
    assert_eq!(key.status, key2.status);
}
