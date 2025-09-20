hamrah-api/migrations/0002_links_pipeline.sql
```
-- Links, Processing, Summaries, Archives, Delta Sync, Pushes Schema Migration

-- LINKS TABLE
CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY, -- ULID
    user_id TEXT NOT NULL,
    client_id TEXT, -- UUID/UUIDv7 from client, optional
    original_url TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    host TEXT,
    state TEXT NOT NULL, -- queued|fetching|processing|ready|failed
    failure_reason TEXT,
    title TEXT,
    description TEXT,
    site_name TEXT,
    favicon_url TEXT,
    image_url TEXT,
    summary_short TEXT,
    summary_long TEXT,
    primary_summary_model_id TEXT,
    lang TEXT,
    word_count INTEGER,
    reading_time_sec INTEGER,
    content_hash TEXT,
    archive_etag TEXT,
    archive_bytes INTEGER,
    archive_r2_key TEXT,
    save_count INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    ready_at TEXT,
    UNIQUE (user_id, canonical_url)
);

-- LINK_SAVES TABLE
CREATE TABLE IF NOT EXISTS link_saves (
    id TEXT PRIMARY KEY,
    link_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    source_app TEXT,
    shared_text TEXT,
    shared_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES links(user_id) ON DELETE CASCADE
);

-- TAGS TABLE
CREATE TABLE IF NOT EXISTS tags (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

-- LINK_TAGS TABLE
CREATE TABLE IF NOT EXISTS link_tags (
    link_id TEXT NOT NULL,
    tag_id TEXT NOT NULL,
    confidence REAL,
    PRIMARY KEY (link_id, tag_id),
    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- LINK_SUMMARIES TABLE
CREATE TABLE IF NOT EXISTS link_summaries (
    id TEXT PRIMARY KEY,
    link_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    model_id TEXT NOT NULL, -- e.g., "@cf/meta/llama-3.1-8b-instruct"
    prompt_version TEXT,
    prompt_text TEXT NOT NULL,
    short_summary TEXT NOT NULL,
    long_summary TEXT,
    tags_json TEXT,
    usage_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(link_id, model_id),
    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES links(user_id) ON DELETE CASCADE
);

-- JOBS TABLE
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    link_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    kind TEXT NOT NULL, -- process_link
    run_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES links(user_id) ON DELETE CASCADE
);

-- PUSH_TOKENS TABLE
CREATE TABLE IF NOT EXISTS push_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_token TEXT NOT NULL,
    platform TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, device_token),
    FOREIGN KEY (user_id) REFERENCES links(user_id) ON DELETE CASCADE
);

-- USER_PREFS TABLE
CREATE TABLE IF NOT EXISTS user_prefs (
    user_id TEXT PRIMARY KEY,
    preferred_models TEXT,
    summary_models TEXT,
    summary_prompt_override TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES links(user_id) ON DELETE CASCADE
);

-- IDEMPOTENCY_KEYS TABLE
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    response_body BLOB,
    status INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES links(user_id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_links_user_id ON links(user_id);
CREATE INDEX IF NOT EXISTS idx_links_canonical_url ON links(canonical_url);
CREATE INDEX IF NOT EXISTS idx_links_updated_at ON links(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_link_saves_link_id ON link_saves(link_id);
CREATE INDEX IF NOT EXISTS idx_link_tags_tag_id ON link_tags(tag_id);
CREATE INDEX IF NOT EXISTS idx_link_summaries_link_id ON link_summaries(link_id);
CREATE INDEX IF NOT EXISTS idx_jobs_link_id ON jobs(link_id);
CREATE INDEX IF NOT EXISTS idx_push_tokens_user_id ON push_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_user_prefs_user_id ON user_prefs(user_id);

-- End of migration
