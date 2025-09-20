/// <reference path="./ambient.d.ts" />
import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep, WorkerEntrypoint } from "cloudflare:workers";
import type { D1Database, R2Bucket, Ai, Workflow } from "cloudflare:workers";

interface Env {
  DB: D1Database;
  ARCHIVES: R2Bucket;
  AI: Ai; // Workers AI binding: configured in wrangler as [ai] binding = "AI"
  // Binding below is configured in wrangler under [[workflows]]
  LINK_PIPELINE: Workflow;
}

type LinkPipelineParams = {
  linkId: string;
  userId: string;
};

type LinkRow = {
  id: string;
  user_id: string;
  original_url: string;
  canonical_url: string;
  host: string | null;
  state: string;
  failure_reason: string | null;
  title: string | null;
  description: string | null;
  site_name: string | null;
  favicon_url: string | null;
  image_url: string | null;
  summary_short: string | null;
  summary_long: string | null;
  primary_summary_model_id: string | null;
  lang: string | null;
  word_count: number | null;
  reading_time_sec: number | null;
  content_hash: string | null;
  archive_etag: string | null;
  archive_bytes: number | null;
  archive_r2_key: string | null;
  save_count: number;
  created_at: string;
  updated_at: string;
  ready_at: string | null;
  deleted_at: string | null;
};

export class LinkPipelineWorkflow extends WorkflowEntrypoint<Env, LinkPipelineParams> {
  override async run(event: WorkflowEvent<LinkPipelineParams>, step: WorkflowStep) {
    const { linkId, userId } = event.payload;

    const nowISO = new Date().toISOString();

    // Step 1: Load link and validate
    const link = await step.do("load-link", async () => {
      const res = await this.env.DB.prepare(
        "SELECT * FROM links WHERE id = ? AND user_id = ?"
      )
        .bind(linkId, userId)
        .first<LinkRow>();

      if (!res || res.deleted_at) {
        return null;
      }
      return res;
    });

    if (!link) {
      return { status: "skipped", reason: "link not found or deleted" };
    }

    // SSRF basic guard: ensure http(s) and block localhost-ish hosts
    if (!isPublicHttpUrl(link.canonical_url)) {
      await markFailed(this.env.DB, linkId, "Invalid URL for fetch");
      return { status: "failed", reason: "invalid_url" };
    }

    // Step 2: Fetch and extract main content/metadata
    const fetchResult = await step.do("fetch-html", async () => {
      try {
        const resp = await fetch(link.canonical_url, {
          method: "GET",
          redirect: "follow",
          headers: {
            "User-Agent": "HamrahLinkFetcher/1.0 (+https://hamrah.app)",
            Accept:
              "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          },
        });
        if (!resp.ok) {
          return { ok: false, status: resp.status, error: `HTTP ${resp.status}` };
        }
        const html = await resp.text();
        return { ok: true as const, html };
      } catch (e: any) {
        return { ok: false, status: 0, error: e?.message || "fetch_error" };
      }
    });

    if (!fetchResult.ok) {
      await markFailed(this.env.DB, linkId, `Fetch failed: ${fetchResult.error}`);
      return { status: "failed", reason: "fetch_failed", detail: fetchResult.error };
    }

    const extracted = await step.do("extract-metadata", async () => {
      return extractMetadata(fetchResult.html!, link.canonical_url);
    });

    const textForSummary = extracted.mainText || fallbackText(fetchResult.html!);

    // Step 3: Archive to R2 (raw HTML)
    const archive = await step.do("archive-r2", async () => {
      const key = r2KeyForLink(userId, linkId);
      const putRes = await this.env.ARCHIVES.put(key, fetchResult.html!, {
        httpMetadata: { contentType: "text/html; charset=utf-8" },
      });
      const etag = putRes?.etag ?? null;
      const size = putRes?.size ?? fetchResult.html!.length;
      return { key, etag, bytes: size };
    });

    // Step 4: Compute content hash and stats
    const stats = await step.do("hash-and-stats", async () => {
      const hash = await sha256Hex(textForSummary);
      const wc = (textForSummary.match(/\S+/g) || []).length;
      const rtimeSec = Math.max(30, Math.round((wc / 200) * 60)); // minimum 30s
      return { hash, wc, rtimeSec };
    });

    // Step 5: Determine model from user prefs, generate summaries via Workers AI
    const modelId = await step.do("choose-model", async () => {
      return (
        (await getUserPreferredModel(this.env.DB, userId)) ||
        "@cf/meta/llama-3.1-8b-instruct"
      );
    });

    const summaries = await step.do("summarize", async () => {
      try {
        const short = await aiSummarize(
          this.env.AI,
          modelId,
          textForSummary,
          { style: "concise", maxTokens: 240 }
        );
        const longer = await aiSummarize(
          this.env.AI,
          modelId,
          textForSummary,
          { style: "detailed", maxTokens: 1200 }
        );
        return { ok: true as const, short, long: longer };
      } catch (e: any) {
        return { ok: false as const, error: e?.message || "ai_error" };
      }
    });

    if (!summaries.ok) {
      await markFailed(this.env.DB, linkId, `AI error: ${summaries.error}`);
      return { status: "failed", reason: "ai_failed", detail: summaries.error };
    }

    // Step 6: Tagging with AI (lightweight JSON list)
    const tags = await step.do("tagging", async () => {
      try {
        const tagJson = await aiTag(
          this.env.AI,
          modelId,
          textForSummary,
        );
        // persist tags (ensure tag rows exist, upsert link_tags)
        await upsertTagsForLink(this.env.DB, linkId, tagJson);
        return { ok: true as const, tags: tagJson };
      } catch (e: any) {
        // tagging is best-effort
        return { ok: false as const, error: e?.message || "tag_error" };
      }
    });

    // Step 7: Persist metadata and summaries to D1; mark ready
    await step.do("persist", async () => {
      const now = new Date().toISOString();
      await this.env.DB.batch([
        this.env.DB.prepare(
          `
          UPDATE links SET
            title = COALESCE(?, title),
            description = COALESCE(?, description),
            site_name = COALESCE(?, site_name),
            favicon_url = COALESCE(?, favicon_url),
            image_url = COALESCE(?, image_url),
            summary_short = ?,
            summary_long = ?,
            primary_summary_model_id = ?,
            word_count = ?,
            reading_time_sec = ?,
            content_hash = ?,
            archive_etag = ?,
            archive_bytes = ?,
            archive_r2_key = ?,
            state = 'ready',
            ready_at = ?,
            updated_at = ?
          WHERE id = ? AND user_id = ? AND deleted_at IS NULL
          `
        )
          .bind(
            extracted.title,
            extracted.description,
            extracted.siteName,
            extracted.faviconUrl,
            extracted.imageUrl,
            summaries.short,
            summaries.long,
            modelId,
            stats.wc,
            stats.rtimeSec,
            stats.hash,
            archive.etag,
            archive.bytes,
            archive.key,
            now,
            now,
            linkId,
            userId
          ),
        this.env.DB.prepare(
          `
          INSERT INTO link_summaries
            (id, link_id, user_id, model_id, prompt_version, prompt_text, short_summary, long_summary, tags_json, usage_json, created_at, updated_at)
          VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `
        ).bind(
          crypto.randomUUID(),
          linkId,
          userId,
          modelId,
          "v1",
          "auto-generated",
          summaries.short,
          summaries.long,
          tags.ok ? JSON.stringify(tags.tags) : null,
          null,
          now,
          now
        ),
      ]);
    });

    // Step 8: Push notifications (best-effort, stub – integration point)
    await step.do("notify", async () => {
      // TODO: Integrate with APNS/FCM or a push service; here we just log.
      // Example: fetch tokens and send via 3rd party system.
      console.log(`notify: link ${linkId} ready for user ${userId}`);
    });

    return { status: "completed", linkId, userId };
  }
}

export default class PipelineService extends WorkerEntrypoint<Env> {
  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/processLink") {
      try {
        const payload = (await request.json()) as LinkPipelineParams;
        if (!payload || !payload.linkId || !payload.userId) {
          return Response.json({ error: "Invalid payload" }, { status: 400 });
        }
        return await this.processLink(payload);
      } catch (e: any) {
        return Response.json({ error: e?.message || "Invalid JSON" }, { status: 400 });
      }
    }
    return new Response(null, { status: 404 });
  }

  // Method callable via Service Binding from other Workers (e.g., API Worker)
  async processLink(payload: LinkPipelineParams): Promise<Response> {
    const instance = await this.env.LINK_PIPELINE.create({ params: payload });
    return Response.json({
      id: instance.id,
      details: await instance.status(),
    });
  }
}

/* --------------- Helpers ---------------- */

function isPublicHttpUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    const host = (u.hostname || "").toLowerCase();
    if (host === "localhost" || host.endsWith(".local")) return false;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      // naive private ranges block
      if (
        host.startsWith("10.") ||
        host.startsWith("127.") ||
        host.startsWith("192.168.") ||
        host.startsWith("172.16.") ||
        host.startsWith("172.17.") ||
        host.startsWith("172.18.") ||
        host.startsWith("172.19.") ||
        host.startsWith("172.20.") ||
        host.startsWith("172.21.") ||
        host.startsWith("172.22.") ||
        host.startsWith("172.23.") ||
        host.startsWith("172.24.") ||
        host.startsWith("172.25.") ||
        host.startsWith("172.26.") ||
        host.startsWith("172.27.") ||
        host.startsWith("172.28.") ||
        host.startsWith("172.29.") ||
        host.startsWith("172.30.") ||
        host.startsWith("172.31.")
      ) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

function r2KeyForLink(userId: string, linkId: string): string {
  return `archives/${userId}/${linkId}.html`;
}

async function markFailed(db: D1Database, linkId: string, reason: string) {
  const now = new Date().toISOString();
  await db
    .prepare(
      "UPDATE links SET state = 'failed', failure_reason = ?, updated_at = ? WHERE id = ?"
    )
    .bind(reason, now, linkId)
    .run();
}

function extractMetadata(html: string, url: string): {
  title: string | null;
  description: string | null;
  siteName: string | null;
  imageUrl: string | null;
  faviconUrl: string | null;
  mainText: string;
} {
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  const title = titleMatch ? decodeHtml(titleMatch[1].trim()) : null;

  const meta = collectMeta(html);
  const description =
    meta["og:description"] ||
    meta["twitter:description"] ||
    meta["description"] ||
    null;

  const siteName = meta["og:site_name"] || null;
  const imageUrl = meta["og:image"] || meta["twitter:image"] || null;

  const faviconCandidate = findFaviconUrl(html, url);
  const mainText = stripHtmlToText(html);

  return {
    title,
    description,
    siteName,
    imageUrl,
    faviconUrl: faviconCandidate,
    mainText,
  };
}

function collectMeta(html: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re =
    /<meta\s+(?:name|property)=["']([^"']+)["']\s+content=["']([^"']+)["'][^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    out[m[1].toLowerCase()] = decodeHtml(m[2]);
  }
  return out;
}

function findFaviconUrl(html: string, pageUrl: string): string | null {
  const linkRelIconRe =
    /<link[^>]+rel=["'](?:shortcut\s+icon|icon|apple-touch-icon(?:-precomposed)?)["'][^>]*>/gi;
  const hrefRe = /href=["']([^"']+)["']/i;
  const m = linkRelIconRe.exec(html);
  if (m) {
    const hr = hrefRe.exec(m[0]);
    if (hr && hr[1]) {
      try {
        return new URL(hr[1], pageUrl).toString();
      } catch { }
    }
  }
  try {
    const u = new URL(pageUrl);
    return `${u.protocol}//${u.host}/favicon.ico`;
  } catch {
    return null;
  }
}

function stripHtmlToText(html: string): string {
  // Remove scripts/styles and tags, keep text
  const cleaned = html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, " ")
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, " ")
    .replace(/<\/?[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned;
}

function fallbackText(html: string): string {
  const text = stripHtmlToText(html);
  // Limit to some reasonable length to avoid huge prompts
  return text.slice(0, 100_000); // 100k chars cap
}

function decodeHtml(s: string): string {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'");
}

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(hash);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function getUserPreferredModel(db: D1Database, userId: string): Promise<string | null> {
  const row = await db
    .prepare(
      "SELECT preferred_models, summary_models FROM user_prefs WHERE user_id = ?"
    )
    .bind(userId)
    .first<{ preferred_models: string | null; summary_models: string | null }>();

  const list = parseModelList(row?.summary_models) || parseModelList(row?.preferred_models);
  return list?.[0] || null;
}

function parseModelList(s: string | null | undefined): string[] {
  if (s == null) return [];
  const trimmed = s.trim();
  if (trimmed === "") return [];

  // Try JSON array
  if (trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (!Array.isArray(parsed)) return [];
      return (parsed as string[]).filter(Boolean);
    } catch {
      return [];
    }
  }

  // If it looks like an object or quoted string, treat as invalid
  if (
    trimmed.startsWith("{") ||
    (trimmed.startsWith("\"") && trimmed.endsWith("\""))
  ) {
    return [];
  }

  // Treat as CSV if there's a comma
  if (trimmed.includes(",")) {
    const arr = trimmed.split(",").map((x) => x.trim()).filter(Boolean);
    return arr.length > 0 ? arr : [];
  }

  // If the trimmed string is empty after all, return []
  if (trimmed === "") return [];

  // Otherwise, treat as single model string
  return [trimmed];
}

async function aiSummarize(
  ai: Ai,
  model: string,
  text: string,
  opts: { style: "concise" | "detailed"; maxTokens: number }
): Promise<string> {
  // Workers AI typical chat-style input
  // Some models require "messages" rather than "prompt"
  const system = `You are a summarization assistant. Produce ${opts.style} summaries of the provided content.`;
  const user = `Summarize the following content in ${opts.style} form.\n\nContent:\n${text}`;

  const result: any = await ai.run(model, {
    messages: [
      { role: "system", content: system },
      { role: "user", content: user },
    ],
    max_tokens: opts.maxTokens,
    temperature: 0.2,
  });

  // Attempt to normalize output
  const out =
    result?.response ||
    result?.result ||
    result?.choices?.[0]?.message?.content ||
    result?.choices?.[0]?.text ||
    "";
  return String(out).trim();
}

async function aiTag(ai: Ai, model: string, text: string): Promise<string[]> {
  const system =
    "You are an assistant that extracts 3-7 concise topical tags from content. Output a JSON array of lowercase tags (strings).";
  const user = `Extract tags for this content:\n${text}`;

  const res: any = await ai.run(model, {
    messages: [
      { role: "system", content: system },
      { role: "user", content: user },
    ],
    temperature: 0.2,
    max_tokens: 256,
  });

  const out =
    res?.response ||
    res?.result ||
    res?.choices?.[0]?.message?.content ||
    res?.choices?.[0]?.text ||
    "[]";

  try {
    const parsed = JSON.parse(String(out));
    if (Array.isArray(parsed)) {
      return parsed.map((t) => String(t)).filter(Boolean).slice(0, 10);
    }
  } catch {
    // try to salvage tags by regex of JSON array
    const m = String(out).match(/\[.*\]/s);
    if (m) {
      try {
        const p = JSON.parse(m[0]);
        if (Array.isArray(p)) {
          return p.map((t) => String(t)).filter(Boolean).slice(0, 10);
        }
      } catch { }
    }
  }
  return [];
}

async function upsertTagsForLink(db: D1Database, linkId: string, tags: string[]) {
  if (!tags || tags.length === 0) return;
  for (const name of tags) {
    // ensure tag exists
    const existing = await db
      .prepare("SELECT id FROM tags WHERE name = ?")
      .bind(name)
      .first<{ id: string }>();
    let tagId = existing?.id;
    if (!tagId) {
      tagId = crypto.randomUUID();
      await db.prepare("INSERT INTO tags (id, name) VALUES (?, ?)").bind(tagId, name).run();
    }
    // upsert link_tags
    await db
      .prepare(
        `
        INSERT INTO link_tags (link_id, tag_id, confidence)
        VALUES (?, ?, ?)
        ON CONFLICT(link_id, tag_id) DO UPDATE SET confidence=excluded.confidence
      `
      )
      .bind(linkId, tagId, 0.9)
      .run();
  }
}
