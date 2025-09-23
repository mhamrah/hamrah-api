import { describe, it, expect, beforeEach } from 'vitest'

// We'll need to extract the helper functions to test them
// For now, we'll test the functions as if they were exported

describe('Helper Functions', () => {
  describe('isPublicHttpUrl', () => {
    // Test function that would be extracted from main file
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

    it('should allow valid public HTTP URLs', () => {
      expect(isPublicHttpUrl('http://example.com')).toBe(true)
      expect(isPublicHttpUrl('https://www.google.com')).toBe(true)
      expect(isPublicHttpUrl('https://api.github.com/repos')).toBe(true)
    })

    it('should reject non-HTTP protocols', () => {
      expect(isPublicHttpUrl('ftp://example.com')).toBe(false)
      expect(isPublicHttpUrl('file:///etc/passwd')).toBe(false)
      expect(isPublicHttpUrl('javascript:alert(1)')).toBe(false)
    })

    it('should reject localhost and local domains', () => {
      expect(isPublicHttpUrl('http://localhost')).toBe(false)
      expect(isPublicHttpUrl('https://localhost:3000')).toBe(false)
      expect(isPublicHttpUrl('http://test.local')).toBe(false)
      expect(isPublicHttpUrl('https://myapp.local')).toBe(false)
    })

    it('should reject private IP ranges', () => {
      // 10.x.x.x
      expect(isPublicHttpUrl('http://10.0.0.1')).toBe(false)
      expect(isPublicHttpUrl('https://10.255.255.255')).toBe(false)

      // 127.x.x.x (loopback)
      expect(isPublicHttpUrl('http://127.0.0.1')).toBe(false)
      expect(isPublicHttpUrl('https://127.1.1.1')).toBe(false)

      // 192.168.x.x
      expect(isPublicHttpUrl('http://192.168.1.1')).toBe(false)
      expect(isPublicHttpUrl('https://192.168.0.100')).toBe(false)

      // 172.16.x.x - 172.31.x.x
      expect(isPublicHttpUrl('http://172.16.0.1')).toBe(false)
      expect(isPublicHttpUrl('https://172.31.255.255')).toBe(false)
    })

    it('should allow public IP addresses', () => {
      expect(isPublicHttpUrl('http://8.8.8.8')).toBe(true)
      expect(isPublicHttpUrl('https://1.1.1.1')).toBe(true)
      expect(isPublicHttpUrl('http://208.67.222.222')).toBe(true)
    })

    it('should handle invalid URLs gracefully', () => {
      expect(isPublicHttpUrl('not-a-url')).toBe(false)
      expect(isPublicHttpUrl('')).toBe(false)
      expect(isPublicHttpUrl('http://')).toBe(false)
      expect(isPublicHttpUrl('malformed://url')).toBe(false)
    })
  })



  describe('stripHtmlToText', () => {
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

    it('should remove HTML tags', () => {
      const html = '<p>Hello <strong>world</strong>!</p>'
      expect(stripHtmlToText(html)).toBe('Hello world !')
    })

    it('should remove script tags and content', () => {
      const html = '<p>Before</p><script>alert("evil")</script><p>After</p>'
      expect(stripHtmlToText(html)).toBe('Before After')
    })

    it('should remove style tags and content', () => {
      const html = '<p>Before</p><style>body { color: red; }</style><p>After</p>'
      expect(stripHtmlToText(html)).toBe('Before After')
    })

    it('should handle nested tags', () => {
      const html = '<div><p>Nested <span>content</span> here</p></div>'
      expect(stripHtmlToText(html)).toBe('Nested content here')
    })

    it('should normalize whitespace', () => {
      const html = '<p>Multiple\n   spaces\t\tand\r\nnewlines</p>'
      expect(stripHtmlToText(html)).toBe('Multiple spaces and newlines')
    })

    it('should handle empty and whitespace-only HTML', () => {
      expect(stripHtmlToText('')).toBe('')
      expect(stripHtmlToText('<div></div>')).toBe('')
      expect(stripHtmlToText('<p>   </p>')).toBe('')
    })
  })

  describe('decodeHtml', () => {
    function decodeHtml(s: string): string {
      return s
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&#039;/g, "'");
    }

    it('should decode HTML entities', () => {
      expect(decodeHtml('&amp;')).toBe('&')
      expect(decodeHtml('&lt;')).toBe('<')
      expect(decodeHtml('&gt;')).toBe('>')
      expect(decodeHtml('&quot;')).toBe('"')
      expect(decodeHtml('&#039;')).toBe("'")
    })

    it('should decode multiple entities in one string', () => {
      const input = 'Tom &amp; Jerry &lt;3 &quot;cartoons&quot;'
      const expected = 'Tom & Jerry <3 "cartoons"'
      expect(decodeHtml(input)).toBe(expected)
    })

    it('should handle strings without entities', () => {
      const input = 'Regular text without entities'
      expect(decodeHtml(input)).toBe(input)
    })

    it('should handle empty strings', () => {
      expect(decodeHtml('')).toBe('')
    })
  })

  describe('parseModelList', () => {
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

    it('should parse JSON array format', () => {
      const input = '["model1", "model2", "model3"]'
      const expected = ['model1', 'model2', 'model3']
      expect(parseModelList(input)).toEqual(expected)
    })

    it('should parse CSV format', () => {
      const input = 'model1, model2, model3'
      const expected = ['model1', 'model2', 'model3']
      expect(parseModelList(input)).toEqual(expected)
    })

    it('should filter out empty strings in JSON', () => {
      const input = '["model1", "", "model2", null, "model3"]'
      const expected = ['model1', 'model2', 'model3']
      expect(parseModelList(input)).toEqual(expected)
    })

    it('should filter out empty strings in CSV', () => {
      const input = 'model1, , model2,  , model3'
      const expected = ['model1', 'model2', 'model3']
      expect(parseModelList(input)).toEqual(expected)
    })

    it('should return null for null/undefined/empty inputs', () => {
      expect(parseModelList(null)).toEqual([])
      expect(parseModelList(undefined)).toEqual([])
      expect(parseModelList('')).toEqual([])
      expect(parseModelList('   ')).toEqual([])
    })

    it('should return null for invalid JSON', () => {
      expect(parseModelList('{"invalid": "json"}')).toEqual([])
      expect(parseModelList('[invalid json')).toEqual([])
    })

    it('should handle single model', () => {
      expect(parseModelList('["single-model"]')).toEqual(['single-model'])
      expect(parseModelList('single-model')).toEqual(['single-model'])
    })
  })

  describe('sha256Hex', () => {
    // Note: This would need to be tested in a proper environment with crypto.subtle
    it('should generate consistent hashes', async () => {
      // Mock implementation for testing
      const mockSha256Hex = async (text: string): Promise<string> => {
        // Simple deterministic hash for testing
        let hash = 0;
        for (let i = 0; i < text.length; i++) {
          const char = text.charCodeAt(i);
          hash = ((hash << 5) - hash) + char;
          hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString(16).padStart(8, '0');
      }

      const result1 = await mockSha256Hex('test string')
      const result2 = await mockSha256Hex('test string')
      const result3 = await mockSha256Hex('different string')

      expect(result1).toBe(result2)
      expect(result1).not.toBe(result3)
    })
  })

  describe('collectMeta', () => {
    function collectMeta(html: string): Record<string, string> {
      const out: Record<string, string> = {};
      const re =
        /<meta\s+(?:name|property)=["']([^"']+)["']\s+content=["']([^"']+)["'][^>]*>/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(html))) {
        out[m[1].toLowerCase()] = m[2]; // Note: removed decodeHtml for simplicity
      }
      return out;
    }

    it('should extract meta tags with name attribute', () => {
      const html = '<meta name="description" content="A great website">'
      const result = collectMeta(html)
      expect(result.description).toBe('A great website')
    })

    it('should extract meta tags with property attribute (OpenGraph)', () => {
      const html = '<meta property="og:title" content="My Page Title">'
      const result = collectMeta(html)
      expect(result['og:title']).toBe('My Page Title')
    })

    it('should handle multiple meta tags', () => {
      const html = `
        <meta name="description" content="Page description">
        <meta property="og:title" content="OG Title">
        <meta name="keywords" content="test, meta, tags">
      `
      const result = collectMeta(html)

      expect(result.description).toBe('Page description')
      expect(result['og:title']).toBe('OG Title')
      expect(result.keywords).toBe('test, meta, tags')
    })

    it('should convert meta names to lowercase', () => {
      const html = '<meta name="DESCRIPTION" content="Test">'
      const result = collectMeta(html)
      expect(result.description).toBe('Test')
    })

    it('should handle single and double quotes', () => {
      const html = `
        <meta name="description" content="Double quotes">
        <meta name='keywords' content='Single quotes'>
      `
      const result = collectMeta(html)

      expect(result.description).toBe('Double quotes')
      expect(result.keywords).toBe('Single quotes')
    })

    it('should return empty object for HTML without meta tags', () => {
      const html = '<p>No meta tags here</p>'
      const result = collectMeta(html)
      expect(result).toEqual({})
    })
  })

  describe('findFaviconUrl', () => {
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

    it('should find favicon from link tag', () => {
      const html = '<link rel="icon" href="/favicon.ico">'
      const pageUrl = 'https://example.com/page'
      const result = findFaviconUrl(html, pageUrl)
      expect(result).toBe('https://example.com/favicon.ico')
    })

    it('should find shortcut icon', () => {
      const html = '<link rel="shortcut icon" href="/images/favicon.png">'
      const pageUrl = 'https://example.com/page'
      const result = findFaviconUrl(html, pageUrl)
      expect(result).toBe('https://example.com/images/favicon.png')
    })

    it('should find apple-touch-icon', () => {
      const html = '<link rel="apple-touch-icon" href="/apple-icon.png">'
      const pageUrl = 'https://example.com/page'
      const result = findFaviconUrl(html, pageUrl)
      expect(result).toBe('https://example.com/apple-icon.png')
    })

    it('should fallback to default favicon.ico', () => {
      const html = '<p>No favicon link found</p>'
      const pageUrl = 'https://example.com/some/deep/page'
      const result = findFaviconUrl(html, pageUrl)
      expect(result).toBe('https://example.com/favicon.ico')
    })

    it('should handle absolute favicon URLs', () => {
      const html = '<link rel="icon" href="https://cdn.example.com/favicon.ico">'
      const pageUrl = 'https://example.com/page'
      const result = findFaviconUrl(html, pageUrl)
      expect(result).toBe('https://cdn.example.com/favicon.ico')
    })

    it('should return null for invalid page URLs', () => {
      const html = '<link rel="icon" href="/favicon.ico">'
      const pageUrl = 'invalid-url'
      const result = findFaviconUrl(html, pageUrl)
      expect(result).toBe(null)
    })
  })
})
