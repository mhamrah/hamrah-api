use axum::http::{HeaderMap, HeaderValue};
use chrono::{DateTime, Utc};

pub struct CookieOptions {
    pub http_only: bool,
    pub secure: bool,
    pub same_site: SameSite,
    pub path: String,
    pub domain: Option<String>,
    pub max_age: Option<i64>,
    pub expires: Option<DateTime<Utc>>,
}

impl Default for CookieOptions {
    fn default() -> Self {
        Self {
            http_only: true,
            secure: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            domain: None,
            max_age: None,
            expires: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SameSite::Strict => write!(f, "Strict"),
            SameSite::Lax => write!(f, "Lax"),
            SameSite::None => write!(f, "None"),
        }
    }
}

pub fn set_session_cookie(
    headers: &mut HeaderMap,
    name: &str,
    value: &str,
    expires_at: DateTime<Utc>,
    is_secure: bool,
) {
    let domain = get_cookie_domain_from_request(headers);
    
    let options = CookieOptions {
        http_only: true,
        secure: is_secure,
        same_site: SameSite::Lax,
        expires: Some(expires_at),
        domain,
        ..Default::default()
    };
    
    set_cookie(headers, name, value, options);
}

pub fn delete_session_cookie(headers: &mut HeaderMap, name: &str, is_secure: bool) {
    let domain = get_cookie_domain_from_request(headers);
    
    let options = CookieOptions {
        http_only: true,
        secure: is_secure,
        same_site: SameSite::Lax,
        max_age: Some(0),
        domain,
        ..Default::default()
    };
    
    set_cookie(headers, name, "", options);
}

pub fn set_cookie(headers: &mut HeaderMap, name: &str, value: &str, options: CookieOptions) {
    let mut cookie = format!("{}={}", name, value);
    
    if options.http_only {
        cookie.push_str("; HttpOnly");
    }
    
    if options.secure {
        cookie.push_str("; Secure");
    }
    
    cookie.push_str(&format!("; SameSite={}", options.same_site));
    cookie.push_str(&format!("; Path={}", options.path));
    
    if let Some(domain) = &options.domain {
        cookie.push_str(&format!("; Domain={}", domain));
    }
    
    if let Some(max_age) = options.max_age {
        cookie.push_str(&format!("; Max-Age={}", max_age));
    }
    
    if let Some(expires) = options.expires {
        cookie.push_str(&format!("; Expires={}", expires.format("%a, %d %b %Y %H:%M:%S GMT")));
    }
    
    if let Ok(header_value) = HeaderValue::from_str(&cookie) {
        headers.append("Set-Cookie", header_value);
    }
}

pub fn get_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get("cookie")?;
    let cookie_str = cookie_header.to_str().ok()?;
    
    for cookie in cookie_str.split(';') {
        let cookie = cookie.trim();
        if let Some((cookie_name, cookie_value)) = cookie.split_once('=') {
            if cookie_name.trim() == name {
                return Some(cookie_value.trim().to_string());
            }
        }
    }
    
    None
}

fn get_cookie_domain_from_request(headers: &HeaderMap) -> Option<String> {
    // Check the Origin or Referer header to determine the appropriate domain
    let origin = headers.get("origin")
        .or_else(|| headers.get("referer"))
        .and_then(|h| h.to_str().ok())?;
    
    if origin.contains("hamrah.app") {
        // Production: share cookies across hamrah.app subdomains
        Some(".hamrah.app".to_string())
    } else if origin.contains("localhost") {
        // Development: no domain restriction for localhost
        None
    } else {
        // Default: no domain restriction
        None
    }
}