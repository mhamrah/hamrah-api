use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use url::Url;

/// Converts a DateTime<Utc> to Unix timestamp in milliseconds
pub fn datetime_to_timestamp(dt: DateTime<Utc>) -> i64 {
    dt.timestamp_millis()
}

/// Converts a Unix timestamp in milliseconds to DateTime<Utc>
/// Returns current time if the timestamp is invalid
pub fn timestamp_to_datetime(ts: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ts).unwrap_or_else(Utc::now)
}

/// Converts an optional DateTime<Utc> to optional timestamp
#[allow(dead_code)] // Library utility function
pub fn optional_datetime_to_timestamp(dt: Option<DateTime<Utc>>) -> Option<i64> {
    dt.map(datetime_to_timestamp)
}

/// Converts an optional timestamp to optional DateTime<Utc>
#[allow(dead_code)] // Library utility function
pub fn optional_timestamp_to_datetime(ts: Option<i64>) -> Option<DateTime<Utc>> {
    ts.map(timestamp_to_datetime)
}

/// Helper for serializing DateTime fields in API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampField {
    pub timestamp: i64,
    pub iso_string: String,
}

impl TimestampField {
    #[allow(dead_code)] // Library utility function
    pub fn new(dt: DateTime<Utc>) -> Self {
        Self {
            timestamp: datetime_to_timestamp(dt),
            iso_string: dt.to_rfc3339(),
        }
    }

    #[allow(dead_code)] // Library utility function
    pub fn from_timestamp(ts: i64) -> Self {
        let dt = timestamp_to_datetime(ts);
        Self {
            timestamp: ts,
            iso_string: dt.to_rfc3339(),
        }
    }
}

/// Validates email format (basic validation)
#[allow(dead_code)] // Library utility function
pub fn is_valid_email(email: &str) -> bool {
    if email.len() <= 3 || email.len() >= 255 {
        return false;
    }

    let at_count = email.matches('@').count();
    if at_count != 1 {
        return false;
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Check that both local and domain parts are not empty
    !local.is_empty() && !domain.is_empty() && domain.contains('.')
}

/// Validates UUID format
#[allow(dead_code)] // Library utility function
pub fn is_valid_uuid(uuid_str: &str) -> bool {
    uuid::Uuid::parse_str(uuid_str).is_ok()
}

/// Generates a secure random string using UUID
#[allow(dead_code)] // Library utility function
pub fn generate_secure_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Helper to convert boolean to integer for D1 storage
#[allow(dead_code)] // Library utility function
pub fn bool_to_int(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

/// Helper to convert integer from D1 to boolean
#[allow(dead_code)] // Library utility function
pub fn int_to_bool(value: i64) -> bool {
    value != 0
}

/// Canonicalize a URL: lowercase host, https normalization, strip default ports/fragments,
/// collapse slashes, trim trailing slash (except root), remove tracking/session params.
/// Returns canonical_url and host.
pub fn url_canonicalize(original: &str) -> Option<(String, String)> {
    let mut url = Url::parse(original).ok()?;

    // Only http/https
    match url.scheme() {
        "http" | "https" => {}
        _ => return None,
    }

    // Lowercase host
    if let Some(host) = url.host_str() {
        url.set_host(Some(&host.to_lowercase())).ok()?;
    }

    // Normalize https, remove default ports
    if url.scheme() == "https" && url.port() == Some(443) {
        url.set_port(None).ok()?;
    }
    if url.scheme() == "http" && url.port() == Some(80) {
        url.set_port(None).ok()?;
    }

    // Remove fragment
    url.set_fragment(None);

    // Remove tracking/session params
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| {
            let k = k.to_ascii_lowercase();
            !(k.starts_with("utm_")
                || k == "gclid"
                || k == "fbclid"
                || k == "msclkid"
                || k == "mc_eid"
                || k == "ref"
                || k == "ref_src"
                || k == "igshid"
                || k == "sid"
                || k == "session"
                || k == "phpsessid")
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if pairs.is_empty() {
        url.set_query(None);
    } else {
        let query = serde_urlencoded::to_string(&pairs).unwrap_or_default();
        url.set_query(Some(&query));
    }

    // Collapse multiple slashes, trim trailing slash (except root)
    let mut path = url.path().to_string();
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    if path.ends_with('/') && path != "/" {
        path.pop();
        url.set_path(&path);
    } else if path != url.path() {
        url.set_path(&path);
    }

    let host = url.host_str().unwrap_or("").to_string();
    Some((url.to_string(), host))
}

/// Validate that a URL is http(s) and not a private IP or localhost.
/// Returns true if valid for external fetch.
pub fn url_is_valid_public_http(url: &str) -> bool {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return false,
    }
    // Block localhost and private IPs
    if let Some(host) = parsed.host_str() {
        let host_lc = host.to_ascii_lowercase();
        if host_lc == "localhost" || host_lc.ends_with(".local") {
            return false;
        }
        // Try to parse as IP (strip brackets for IPv6)
        let ip_str = if host.starts_with('[') && host.ends_with(']') {
            &host[1..host.len() - 1]
        } else {
            host
        };
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local() {
                        return false;
                    }
                }
                IpAddr::V6(v6) => {
                    if v6.is_loopback()
                        || v6.is_unique_local()
                        || v6.is_unspecified()
                        || v6.is_multicast()
                    {
                        return false;
                    }
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_datetime_to_timestamp() {
        let dt = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        let ts = datetime_to_timestamp(dt);
        assert_eq!(ts, 1672531200000);
    }

    #[test]
    fn test_timestamp_to_datetime() {
        let ts = 1672531200000i64;
        let dt = timestamp_to_datetime(ts);
        let expected = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(dt, expected);
    }

    #[test]
    fn test_is_valid_email() {
        assert!(is_valid_email("test@example.com"));
        assert!(!is_valid_email("invalid-email"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("test@"));
    }

    #[test]
    fn test_bool_conversions() {
        assert_eq!(bool_to_int(true), 1);
        assert_eq!(bool_to_int(false), 0);
        assert_eq!(int_to_bool(1), true);
        assert_eq!(int_to_bool(0), false);
        assert_eq!(int_to_bool(42), true);
    }

    #[test]
    fn test_timestamp_field() {
        let dt = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        let field = TimestampField::new(dt);
        assert_eq!(field.timestamp, 1672531200000);
        assert_eq!(field.iso_string, "2023-01-01T00:00:00+00:00");
    }

    #[test]
    fn test_generate_secure_id() {
        let id1 = generate_secure_id();
        let id2 = generate_secure_id();
        assert_ne!(id1, id2);
        assert!(is_valid_uuid(&id1));
        assert!(is_valid_uuid(&id2));
    }

    #[test]
    fn test_url_canonicalize_basic() {
        let (canon, host) =
            url_canonicalize("https://EXAMPLE.com:443/foo/bar/?utm_source=abc&ref=xyz#frag")
                .unwrap();
        assert_eq!(host, "example.com");
        assert!(canon.starts_with("https://example.com/foo/bar"));
        assert!(!canon.contains("utm_"));
        assert!(!canon.contains("ref="));
        assert!(!canon.contains("#frag"));
    }

    #[test]
    fn test_url_canonicalize_trailing_slash() {
        let (canon, _) = url_canonicalize("https://example.com/foo/bar/").unwrap();
        assert!(!canon.ends_with("//"));
        assert!(!canon.ends_with("/foo/bar/"));
        assert!(canon.ends_with("/foo/bar"));
    }

    #[test]
    fn test_url_canonicalize_collapse_slashes() {
        let (canon, _) = url_canonicalize("https://example.com//foo///bar/").unwrap();
        assert!(canon.contains("/foo/bar"));
        assert!(!canon.contains("//foo"));
    }

    #[test]
    fn test_url_canonicalize_strip_session_params() {
        let (canon, _) =
            url_canonicalize("https://example.com/page?sid=123&session=abc&PHPSESSID=xyz&ok=1")
                .unwrap();
        assert!(!canon.contains("sid="));
        assert!(!canon.contains("session="));
        assert!(!canon.contains("PHPSESSID"));
        assert!(canon.contains("ok=1"));
    }

    #[test]
    fn test_url_canonicalize_non_http() {
        assert!(url_canonicalize("ftp://example.com/abc").is_none());
        assert!(url_canonicalize("mailto:foo@bar.com").is_none());
    }

    #[test]
    fn test_url_is_valid_public_http() {
        assert!(url_is_valid_public_http("https://example.com"));
        assert!(url_is_valid_public_http("http://foo.org/path"));
        assert!(!url_is_valid_public_http("ftp://example.com"));
        assert!(!url_is_valid_public_http("http://localhost"));
        assert!(!url_is_valid_public_http("http://127.0.0.1"));
        assert!(!url_is_valid_public_http("http://10.0.0.1"));
        assert!(!url_is_valid_public_http("http://192.168.1.1"));

        assert!(!url_is_valid_public_http("http://[::1]"));

        assert!(!url_is_valid_public_http("http://mybox.local"));
    }
}
