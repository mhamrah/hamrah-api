use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
}
