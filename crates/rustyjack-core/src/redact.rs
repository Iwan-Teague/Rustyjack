// Redaction helpers for logging sensitive data
//
// Provides utilities to automatically redact sensitive information
// from logs while maintaining useful debugging information.

use std::fmt;

/// A wrapper type that redacts its contents when displayed
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Macro to redact sensitive values in logs
///
/// # Examples
///
/// ```
/// use rustyjack_core::redact;
///
/// let password = "secret123";
/// tracing::info!("Connecting with password: {}", redact!(password));
/// // Logs: "Connecting with password: [REDACTED]"
/// ```
#[macro_export]
macro_rules! redact {
    ($value:expr) => {
        $crate::redact::Redacted::new($value)
    };
}

/// Check if a field name suggests it contains sensitive data
pub fn is_sensitive_field(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("pass")
        || lower.contains("pwd")
        || lower.contains("psk")
        || lower.contains("key")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("credential")
        || lower.contains("auth")
}

/// Redact sensitive fields in a JSON value
pub fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if is_sensitive_field(key) {
                    *val = serde_json::Value::String("[REDACTED]".to_string());
                } else {
                    redact_json(val);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr.iter_mut() {
                redact_json(val);
            }
        }
        _ => {}
    }
}

/// Redact a string value if the field name is sensitive
pub fn redact_if_sensitive(field: &str, value: &str) -> String {
    if is_sensitive_field(field) {
        "[REDACTED]".to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redacted_display() {
        let secret = Redacted::new("my_secret_password");
        assert_eq!(format!("{}", secret), "[REDACTED]");
        assert_eq!(format!("{:?}", secret), "[REDACTED]");
    }

    #[test]
    fn test_is_sensitive_field() {
        assert!(is_sensitive_field("password"));
        assert!(is_sensitive_field("user_password"));
        assert!(is_sensitive_field("psk"));
        assert!(is_sensitive_field("wpa_key"));
        assert!(is_sensitive_field("secret_token"));
        assert!(is_sensitive_field("AUTH_KEY"));

        assert!(!is_sensitive_field("username"));
        assert!(!is_sensitive_field("ssid"));
        assert!(!is_sensitive_field("interface"));
    }

    #[test]
    fn test_redact_json() {
        let mut value = serde_json::json!({
            "username": "admin",
            "password": "secret123",
            "ssid": "MyNetwork",
            "psk": "wifipassword",
            "nested": {
                "api_key": "abc123",
                "interface": "wlan0"
            }
        });

        redact_json(&mut value);

        assert_eq!(value["username"], "admin");
        assert_eq!(value["password"], "[REDACTED]");
        assert_eq!(value["ssid"], "MyNetwork");
        assert_eq!(value["psk"], "[REDACTED]");
        assert_eq!(value["nested"]["api_key"], "[REDACTED]");
        assert_eq!(value["nested"]["interface"], "wlan0");
    }
}
