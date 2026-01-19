use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationTier {
    ReadOnly,
    Operator,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzSummary {
    pub uid: u32,
    pub gid: u32,
    pub role: AuthorizationTier,
}
