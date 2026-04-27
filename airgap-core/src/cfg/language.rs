use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLanguage {
    Chinese,
    English,
}

impl std::fmt::Display for SupportLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Chinese => write!(f, "Chinese"),
            Self::English => write!(f, "English"),
        }
    }
}
