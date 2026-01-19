//! Error types for the KeyEnv SDK.

use thiserror::Error;

/// Error type for KeyEnv SDK operations.
#[derive(Error, Debug)]
pub enum Error {
    /// API error response from the KeyEnv server.
    #[error("API error {status}: {message}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Error message from the API.
        message: String,
        /// Optional error code for programmatic handling.
        code: Option<String>,
    },

    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Environment variable operation failed.
    #[error("Environment variable error: {0}")]
    Env(#[from] std::env::VarError),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Create a new API error.
    pub fn api(status: u16, message: impl Into<String>) -> Self {
        Self::Api {
            status,
            message: message.into(),
            code: None,
        }
    }

    /// Create a new API error with a code.
    pub fn api_with_code(status: u16, message: impl Into<String>, code: impl Into<String>) -> Self {
        Self::Api {
            status,
            message: message.into(),
            code: Some(code.into()),
        }
    }

    /// Create a new configuration error.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Returns true if this is a 404 Not Found error.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Api { status: 404, .. })
    }

    /// Returns true if this is a 401 Unauthorized error.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Api { status: 401, .. })
    }

    /// Returns true if this is a 403 Forbidden error.
    pub fn is_forbidden(&self) -> bool {
        matches!(self, Self::Api { status: 403, .. })
    }

    /// Returns true if this is a 409 Conflict error.
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Api { status: 409, .. })
    }

    /// Returns true if this is a 429 Rate Limited error.
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Self::Api { status: 429, .. })
    }

    /// Returns true if this is a 5xx server error.
    pub fn is_server_error(&self) -> bool {
        matches!(self, Self::Api { status, .. } if *status >= 500 && *status < 600)
    }
}

/// Result type alias for KeyEnv operations.
pub type Result<T> = std::result::Result<T, Error>;
