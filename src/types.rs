//! Type definitions for the KeyEnv SDK.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A KeyEnv user.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    /// User ID.
    pub id: String,
    /// User email address.
    pub email: String,
    /// User's first name.
    pub first_name: String,
    /// User's last name.
    pub last_name: String,
    /// URL to user's avatar image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// When the user was created.
    pub created_at: DateTime<Utc>,
}

/// A KeyEnv project.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Project {
    /// Project ID.
    pub id: String,
    /// Project name.
    pub name: String,
    /// Project description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Team ID that owns this project.
    pub team_id: String,
    /// When the project was created.
    pub created_at: DateTime<Utc>,
    /// When the project was last updated.
    pub updated_at: DateTime<Utc>,
    /// Environments in this project.
    #[serde(default)]
    pub environments: Vec<Environment>,
}

/// An environment within a project.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Environment {
    /// Environment ID.
    pub id: String,
    /// Environment name (e.g., "development", "production").
    pub name: String,
    /// Environment description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Project ID this environment belongs to.
    pub project_id: String,
    /// ID of environment this one inherits from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inherits_from_id: Option<String>,
    /// Display order.
    pub order: i32,
    /// When the environment was created.
    pub created_at: DateTime<Utc>,
    /// When the environment was last updated.
    pub updated_at: DateTime<Utc>,
}

/// A secret's metadata without the value.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Secret {
    /// Secret ID.
    pub id: String,
    /// Secret key name.
    pub key: String,
    /// Secret description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Environment ID this secret belongs to.
    pub environment_id: String,
    /// Type of secret (detected automatically).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<String>,
    /// Version number.
    pub version: i32,
    /// When the secret was created.
    pub created_at: DateTime<Utc>,
    /// When the secret was last updated.
    pub updated_at: DateTime<Utc>,
}

/// A secret including its decrypted value.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretWithValue {
    /// Secret ID.
    pub id: String,
    /// Secret key name.
    pub key: String,
    /// Secret description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Environment ID this secret belongs to.
    pub environment_id: String,
    /// Type of secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<String>,
    /// Version number.
    pub version: i32,
    /// When the secret was created.
    pub created_at: DateTime<Utc>,
    /// When the secret was last updated.
    pub updated_at: DateTime<Utc>,
    /// The decrypted secret value.
    pub value: String,
}

/// A secret with inheritance information.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretWithInheritance {
    /// Secret ID.
    pub id: String,
    /// Secret key name.
    pub key: String,
    /// Secret description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Environment ID this secret belongs to.
    pub environment_id: String,
    /// Type of secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<String>,
    /// Version number.
    pub version: i32,
    /// When the secret was created.
    pub created_at: DateTime<Utc>,
    /// When the secret was last updated.
    pub updated_at: DateTime<Utc>,
    /// Environment name this secret was inherited from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inherited_from: Option<String>,
}

/// A secret with value and inheritance information.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretWithValueAndInheritance {
    /// Secret ID.
    pub id: String,
    /// Secret key name.
    pub key: String,
    /// Secret description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Environment ID this secret belongs to.
    pub environment_id: String,
    /// Type of secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<String>,
    /// Version number.
    pub version: i32,
    /// When the secret was created.
    pub created_at: DateTime<Utc>,
    /// When the secret was last updated.
    pub updated_at: DateTime<Utc>,
    /// The decrypted secret value.
    pub value: String,
    /// Environment name this secret was inherited from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inherited_from: Option<String>,
}

/// Input for creating or importing a secret.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretInput {
    /// Secret key name.
    pub key: String,
    /// Secret value.
    pub value: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl SecretInput {
    /// Create a new secret input.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            description: None,
        }
    }

    /// Create a new secret input with a description.
    pub fn with_description(
        key: impl Into<String>,
        value: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            description: Some(description.into()),
        }
    }
}

/// Options for bulk import operations.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BulkImportOptions {
    /// Whether to overwrite existing secrets.
    pub overwrite: bool,
}

/// Result of a bulk import operation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BulkImportResult {
    /// Number of secrets created.
    pub created: i32,
    /// Number of secrets updated.
    pub updated: i32,
    /// Number of secrets skipped.
    pub skipped: i32,
}

/// A permission for an environment.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Permission {
    /// Permission ID.
    pub id: String,
    /// User ID.
    pub user_id: String,
    /// User email.
    pub user_email: String,
    /// Environment ID.
    pub environment_id: String,
    /// Environment name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_name: Option<String>,
    /// Role (e.g., "read", "write", "admin").
    pub role: String,
    /// Whether the user can write to this environment.
    pub can_write: bool,
    /// When the permission was created.
    pub created_at: DateTime<Utc>,
    /// When the permission was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Input for setting a permission.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PermissionInput {
    /// User ID.
    pub user_id: String,
    /// Role to assign.
    pub role: String,
}

/// Response containing the current user's permissions.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MyPermissionsResponse {
    /// List of permissions.
    pub permissions: Vec<Permission>,
    /// Whether the user is a team admin.
    pub is_team_admin: bool,
}

/// Default permission settings for an environment.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DefaultPermission {
    /// Environment name.
    pub environment_name: String,
    /// Default role for new team members.
    pub default_role: String,
}

/// Historical version of a secret.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretHistory {
    /// History entry ID.
    pub id: String,
    /// Secret ID.
    pub secret_id: String,
    /// Secret key.
    pub key: String,
    /// Version number.
    pub version: i32,
    /// User ID who made the change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_by: Option<String>,
    /// Type of change.
    pub change_type: String,
    /// When the change was made.
    pub created_at: DateTime<Utc>,
}

/// A team.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Team {
    /// Team ID.
    pub id: String,
    /// Team name.
    pub name: String,
    /// When the team was created.
    pub created_at: DateTime<Utc>,
    /// When the team was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Information about a service token.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceToken {
    /// Token ID.
    pub id: String,
    /// Token name.
    pub name: String,
    /// Project ID this token is for.
    pub project_id: String,
    /// Project name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    /// Permissions granted to this token.
    pub permissions: Vec<String>,
    /// When the token expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
}

/// Response containing current user or service token information.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CurrentUserResponse {
    /// Type of authentication ("user" or "service_token").
    #[serde(rename = "type")]
    pub auth_type: String,
    /// User information (if authenticated as user).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    /// Service token information (if authenticated as service token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_token: Option<ServiceToken>,
}

// Internal API response types
#[derive(Debug, Deserialize)]
pub(crate) struct ProjectsResponse {
    pub projects: Vec<Project>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EnvironmentsResponse {
    pub environments: Vec<Environment>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SecretsResponse {
    pub secrets: Vec<SecretWithInheritance>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SecretsExportResponse {
    pub secrets: Vec<SecretWithValueAndInheritance>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PermissionsResponse {
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DefaultsResponse {
    pub defaults: Vec<DefaultPermission>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HistoryResponse {
    pub history: Vec<SecretHistory>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApiErrorResponse {
    pub error: Option<String>,
    pub message: Option<String>,
    pub code: Option<String>,
}
