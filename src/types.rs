//! Type definitions for the KeyEnv SDK.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A KeyEnv user.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    /// User ID.
    pub id: String,
    /// Clerk user ID (if user auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clerk_id: Option<String>,
    /// User email address (optional for service tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// User's name (optional, not always returned by API).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// URL to user's avatar image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// When the user was created.
    pub created_at: DateTime<Utc>,
    /// Teams the user belongs to (for user auth).
    #[serde(default)]
    pub teams: Vec<TeamMembership>,
}

/// A KeyEnv project.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Project {
    /// Project ID.
    pub id: String,
    /// Project name.
    pub name: String,
    /// Project slug (URL-friendly identifier).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    /// Project description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Team ID that owns this project.
    pub team_id: String,
    /// When the project was created.
    pub created_at: DateTime<Utc>,
    /// When the project was last updated (optional, not always returned by API).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
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
    /// Environment description (optional, not always returned by API).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Project ID this environment belongs to.
    pub project_id: String,
    /// ID/name of environment this one inherits from.
    #[serde(skip_serializing_if = "Option::is_none", alias = "inherits_from_id")]
    pub inherits_from: Option<String>,
    /// Display order (optional, not always returned by API).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<i32>,
    /// When the environment was created.
    pub created_at: DateTime<Utc>,
    /// When the environment was last updated (optional, not always returned by API).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
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
    /// Type of secret (detected automatically). API returns this as "type".
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
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
    /// Type of secret. API returns this as "type".
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
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
    /// Type of secret. API returns this as "type".
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
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
    /// Type of secret. API returns this as "type".
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
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
    /// Secret key (optional, not always returned by API).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Version number.
    pub version: i32,
    /// User ID who made the change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_by: Option<String>,
    /// Type of change (optional, not always returned by API).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_type: Option<String>,
    /// When the change was made (API returns as changed_at or created_at).
    #[serde(alias = "created_at")]
    pub changed_at: DateTime<Utc>,
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
    /// When the team was last updated (optional, not always returned by API).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// A team membership.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeamMembership {
    /// Team ID.
    pub team_id: String,
    /// User ID.
    pub user_id: String,
    /// Role in the team.
    pub role: String,
    /// When the membership was created.
    pub created_at: DateTime<Utc>,
    /// Team details (optional, populated in some queries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<Team>,
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
/// This is a flat structure that contains fields for both user and service token auth.
/// For user auth: id, clerk_id, email, created_at, teams are populated.
/// For service token auth: id, team_id, project_ids, scopes, auth_type are populated.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CurrentUserResponse {
    /// User/Token ID.
    pub id: String,
    /// Type of authentication ("service_token" for service tokens, absent for user auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    /// Clerk user ID (for user auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clerk_id: Option<String>,
    /// User email address (for user auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// When the user/token was created (optional for service tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    /// Teams the user belongs to (for user auth).
    #[serde(default)]
    pub teams: Vec<TeamMembership>,
    /// Team ID (for service token auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Project IDs (for service token auth).
    #[serde(default)]
    pub project_ids: Vec<String>,
    /// Scopes (for service token auth).
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl CurrentUserResponse {
    /// Check if this is a service token authentication.
    pub fn is_service_token(&self) -> bool {
        self.auth_type.as_deref() == Some("service_token")
    }

    /// Check if this is a user authentication.
    pub fn is_user(&self) -> bool {
        !self.is_service_token()
    }
}

// Internal API response types
#[derive(Debug, Deserialize)]
pub(crate) struct DataResponse<T> {
    pub data: T,
}

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
pub(crate) struct SecretResponse {
    pub secret: SecretWithValueAndInheritance,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApiErrorResponse {
    pub error: Option<String>,
    pub message: Option<String>,
    pub code: Option<String>,
}
