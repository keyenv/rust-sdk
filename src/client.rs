//! KeyEnv client implementation.

use crate::error::{Error, Result};
use crate::types::*;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.keyenv.dev";

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// SDK version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// API version prefix for all requests.
const API_PREFIX: &str = "/api/v1";

/// Builder for creating a KeyEnv client.
#[derive(Debug, Clone)]
pub struct KeyEnvBuilder {
    token: Option<String>,
    base_url: String,
    timeout: Duration,
    cache_ttl: Duration,
}

impl Default for KeyEnvBuilder {
    fn default() -> Self {
        Self {
            token: None,
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout: DEFAULT_TIMEOUT,
            cache_ttl: Duration::ZERO,
        }
    }
}

impl KeyEnvBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the authentication token (required).
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Set the API base URL (optional).
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        let u = url.into();
        self.base_url = u.trim_end_matches('/').trim_end_matches("/api/v1").to_string();
        self
    }

    /// Set the request timeout (optional, default 30s).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the cache TTL (optional, 0 disables caching).
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Build the KeyEnv client.
    pub fn build(self) -> Result<KeyEnv> {
        let token = self
            .token
            .ok_or_else(|| Error::config("token is required"))?;

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token))
                .map_err(|_| Error::config("invalid token"))?,
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&format!("keyenv-rust/{}", VERSION))
                .unwrap_or_else(|_| HeaderValue::from_static("keyenv-rust")),
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(self.timeout)
            .build()?;

        Ok(KeyEnv {
            client,
            base_url: self.base_url,
            cache_ttl: self.cache_ttl,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

/// Cache entry with expiration.
struct CacheEntry {
    data: String, // JSON serialized
    expires_at: Instant,
}

/// KeyEnv API client.
#[derive(Clone)]
pub struct KeyEnv {
    client: reqwest::Client,
    base_url: String,
    cache_ttl: Duration,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl KeyEnv {
    /// Create a new builder for the KeyEnv client.
    pub fn builder() -> KeyEnvBuilder {
        KeyEnvBuilder::new()
    }

    /// Get from cache if available and not expired.
    async fn get_cached<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        if self.cache_ttl.is_zero() {
            return None;
        }

        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(key) {
            if Instant::now() < entry.expires_at {
                return serde_json::from_str(&entry.data).ok();
            }
        }
        // Drop the read lock before acquiring write lock for cleanup
        drop(cache);

        // Lazy cleanup: remove the expired entry
        let mut cache = self.cache.write().await;
        if let Some(entry) = cache.get(key) {
            if Instant::now() >= entry.expires_at {
                cache.remove(key);
            }
        }
        None
    }

    /// Store in cache, pruning expired entries.
    async fn set_cached<T: serde::Serialize>(&self, key: &str, data: &T) {
        if self.cache_ttl.is_zero() {
            return;
        }

        if let Ok(json) = serde_json::to_string(data) {
            let mut cache = self.cache.write().await;
            let now = Instant::now();

            // Prune expired entries to prevent memory leaks
            cache.retain(|_, entry| now < entry.expires_at);

            cache.insert(
                key.to_string(),
                CacheEntry {
                    data: json,
                    expires_at: now + self.cache_ttl,
                },
            );
        }
    }

    /// Clear cache for a specific project/environment.
    pub async fn clear_cache(&self, project_id: Option<&str>, environment: Option<&str>) {
        let mut cache = self.cache.write().await;

        match (project_id, environment) {
            (Some(pid), Some(env)) => {
                let prefix = format!("secrets:{}:{}", pid, env);
                cache.retain(|k, _| !k.starts_with(&prefix));
            }
            (Some(pid), None) => {
                let prefix = format!("secrets:{}:", pid);
                cache.retain(|k, _| !k.starts_with(&prefix));
            }
            _ => {
                cache.clear();
            }
        }
    }

    /// Clear all cached data.
    pub async fn clear_all_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Make a GET request.
    async fn get(&self, path: &str) -> Result<String> {
        let url = format!("{}{}{}", self.base_url, API_PREFIX, path);
        let response = self.client.get(&url).send().await?;
        self.handle_response(response).await
    }

    /// Make a POST request.
    async fn post<T: serde::Serialize>(&self, path: &str, body: &T) -> Result<String> {
        let url = format!("{}{}{}", self.base_url, API_PREFIX, path);
        let response = self.client.post(&url).json(body).send().await?;
        self.handle_response(response).await
    }

    /// Make a PUT request.
    async fn put<T: serde::Serialize>(&self, path: &str, body: &T) -> Result<String> {
        let url = format!("{}{}{}", self.base_url, API_PREFIX, path);
        let response = self.client.put(&url).json(body).send().await?;
        self.handle_response(response).await
    }

    /// Make a DELETE request.
    async fn delete(&self, path: &str) -> Result<String> {
        let url = format!("{}{}{}", self.base_url, API_PREFIX, path);
        let response = self.client.delete(&url).send().await?;
        self.handle_response(response).await
    }

    /// Handle API response.
    async fn handle_response(&self, response: reqwest::Response) -> Result<String> {
        let status = response.status();
        let body = response.text().await?;

        if status.is_success() {
            return Ok(body);
        }

        // Try to parse error response
        if let Ok(error_resp) = serde_json::from_str::<ApiErrorResponse>(&body) {
            let message = error_resp.error.or(error_resp.message).unwrap_or_else(|| {
                status
                    .canonical_reason()
                    .unwrap_or("Unknown error")
                    .to_string()
            });

            return Err(match error_resp.code {
                Some(code) => Error::api_with_code(status.as_u16(), message, code),
                None => Error::api(status.as_u16(), message),
            });
        }

        Err(Error::api(
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown error"),
        ))
    }

    /// Get current user or service token information.
    pub async fn get_current_user(&self) -> Result<CurrentUserResponse> {
        let body = self.get("/users/me").await?;
        let envelope: DataResponse<CurrentUserResponse> = serde_json::from_str(&body)?;
        Ok(envelope.data)
    }

    /// Validate the token and return user info.
    pub async fn validate_token(&self) -> Result<CurrentUserResponse> {
        self.get_current_user().await
    }

    /// List all accessible projects.
    pub async fn list_projects(&self) -> Result<Vec<Project>> {
        let body = self.get("/projects").await?;
        let resp: ProjectsResponse = serde_json::from_str(&body)?;
        Ok(resp.projects)
    }

    /// Get a project by ID.
    pub async fn get_project(&self, project_id: &str) -> Result<Project> {
        let body = self.get(&format!("/projects/{}", project_id)).await?;
        let envelope: DataResponse<Project> = serde_json::from_str(&body)?;
        Ok(envelope.data)
    }

    /// Create a new project.
    pub async fn create_project(&self, team_id: &str, name: &str) -> Result<Project> {
        let body = serde_json::json!({
            "team_id": team_id,
            "name": name,
        });
        let resp = self.post("/projects", &body).await?;
        let envelope: DataResponse<Project> = serde_json::from_str(&resp)?;
        Ok(envelope.data)
    }

    /// Delete a project.
    pub async fn delete_project(&self, project_id: &str) -> Result<()> {
        self.delete(&format!("/projects/{}", project_id)).await?;
        Ok(())
    }

    /// List environments in a project.
    pub async fn list_environments(&self, project_id: &str) -> Result<Vec<Environment>> {
        let body = self
            .get(&format!("/projects/{}/environments", project_id))
            .await?;
        let resp: EnvironmentsResponse = serde_json::from_str(&body)?;
        Ok(resp.environments)
    }

    /// Create a new environment in a project.
    pub async fn create_environment(
        &self,
        project_id: &str,
        name: &str,
        inherits_from: Option<&str>,
    ) -> Result<Environment> {
        let mut body = serde_json::json!({
            "name": name,
        });
        if let Some(inherits) = inherits_from {
            body["inherits_from"] = serde_json::Value::String(inherits.to_string());
        }
        let path = format!("/projects/{}/environments", project_id);
        let resp = self.post(&path, &body).await?;
        let envelope: DataResponse<Environment> = serde_json::from_str(&resp)?;
        Ok(envelope.data)
    }

    /// Delete an environment from a project.
    pub async fn delete_environment(&self, project_id: &str, environment: &str) -> Result<()> {
        self.delete(&format!(
            "/projects/{}/environments/{}",
            project_id, environment
        ))
        .await?;
        Ok(())
    }

    /// List secrets (without values) in an environment.
    pub async fn list_secrets(
        &self,
        project_id: &str,
        environment: &str,
    ) -> Result<Vec<SecretWithInheritance>> {
        let body = self
            .get(&format!(
                "/projects/{}/environments/{}/secrets",
                project_id, environment
            ))
            .await?;
        let resp: SecretsResponse = serde_json::from_str(&body)?;
        Ok(resp.secrets)
    }

    /// Export secrets with values from an environment.
    pub async fn export_secrets(
        &self,
        project_id: &str,
        environment: &str,
    ) -> Result<Vec<SecretWithValueAndInheritance>> {
        let cache_key = format!("secrets:{}:{}:export", project_id, environment);

        // Check cache
        if let Some(cached) = self.get_cached(&cache_key).await {
            return Ok(cached);
        }

        let body = self
            .get(&format!(
                "/projects/{}/environments/{}/secrets/export",
                project_id, environment
            ))
            .await?;
        let resp: SecretsExportResponse = serde_json::from_str(&body)?;

        // Store in cache
        self.set_cached(&cache_key, &resp.secrets).await;

        Ok(resp.secrets)
    }

    /// Export secrets as a HashMap.
    pub async fn export_secrets_as_map(
        &self,
        project_id: &str,
        environment: &str,
    ) -> Result<HashMap<String, String>> {
        let secrets = self.export_secrets(project_id, environment).await?;
        Ok(secrets.into_iter().map(|s| (s.key, s.value)).collect())
    }

    /// Get a single secret by key.
    pub async fn get_secret(
        &self,
        project_id: &str,
        environment: &str,
        key: &str,
    ) -> Result<SecretWithValueAndInheritance> {
        let body = self
            .get(&format!(
                "/projects/{}/environments/{}/secrets/{}",
                project_id, environment, key
            ))
            .await?;
        let resp: SecretResponse = serde_json::from_str(&body)?;
        Ok(resp.secret)
    }

    /// Set (create or update) a secret.
    pub async fn set_secret(
        &self,
        project_id: &str,
        environment: &str,
        key: &str,
        value: &str,
    ) -> Result<()> {
        self.set_secret_with_description(project_id, environment, key, value, None)
            .await
    }

    /// Set a secret with an optional description.
    pub async fn set_secret_with_description(
        &self,
        project_id: &str,
        environment: &str,
        key: &str,
        value: &str,
        description: Option<&str>,
    ) -> Result<()> {
        let path = format!(
            "/projects/{}/environments/{}/secrets/{}",
            project_id, environment, key
        );

        let mut body = serde_json::json!({
            "value": value,
        });
        if let Some(desc) = description {
            body["description"] = serde_json::Value::String(desc.to_string());
        }

        // Try PUT first (update), then POST (create) if not found
        match self.put(&path, &body).await {
            Ok(_) => {}
            Err(Error::Api { status: 404, .. }) => {
                // Secret doesn't exist, create it
                let create_path = format!(
                    "/projects/{}/environments/{}/secrets",
                    project_id, environment
                );
                let mut create_body = serde_json::json!({
                    "key": key,
                    "value": value,
                });
                if let Some(desc) = description {
                    create_body["description"] = serde_json::Value::String(desc.to_string());
                }
                self.post(&create_path, &create_body).await?;
            }
            Err(e) => return Err(e),
        }

        // Clear cache for this environment
        self.clear_cache(Some(project_id), Some(environment)).await;

        Ok(())
    }

    /// Delete a secret.
    pub async fn delete_secret(
        &self,
        project_id: &str,
        environment: &str,
        key: &str,
    ) -> Result<()> {
        self.delete(&format!(
            "/projects/{}/environments/{}/secrets/{}",
            project_id, environment, key
        ))
        .await?;

        // Clear cache for this environment
        self.clear_cache(Some(project_id), Some(environment)).await;

        Ok(())
    }

    /// Bulk import secrets.
    pub async fn bulk_import(
        &self,
        project_id: &str,
        environment: &str,
        secrets: Vec<SecretInput>,
        options: BulkImportOptions,
    ) -> Result<BulkImportResult> {
        let path = format!(
            "/projects/{}/environments/{}/secrets/bulk",
            project_id, environment
        );

        let body = serde_json::json!({
            "secrets": secrets,
            "overwrite": options.overwrite,
        });

        let resp_body = self.post(&path, &body).await?;
        let envelope: DataResponse<BulkImportResult> = serde_json::from_str(&resp_body)?;
        let result = envelope.data;

        // Clear cache for this environment
        self.clear_cache(Some(project_id), Some(environment)).await;

        Ok(result)
    }

    /// Load secrets into environment variables.
    /// Returns the number of secrets loaded.
    pub async fn load_env(&self, project_id: &str, environment: &str) -> Result<usize> {
        let secrets = self.export_secrets(project_id, environment).await?;

        for secret in &secrets {
            std::env::set_var(&secret.key, &secret.value);
        }

        Ok(secrets.len())
    }

    /// Generate .env file content.
    pub async fn generate_env_file(&self, project_id: &str, environment: &str) -> Result<String> {
        let secrets = self.export_secrets(project_id, environment).await?;
        let mut content = String::new();

        for secret in secrets {
            let value = &secret.value;
            let needs_quotes = value.contains(' ')
                || value.contains('\t')
                || value.contains('\n')
                || value.contains('"')
                || value.contains('\'')
                || value.contains('\\')
                || value.contains('$');

            if needs_quotes {
                let escaped = value
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
                    .replace('$', "\\$");
                content.push_str(&format!("{}=\"{}\"\n", secret.key, escaped));
            } else {
                content.push_str(&format!("{}={}\n", secret.key, value));
            }
        }

        Ok(content)
    }

    /// List permissions for an environment.
    pub async fn list_permissions(
        &self,
        project_id: &str,
        environment: &str,
    ) -> Result<Vec<Permission>> {
        let body = self
            .get(&format!(
                "/projects/{}/environments/{}/permissions",
                project_id, environment
            ))
            .await?;
        let resp: PermissionsResponse = serde_json::from_str(&body)?;
        Ok(resp.permissions)
    }

    /// Set a user's permission for an environment.
    pub async fn set_permission(
        &self,
        project_id: &str,
        environment: &str,
        user_id: &str,
        role: &str,
    ) -> Result<()> {
        let path = format!(
            "/projects/{}/environments/{}/permissions/{}",
            project_id, environment, user_id
        );
        let body = serde_json::json!({ "role": role });
        self.put(&path, &body).await?;
        Ok(())
    }

    /// Delete a user's permission for an environment.
    pub async fn delete_permission(
        &self,
        project_id: &str,
        environment: &str,
        user_id: &str,
    ) -> Result<()> {
        self.delete(&format!(
            "/projects/{}/environments/{}/permissions/{}",
            project_id, environment, user_id
        ))
        .await?;
        Ok(())
    }

    /// Bulk set permissions.
    pub async fn bulk_set_permissions(
        &self,
        project_id: &str,
        environment: &str,
        permissions: Vec<PermissionInput>,
    ) -> Result<()> {
        let path = format!(
            "/projects/{}/environments/{}/permissions",
            project_id, environment
        );
        let body = serde_json::json!({ "permissions": permissions });
        self.put(&path, &body).await?;
        Ok(())
    }

    /// Get the current user's permissions for a project.
    pub async fn get_my_permissions(&self, project_id: &str) -> Result<MyPermissionsResponse> {
        let body = self
            .get(&format!("/projects/{}/my-permissions", project_id))
            .await?;
        Ok(serde_json::from_str(&body)?)
    }

    /// Get default permissions for a project.
    pub async fn get_project_defaults(&self, project_id: &str) -> Result<Vec<DefaultPermission>> {
        let body = self
            .get(&format!("/projects/{}/permissions/defaults", project_id))
            .await?;
        let resp: DefaultsResponse = serde_json::from_str(&body)?;
        Ok(resp.defaults)
    }

    /// Set default permissions for a project.
    pub async fn set_project_defaults(
        &self,
        project_id: &str,
        defaults: Vec<DefaultPermission>,
    ) -> Result<()> {
        let path = format!("/projects/{}/permissions/defaults", project_id);
        let body = serde_json::json!({ "defaults": defaults });
        self.put(&path, &body).await?;
        Ok(())
    }

    /// Get the version history of a secret.
    pub async fn get_secret_history(
        &self,
        project_id: &str,
        environment: &str,
        key: &str,
    ) -> Result<Vec<SecretHistory>> {
        let body = self
            .get(&format!(
                "/projects/{}/environments/{}/secrets/{}/history",
                project_id, environment, key
            ))
            .await?;
        let resp: HistoryResponse = serde_json::from_str(&body)?;
        Ok(resp.history)
    }
}
