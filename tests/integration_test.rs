//! Integration tests for the KeyEnv Rust SDK.
//!
//! These tests run against a live test API and are skipped if the required
//! environment variables are not set.
//!
//! Required environment variables:
//! - KEYENV_API_URL: API base URL (e.g., http://localhost:8081/api/v1)
//! - KEYENV_TOKEN: Service token for authentication
//! - KEYENV_PROJECT: Project slug (optional, defaults to "sdk-test")
//!
//! Run with:
//! ```bash
//! KEYENV_API_URL=http://localhost:8081/api/v1 \
//! KEYENV_TOKEN=env_test_integration_token_12345 \
//! cargo test --test integration_test -- --nocapture
//! ```

use keyenv::{BulkImportOptions, KeyEnv, SecretInput};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

/// Check if integration tests should run.
/// Returns None if tests should be skipped, Some(config) otherwise.
fn get_test_config() -> Option<TestConfig> {
    let api_url = env::var("KEYENV_API_URL").ok()?;
    let token = env::var("KEYENV_TOKEN").ok()?;
    let project = env::var("KEYENV_PROJECT").unwrap_or_else(|_| "sdk-test".to_string());

    Some(TestConfig {
        api_url,
        token,
        project,
    })
}

struct TestConfig {
    api_url: String,
    token: String,
    project: String,
}

impl TestConfig {
    fn create_client(&self) -> KeyEnv {
        KeyEnv::builder()
            .token(&self.token)
            .base_url(&self.api_url)
            .build()
            .expect("Failed to create client")
    }
}

/// Generate a unique key name using timestamp to avoid conflicts.
fn unique_key(prefix: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("{}_{}", prefix, timestamp)
}

// ============================================================================
// Token Validation Tests
// ============================================================================

#[tokio::test]
async fn test_validate_token() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let result = client.validate_token().await;

    assert!(result.is_ok(), "Token validation failed: {:?}", result.err());

    let user_info = result.unwrap();
    assert!(user_info.is_service_token(), "Expected service token auth");
    assert_eq!(user_info.auth_type, Some("service_token".to_string()));
    println!("Authenticated as service token ID: {}", user_info.id);
}

#[tokio::test]
async fn test_invalid_token() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = KeyEnv::builder()
        .token("invalid_token_12345")
        .base_url(&config.api_url)
        .build()
        .expect("Failed to create client");

    let result = client.validate_token().await;

    assert!(result.is_err());
    if let Err(ref e) = result {
        assert!(e.is_unauthorized(), "Expected 401 error, got: {:?}", e);
    }
}

// ============================================================================
// Project Tests
// ============================================================================

#[tokio::test]
async fn test_list_projects() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let result = client.list_projects().await;

    assert!(result.is_ok(), "List projects failed: {:?}", result.err());

    let projects = result.unwrap();
    println!("Found {} projects", projects.len());

    // Should have at least one project (the test project)
    assert!(!projects.is_empty(), "Expected at least one project");

    // Find our test project by slug
    let test_project = projects.iter().find(|p| p.slug.as_deref() == Some(&config.project));
    assert!(
        test_project.is_some(),
        "Test project with slug '{}' not found",
        config.project
    );
}

#[tokio::test]
async fn test_get_project() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let result = client.get_project(&config.project).await;

    assert!(result.is_ok(), "Get project failed: {:?}", result.err());

    let project = result.unwrap();
    // config.project is the slug, project.name is the display name
    assert_eq!(project.slug.as_deref(), Some(config.project.as_str()));
    println!("Project: {} (slug: {:?}, ID: {})", project.name, project.slug, project.id);
    println!("Environments: {:?}", project.environments.len());
}

#[tokio::test]
async fn test_get_nonexistent_project() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let result = client.get_project("nonexistent-project-12345").await;

    assert!(result.is_err());
    if let Err(ref e) = result {
        assert!(e.is_not_found(), "Expected 404 error, got: {:?}", e);
    }
}

// ============================================================================
// Environment Tests
// ============================================================================

#[tokio::test]
async fn test_list_environments() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let result = client.list_environments(&config.project).await;

    assert!(
        result.is_ok(),
        "List environments failed: {:?}",
        result.err()
    );

    let environments = result.unwrap();
    println!("Found {} environments", environments.len());

    // Should have the standard environments
    let env_names: Vec<&str> = environments.iter().map(|e| e.name.as_str()).collect();
    assert!(
        env_names.contains(&"development"),
        "Expected 'development' environment"
    );

    for env in &environments {
        println!("  - {} (order: {:?})", env.name, env.order);
    }
}

// ============================================================================
// Secret CRUD Tests
// ============================================================================

#[tokio::test]
async fn test_export_secrets() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let result = client.export_secrets(&config.project, "development").await;

    assert!(result.is_ok(), "Export secrets failed: {:?}", result.err());

    let secrets = result.unwrap();
    println!("Exported {} secrets from development", secrets.len());

    for secret in &secrets {
        // Don't print actual values in tests
        println!(
            "  - {} (inherited: {:?})",
            secret.key, secret.inherited_from
        );
    }
}

#[tokio::test]
async fn test_export_secrets_as_map() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let result = client
        .export_secrets_as_map(&config.project, "development")
        .await;

    assert!(
        result.is_ok(),
        "Export secrets as map failed: {:?}",
        result.err()
    );

    let secrets_map = result.unwrap();
    println!("Got {} secrets as HashMap", secrets_map.len());
}

#[tokio::test]
async fn test_list_secrets() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let result = client.list_secrets(&config.project, "development").await;

    assert!(result.is_ok(), "List secrets failed: {:?}", result.err());

    let secrets = result.unwrap();
    println!("Listed {} secrets (without values)", secrets.len());
}

#[tokio::test]
async fn test_create_get_update_delete_secret() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let key = unique_key("RUST_SDK_TEST");
    let initial_value = "initial_value_12345";
    let updated_value = "updated_value_67890";

    // Create secret
    println!("Creating secret: {}", key);
    let create_result = client
        .set_secret(&config.project, "development", &key, initial_value)
        .await;
    assert!(
        create_result.is_ok(),
        "Create secret failed: {:?}",
        create_result.err()
    );

    // Get secret and verify value
    println!("Getting secret: {}", key);
    let get_result = client
        .get_secret(&config.project, "development", &key)
        .await;
    assert!(
        get_result.is_ok(),
        "Get secret failed: {:?}",
        get_result.err()
    );
    let secret = get_result.unwrap();
    assert_eq!(secret.key, key);
    assert_eq!(secret.value, initial_value);
    println!("Secret version: {}", secret.version);

    // Update secret
    println!("Updating secret: {}", key);
    let update_result = client
        .set_secret(&config.project, "development", &key, updated_value)
        .await;
    assert!(
        update_result.is_ok(),
        "Update secret failed: {:?}",
        update_result.err()
    );

    // Verify update
    let get_updated = client
        .get_secret(&config.project, "development", &key)
        .await
        .unwrap();
    assert_eq!(get_updated.value, updated_value);
    assert!(
        get_updated.version > secret.version,
        "Version should increment after update"
    );
    println!("Updated version: {}", get_updated.version);

    // Delete secret
    println!("Deleting secret: {}", key);
    let delete_result = client
        .delete_secret(&config.project, "development", &key)
        .await;
    assert!(
        delete_result.is_ok(),
        "Delete secret failed: {:?}",
        delete_result.err()
    );

    // Verify deletion
    let get_deleted = client
        .get_secret(&config.project, "development", &key)
        .await;
    assert!(
        get_deleted.is_err(),
        "Secret should not exist after deletion"
    );
    if let Err(ref e) = get_deleted {
        assert!(e.is_not_found(), "Expected 404, got: {:?}", e);
    }

    println!("CRUD test completed successfully");
}

#[tokio::test]
async fn test_set_secret_with_description() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let key = unique_key("RUST_SDK_DESC_TEST");
    let value = "test_value";
    let description = "Test secret created by Rust SDK integration test";

    // Create secret with description
    let create_result = client
        .set_secret_with_description(
            &config.project,
            "development",
            &key,
            value,
            Some(description),
        )
        .await;
    assert!(
        create_result.is_ok(),
        "Create secret with description failed: {:?}",
        create_result.err()
    );

    // Get and verify
    let secret = client
        .get_secret(&config.project, "development", &key)
        .await
        .unwrap();
    assert_eq!(secret.key, key);
    assert_eq!(secret.value, value);
    // Note: description may not be returned in get_secret depending on API version

    // Cleanup
    let _ = client
        .delete_secret(&config.project, "development", &key)
        .await;
    println!("Secret with description test completed");
}

#[tokio::test]
async fn test_get_nonexistent_secret() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let result = client
        .get_secret(
            &config.project,
            "development",
            "NONEXISTENT_SECRET_KEY_12345",
        )
        .await;

    assert!(result.is_err());
    if let Err(ref e) = result {
        assert!(e.is_not_found(), "Expected 404 error, got: {:?}", e);
    }
}

// ============================================================================
// Bulk Import Tests
// ============================================================================

#[tokio::test]
async fn test_bulk_import() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let prefix = unique_key("BULK");
    let key1 = format!("{}_VAR1", prefix);
    let key2 = format!("{}_VAR2", prefix);
    let key3 = format!("{}_VAR3", prefix);

    let secrets = vec![
        SecretInput::new(&key1, "bulk_value_1"),
        SecretInput::new(&key2, "bulk_value_2"),
        SecretInput::with_description(&key3, "bulk_value_3", "Bulk imported secret"),
    ];

    // Import secrets
    println!("Bulk importing {} secrets", secrets.len());
    let result = client
        .bulk_import(
            &config.project,
            "development",
            secrets,
            BulkImportOptions { overwrite: true },
        )
        .await;

    assert!(result.is_ok(), "Bulk import failed: {:?}", result.err());

    let import_result = result.unwrap();
    println!(
        "Bulk import result: created={}, updated={}, skipped={}",
        import_result.created, import_result.updated, import_result.skipped
    );

    // Verify secrets were created
    let exported = client
        .export_secrets_as_map(&config.project, "development")
        .await
        .unwrap();
    assert_eq!(exported.get(&key1).map(|s| s.as_str()), Some("bulk_value_1"));
    assert_eq!(exported.get(&key2).map(|s| s.as_str()), Some("bulk_value_2"));
    assert_eq!(exported.get(&key3).map(|s| s.as_str()), Some("bulk_value_3"));

    // Cleanup
    let _ = client
        .delete_secret(&config.project, "development", &key1)
        .await;
    let _ = client
        .delete_secret(&config.project, "development", &key2)
        .await;
    let _ = client
        .delete_secret(&config.project, "development", &key3)
        .await;

    println!("Bulk import test completed");
}

#[tokio::test]
async fn test_bulk_import_with_overwrite() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let key = unique_key("BULK_OVERWRITE");

    // Create initial secret
    client
        .set_secret(&config.project, "development", &key, "original_value")
        .await
        .unwrap();

    // Bulk import with overwrite=true should update it
    let result = client
        .bulk_import(
            &config.project,
            "development",
            vec![SecretInput::new(&key, "overwritten_value")],
            BulkImportOptions { overwrite: true },
        )
        .await
        .unwrap();

    assert_eq!(result.updated, 1);

    // Verify value was updated
    let secret = client
        .get_secret(&config.project, "development", &key)
        .await
        .unwrap();
    assert_eq!(secret.value, "overwritten_value");

    // Cleanup
    let _ = client
        .delete_secret(&config.project, "development", &key)
        .await;

    println!("Bulk import with overwrite test completed");
}

// ============================================================================
// Environment Variable Loading Tests
// ============================================================================

#[tokio::test]
async fn test_load_env() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let key = unique_key("LOAD_ENV_TEST");
    let value = "test_env_value_12345";

    // Create a test secret
    client
        .set_secret(&config.project, "development", &key, value)
        .await
        .unwrap();

    // Load secrets into environment
    let count = client.load_env(&config.project, "development").await.unwrap();
    println!("Loaded {} secrets into environment", count);
    assert!(count > 0);

    // Verify the secret was loaded
    let env_value = env::var(&key);
    assert!(
        env_value.is_ok(),
        "Expected {} to be set in environment",
        key
    );
    assert_eq!(env_value.unwrap(), value);

    // Cleanup
    env::remove_var(&key);
    let _ = client
        .delete_secret(&config.project, "development", &key)
        .await;

    println!("Load env test completed");
}

// ============================================================================
// Env File Generation Tests
// ============================================================================

#[tokio::test]
async fn test_generate_env_file() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let key1 = unique_key("ENV_FILE_SIMPLE");
    let key2 = unique_key("ENV_FILE_SPACES");
    let key3 = unique_key("ENV_FILE_QUOTES");

    // Create test secrets with various formats
    client
        .set_secret(&config.project, "development", &key1, "simple_value")
        .await
        .unwrap();
    client
        .set_secret(&config.project, "development", &key2, "value with spaces")
        .await
        .unwrap();
    client
        .set_secret(
            &config.project,
            "development",
            &key3,
            "value with \"quotes\"",
        )
        .await
        .unwrap();

    // Generate env file content
    let content = client
        .generate_env_file(&config.project, "development")
        .await
        .unwrap();

    println!("Generated .env content:");
    println!("{}", content);

    // Verify content format
    assert!(content.contains(&format!("{}=simple_value\n", key1)));
    assert!(content.contains(&format!("{}=\"value with spaces\"\n", key2)));
    assert!(content.contains(&format!("{}=\"value with \\\"quotes\\\"\"\n", key3)));

    // Cleanup
    let _ = client
        .delete_secret(&config.project, "development", &key1)
        .await;
    let _ = client
        .delete_secret(&config.project, "development", &key2)
        .await;
    let _ = client
        .delete_secret(&config.project, "development", &key3)
        .await;

    println!("Generate env file test completed");
}

// ============================================================================
// Secret History Tests
// ============================================================================

#[tokio::test]
async fn test_get_secret_history() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let key = unique_key("HISTORY_TEST");

    // Create and update secret to generate history
    client
        .set_secret(&config.project, "development", &key, "v1")
        .await
        .unwrap();
    client
        .set_secret(&config.project, "development", &key, "v2")
        .await
        .unwrap();
    client
        .set_secret(&config.project, "development", &key, "v3")
        .await
        .unwrap();

    // Get history
    let result = client
        .get_secret_history(&config.project, "development", &key)
        .await;

    assert!(result.is_ok(), "Get secret history failed: {:?}", result.err());

    let history = result.unwrap();
    println!("Found {} history entries for {}", history.len(), key);
    // API returns history of previous versions (v1, v2), not the current version
    assert!(history.len() >= 2, "Expected at least 2 history entries");

    for entry in &history {
        println!(
            "  Version {}: {:?} at {}",
            entry.version, entry.change_type, entry.changed_at
        );
    }

    // Cleanup
    let _ = client
        .delete_secret(&config.project, "development", &key)
        .await;

    println!("Secret history test completed");
}

// ============================================================================
// Multi-Environment Tests
// ============================================================================

#[tokio::test]
async fn test_multiple_environments() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();
    let key = unique_key("MULTI_ENV_TEST");

    // Set different values in different environments
    client
        .set_secret(&config.project, "development", &key, "dev_value")
        .await
        .unwrap();
    client
        .set_secret(&config.project, "staging", &key, "staging_value")
        .await
        .unwrap();

    // Verify values are different per environment
    let dev_secret = client
        .get_secret(&config.project, "development", &key)
        .await
        .unwrap();
    let staging_secret = client
        .get_secret(&config.project, "staging", &key)
        .await
        .unwrap();

    assert_eq!(dev_secret.value, "dev_value");
    assert_eq!(staging_secret.value, "staging_value");
    assert_ne!(dev_secret.environment_id, staging_secret.environment_id);

    println!("Development value: {}", dev_secret.value);
    println!("Staging value: {}", staging_secret.value);

    // Cleanup
    let _ = client
        .delete_secret(&config.project, "development", &key)
        .await;
    let _ = client
        .delete_secret(&config.project, "staging", &key)
        .await;

    println!("Multi-environment test completed");
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_error_types() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    // Test 401 - Unauthorized
    let bad_client = KeyEnv::builder()
        .token("bad_token")
        .base_url(&config.api_url)
        .build()
        .unwrap();
    let result = bad_client.list_projects().await;
    assert!(result.is_err());
    if let Err(ref e) = result {
        assert!(e.is_unauthorized());
    }

    // Test 404 - Not Found
    let client = config.create_client();
    let result = client
        .get_secret(&config.project, "development", "DEFINITELY_NOT_EXISTS_12345")
        .await;
    assert!(result.is_err());
    if let Err(ref e) = result {
        assert!(e.is_not_found());
    }

    println!("Error types test completed");
}

// ============================================================================
// Cache Tests
// ============================================================================

#[tokio::test]
async fn test_cache_invalidation_on_mutation() {
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = KeyEnv::builder()
        .token(&config.token)
        .base_url(&config.api_url)
        .cache_ttl(std::time::Duration::from_secs(300))
        .build()
        .unwrap();

    let key = unique_key("CACHE_TEST");

    // Create secret
    client
        .set_secret(&config.project, "development", &key, "cache_value_1")
        .await
        .unwrap();

    // Export secrets (this will cache the result)
    let secrets1 = client
        .export_secrets_as_map(&config.project, "development")
        .await
        .unwrap();
    assert_eq!(
        secrets1.get(&key).map(|s| s.as_str()),
        Some("cache_value_1")
    );

    // Update secret (this should invalidate cache)
    client
        .set_secret(&config.project, "development", &key, "cache_value_2")
        .await
        .unwrap();

    // Export again - should get fresh data due to cache invalidation
    let secrets2 = client
        .export_secrets_as_map(&config.project, "development")
        .await
        .unwrap();
    assert_eq!(
        secrets2.get(&key).map(|s| s.as_str()),
        Some("cache_value_2")
    );

    // Cleanup
    let _ = client
        .delete_secret(&config.project, "development", &key)
        .await;

    println!("Cache invalidation test completed");
}

// ============================================================================
// Comprehensive Cleanup Test (run last)
// ============================================================================

#[tokio::test]
async fn test_zz_cleanup_test_secrets() {
    // Named with zz_ prefix to run last alphabetically
    let Some(config) = get_test_config() else {
        println!("Skipping: KEYENV_API_URL or KEYENV_TOKEN not set");
        return;
    };

    let client = config.create_client();

    // List all secrets and clean up any test keys that might have been left behind
    let secrets = client
        .list_secrets(&config.project, "development")
        .await
        .unwrap_or_default();

    let test_prefixes = [
        "RUST_SDK_TEST_",
        "RUST_SDK_DESC_TEST_",
        "BULK_",
        "BULK_OVERWRITE_",
        "LOAD_ENV_TEST_",
        "ENV_FILE_",
        "HISTORY_TEST_",
        "MULTI_ENV_TEST_",
        "CACHE_TEST_",
    ];

    let mut cleaned = 0;
    for secret in secrets {
        if test_prefixes.iter().any(|p| secret.key.starts_with(p)) {
            if let Ok(()) = client
                .delete_secret(&config.project, "development", &secret.key)
                .await
            {
                println!("Cleaned up leftover test secret: {}", secret.key);
                cleaned += 1;
            }
        }
    }

    // Also check staging environment
    let staging_secrets = client
        .list_secrets(&config.project, "staging")
        .await
        .unwrap_or_default();

    for secret in staging_secrets {
        if test_prefixes.iter().any(|p| secret.key.starts_with(p)) {
            if let Ok(()) = client
                .delete_secret(&config.project, "staging", &secret.key)
                .await
            {
                println!("Cleaned up leftover staging secret: {}", secret.key);
                cleaned += 1;
            }
        }
    }

    if cleaned > 0 {
        println!("Cleaned up {} leftover test secrets", cleaned);
    } else {
        println!("No leftover test secrets to clean up");
    }
}
