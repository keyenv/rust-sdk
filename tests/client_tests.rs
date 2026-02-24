use keyenv::{BulkImportOptions, Error, KeyEnv, SecretInput};
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup_mock_server() -> MockServer {
    MockServer::start().await
}

fn create_test_client(base_url: &str) -> KeyEnv {
    KeyEnv::builder()
        .token("test-token")
        .base_url(base_url)
        .build()
        .unwrap()
}

#[tokio::test]
async fn test_builder_requires_token() {
    let result = KeyEnv::builder().build();
    assert!(result.is_err());
    if let Err(Error::Config(msg)) = result {
        assert!(msg.contains("token is required"));
    }
}

#[tokio::test]
async fn test_builder_with_all_options() {
    let client = KeyEnv::builder()
        .token("test-token")
        .base_url("https://custom.api.com")
        .timeout(Duration::from_secs(60))
        .cache_ttl(Duration::from_secs(300))
        .build();

    assert!(client.is_ok());
}

#[tokio::test]
async fn test_list_projects() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "proj-1", "name": "Project 1", "team_id": "team-1", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
                {"id": "proj-2", "name": "Project 2", "team_id": "team-1", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let projects = client.list_projects().await.unwrap();

    assert_eq!(projects.len(), 2);
    assert_eq!(projects[0].id, "proj-1");
    assert_eq!(projects[0].name, "Project 1");
}

#[tokio::test]
async fn test_get_project() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects/proj-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "proj-1",
                "name": "Project 1",
                "team_id": "team-1",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "environments": [
                    {"id": "env-1", "name": "development", "project_id": "proj-1", "order": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
                    {"id": "env-2", "name": "production", "project_id": "proj-1", "order": 2, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
                ]
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let project = client.get_project("proj-1").await.unwrap();

    assert_eq!(project.id, "proj-1");
    assert_eq!(project.environments.len(), 2);
}

#[tokio::test]
async fn test_export_secrets() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects/proj-1/environments/production/secrets/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "s1", "key": "DATABASE_URL", "value": "postgres://localhost/db", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
                {"id": "s2", "key": "API_KEY", "value": "sk_test_123", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let secrets = client.export_secrets("proj-1", "production").await.unwrap();

    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[0].key, "DATABASE_URL");
    assert_eq!(secrets[0].value, "postgres://localhost/db");
}

#[tokio::test]
async fn test_export_secrets_as_map() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects/proj-1/environments/production/secrets/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "s1", "key": "DATABASE_URL", "value": "postgres://localhost/db", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
                {"id": "s2", "key": "API_KEY", "value": "sk_test_123", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let secrets = client
        .export_secrets_as_map("proj-1", "production")
        .await
        .unwrap();

    assert_eq!(
        secrets.get("DATABASE_URL").unwrap(),
        "postgres://localhost/db"
    );
    assert_eq!(secrets.get("API_KEY").unwrap(), "sk_test_123");
}

#[tokio::test]
async fn test_get_secret() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path(
            "/api/v1/projects/proj-1/environments/production/secrets/DATABASE_URL",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "s1",
                "key": "DATABASE_URL",
                "value": "postgres://localhost/db",
                "environment_id": "env-1",
                "version": 1,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let secret = client
        .get_secret("proj-1", "production", "DATABASE_URL")
        .await
        .unwrap();

    assert_eq!(secret.key, "DATABASE_URL");
    assert_eq!(secret.value, "postgres://localhost/db");
}

#[tokio::test]
async fn test_set_secret() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("PUT"))
        .and(path(
            "/api/v1/projects/proj-1/environments/production/secrets/API_KEY",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "s1",
            "key": "API_KEY",
            "environment_id": "env-1",
            "version": 2,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let result = client
        .set_secret("proj-1", "production", "API_KEY", "sk_new_value")
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_secret() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("DELETE"))
        .and(path(
            "/api/v1/projects/proj-1/environments/production/secrets/OLD_KEY",
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let result = client
        .delete_secret("proj-1", "production", "OLD_KEY")
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_bulk_import() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("POST"))
        .and(path(
            "/api/v1/projects/proj-1/environments/development/secrets/bulk",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "created": 2,
                "updated": 1,
                "skipped": 0
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let result = client
        .bulk_import(
            "proj-1",
            "development",
            vec![
                SecretInput::new("VAR1", "value1"),
                SecretInput::new("VAR2", "value2"),
                SecretInput::new("VAR3", "value3"),
            ],
            BulkImportOptions { overwrite: true },
        )
        .await
        .unwrap();

    assert_eq!(result.created, 2);
    assert_eq!(result.updated, 1);
    assert_eq!(result.skipped, 0);
}

#[tokio::test]
async fn test_generate_env_file() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects/proj-1/environments/production/secrets/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "s1", "key": "SIMPLE", "value": "simple_value", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
                {"id": "s2", "key": "WITH_SPACES", "value": "value with spaces", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
                {"id": "s3", "key": "WITH_QUOTES", "value": "value \"quoted\"", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let content = client
        .generate_env_file("proj-1", "production")
        .await
        .unwrap();

    assert!(content.contains("SIMPLE=simple_value\n"));
    assert!(content.contains("WITH_SPACES=\"value with spaces\"\n"));
    assert!(content.contains("WITH_QUOTES=\"value \\\"quoted\\\"\"\n"));
}

#[tokio::test]
async fn test_error_401_unauthorized() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "Invalid token"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let result = client.list_projects().await;

    assert!(result.is_err());
    if let Err(Error::Api {
        status, message, ..
    }) = result
    {
        assert_eq!(status, 401);
        assert!(message.contains("Invalid token"));
    } else {
        panic!("Expected Api error");
    }
}

#[tokio::test]
async fn test_error_404_not_found() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "error": "Project not found"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let result = client.get_project("nonexistent").await;

    assert!(result.is_err());
    if let Err(ref e) = result {
        assert!(e.is_not_found());
    }
}

#[tokio::test]
async fn test_error_403_forbidden() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path(
            "/api/v1/projects/proj-1/environments/production/secrets/SECRET",
        ))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "Access denied"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let result = client.get_secret("proj-1", "production", "SECRET").await;

    assert!(result.is_err());
    if let Err(ref e) = result {
        assert!(e.is_forbidden());
    }
}

#[tokio::test]
async fn test_caching() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects/proj-1/environments/production/secrets/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "s1", "key": "CACHED_VAR", "value": "cached_value", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
            ]
        })))
        .expect(1) // Should only be called once due to caching
        .mount(&mock_server)
        .await;

    let client = KeyEnv::builder()
        .token("test-token")
        .base_url(&mock_server.uri())
        .cache_ttl(Duration::from_secs(300))
        .build()
        .unwrap();

    // First call - should hit the server
    let _ = client.export_secrets("proj-1", "production").await.unwrap();

    // Second call - should use cache
    let secrets = client.export_secrets("proj-1", "production").await.unwrap();
    assert_eq!(secrets[0].key, "CACHED_VAR");
}

#[tokio::test]
async fn test_cache_clearing() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects/proj-1/environments/production/secrets/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "s1", "key": "VAR", "value": "value", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
            ]
        })))
        .expect(2) // Should be called twice - before and after cache clear
        .mount(&mock_server)
        .await;

    let client = KeyEnv::builder()
        .token("test-token")
        .base_url(&mock_server.uri())
        .cache_ttl(Duration::from_secs(300))
        .build()
        .unwrap();

    // First call
    let _ = client.export_secrets("proj-1", "production").await.unwrap();

    // Clear cache
    client.clear_cache(Some("proj-1"), Some("production")).await;

    // Third call - should hit the server again
    let _ = client.export_secrets("proj-1", "production").await.unwrap();
}

#[tokio::test]
async fn test_load_env() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects/proj-1/environments/production/secrets/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "s1", "key": "TEST_RUST_VAR_1", "value": "value1", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
                {"id": "s2", "key": "TEST_RUST_VAR_2", "value": "value2", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let count = client.load_env("proj-1", "production").await.unwrap();

    assert_eq!(count, 2);
    assert_eq!(std::env::var("TEST_RUST_VAR_1").unwrap(), "value1");
    assert_eq!(std::env::var("TEST_RUST_VAR_2").unwrap(), "value2");

    // Clean up
    std::env::remove_var("TEST_RUST_VAR_1");
    std::env::remove_var("TEST_RUST_VAR_2");
}

#[tokio::test]
async fn test_secret_input_constructors() {
    let simple = SecretInput::new("KEY", "VALUE");
    assert_eq!(simple.key, "KEY");
    assert_eq!(simple.value, "VALUE");
    assert!(simple.description.is_none());

    let with_desc = SecretInput::with_description("KEY", "VALUE", "A description");
    assert_eq!(with_desc.key, "KEY");
    assert_eq!(with_desc.value, "VALUE");
    assert_eq!(with_desc.description.unwrap(), "A description");
}

#[tokio::test]
async fn test_api_v1_prefix_in_requests() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/users/me"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "user-1",
                "email": "test@test.com",
                "auth_type": "user"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let result = client.get_current_user().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_generate_env_file_dollar_escaping() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects/proj-1/environments/production/secrets/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "s1", "key": "DOLLAR_VAR", "value": "price=$100", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
                {"id": "s2", "key": "SIMPLE", "value": "no_special", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = create_test_client(&mock_server.uri());
    let content = client
        .generate_env_file("proj-1", "production")
        .await
        .unwrap();

    assert!(content.contains("DOLLAR_VAR=\"price=\\$100\"\n"));
    assert!(content.contains("SIMPLE=no_special\n"));
}

#[tokio::test]
async fn test_cache_expired_entry_cleanup() {
    let mock_server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/projects/proj-1/environments/production/secrets/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "s1", "key": "VAR", "value": "value", "environment_id": "env-1", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
            ]
        })))
        .expect(2) // Called twice: initial + after cache expires
        .mount(&mock_server)
        .await;

    let client = KeyEnv::builder()
        .token("test-token")
        .base_url(&mock_server.uri())
        .cache_ttl(Duration::from_millis(50))
        .build()
        .unwrap();

    // First call - populates cache
    let _ = client.export_secrets("proj-1", "production").await.unwrap();

    // Wait for cache to expire
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second call - expired entry should be cleaned up and re-fetched
    let _ = client.export_secrets("proj-1", "production").await.unwrap();
}

#[tokio::test]
async fn test_error_helper_methods() {
    let unauthorized = Error::api(401, "Unauthorized");
    assert!(unauthorized.is_unauthorized());
    assert!(!unauthorized.is_not_found());

    let not_found = Error::api(404, "Not found");
    assert!(not_found.is_not_found());
    assert!(!not_found.is_unauthorized());

    let forbidden = Error::api(403, "Forbidden");
    assert!(forbidden.is_forbidden());

    let conflict = Error::api(409, "Conflict");
    assert!(conflict.is_conflict());

    let rate_limited = Error::api(429, "Rate limited");
    assert!(rate_limited.is_rate_limited());

    let server_error = Error::api(500, "Internal error");
    assert!(server_error.is_server_error());

    let bad_gateway = Error::api(502, "Bad gateway");
    assert!(bad_gateway.is_server_error());
}
