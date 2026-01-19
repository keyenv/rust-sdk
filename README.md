# KeyEnv Rust SDK

Official Rust SDK for [KeyEnv](https://keyenv.dev) - Secrets management made simple.

[![Crates.io](https://img.shields.io/crates/v/keyenv.svg)](https://crates.io/crates/keyenv)
[![Documentation](https://docs.rs/keyenv/badge.svg)](https://docs.rs/keyenv)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
keyenv = "1.0"
tokio = { version = "1", features = ["full"] }
```

Or using cargo:

```bash
cargo add keyenv tokio --features tokio/full
```

## Quick Start

```rust
use keyenv::KeyEnv;
use std::env;

#[tokio::main]
async fn main() -> Result<(), keyenv::Error> {
    let client = KeyEnv::builder()
        .token(env::var("KEYENV_TOKEN").expect("KEYENV_TOKEN not set"))
        .build()?;

    // Load secrets into environment
    client.load_env("your-project-id", "production").await?;

    println!("{}", env::var("DATABASE_URL").unwrap());
    Ok(())
}
```

## Configuration

```rust
use keyenv::KeyEnv;
use std::time::Duration;

let client = KeyEnv::builder()
    .token("your-service-token")           // Required
    .base_url("https://api.keyenv.dev")    // Optional
    .timeout(Duration::from_secs(30))      // Optional, default 30s
    .cache_ttl(Duration::from_secs(300))   // Optional, 0 disables caching
    .build()?;
```

## Loading Secrets

### Load into Environment

The simplest way to use secrets in your application:

```rust
let count = client.load_env("project-id", "production").await?;
println!("Loaded {} secrets", count);

// Now use them
println!("{}", std::env::var("DATABASE_URL").unwrap());
```

### Export as HashMap

Get secrets as a HashMap:

```rust
let secrets = client.export_secrets_as_map("project-id", "production").await?;
println!("{}", secrets.get("DATABASE_URL").unwrap());
```

### Export with Metadata

Get secrets with full metadata:

```rust
let secrets = client.export_secrets("project-id", "production").await?;
for secret in secrets {
    println!("{}={}", secret.key, secret.value);
}
```

## Managing Secrets

### Get a Single Secret

```rust
let secret = client.get_secret("project-id", "production", "DATABASE_URL").await?;
println!("{}", secret.value);
```

### Set a Secret

Creates or updates a secret:

```rust
client.set_secret("project-id", "production", "API_KEY", "sk_live_...").await?;

// With description
client.set_secret_with_description(
    "project-id",
    "production",
    "API_KEY",
    "sk_live_...",
    Some("Production API key")
).await?;
```

### Delete a Secret

```rust
client.delete_secret("project-id", "production", "OLD_KEY").await?;
```

## Bulk Operations

### Bulk Import

```rust
use keyenv::{SecretInput, BulkImportOptions};

let result = client.bulk_import(
    "project-id",
    "development",
    vec![
        SecretInput::new("DATABASE_URL", "postgres://localhost/mydb"),
        SecretInput::new("REDIS_URL", "redis://localhost:6379"),
    ],
    BulkImportOptions { overwrite: true },
).await?;

println!("Created: {}, Updated: {}", result.created, result.updated);
```

### Generate .env File

```rust
use std::fs;

let content = client.generate_env_file("project-id", "production").await?;
fs::write(".env", content)?;
```

## Projects & Environments

### List Projects

```rust
let projects = client.list_projects().await?;
for project in projects {
    println!("{} ({})", project.name, project.id);
}
```

### Get Project Details

```rust
let project = client.get_project("project-id").await?;
println!("Project: {}", project.name);
for env in project.environments {
    println!("  - {}", env.name);
}
```

## Error Handling

```rust
use keyenv::{KeyEnv, Error};

match client.get_secret("project-id", "production", "MISSING_KEY").await {
    Ok(secret) => println!("{}", secret.value),
    Err(Error::Api { status, message, .. }) => {
        match status {
            401 => eprintln!("Invalid or expired token"),
            403 => eprintln!("Access denied"),
            404 => eprintln!("Secret not found"),
            _ => eprintln!("Error {}: {}", status, message),
        }
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## Caching

Enable caching for better performance:

```rust
let client = KeyEnv::builder()
    .token(env::var("KEYENV_TOKEN")?)
    .cache_ttl(Duration::from_secs(300))  // 5 minutes
    .build()?;

// Cached for 5 minutes
let secrets = client.export_secrets("project-id", "production").await?;

// Clear cache manually
client.clear_cache(Some("project-id"), Some("production")).await;

// Or clear all cache
client.clear_all_cache().await;
```

## API Reference

### Builder Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `token` | `String` | Yes | - | Service token |
| `base_url` | `String` | No | `https://api.keyenv.dev` | API base URL |
| `timeout` | `Duration` | No | `30s` | Request timeout |
| `cache_ttl` | `Duration` | No | `0` | Cache TTL (0 = disabled) |

### Methods

| Method | Description |
|--------|-------------|
| `get_current_user()` | Get current user/token info |
| `list_projects()` | List all accessible projects |
| `get_project(id)` | Get project with environments |
| `list_environments(project_id)` | List environments |
| `list_secrets(project_id, env)` | List secret keys (no values) |
| `export_secrets(project_id, env)` | Export secrets with values |
| `export_secrets_as_map(project_id, env)` | Export as HashMap |
| `get_secret(project_id, env, key)` | Get single secret |
| `set_secret(project_id, env, key, value)` | Create or update secret |
| `set_secret_with_description(...)` | Create/update with description |
| `delete_secret(project_id, env, key)` | Delete secret |
| `bulk_import(project_id, env, secrets, opts)` | Bulk import secrets |
| `load_env(project_id, env)` | Load secrets into env vars |
| `generate_env_file(project_id, env)` | Generate .env file content |
| `get_secret_history(project_id, env, key)` | Get secret version history |
| `list_permissions(project_id, env)` | List permissions |
| `set_permission(project_id, env, user_id, role)` | Set user permission |
| `delete_permission(project_id, env, user_id)` | Delete permission |
| `bulk_set_permissions(...)` | Bulk set permissions |
| `get_my_permissions(project_id)` | Get current user's permissions |
| `get_project_defaults(project_id)` | Get default permissions |
| `set_project_defaults(project_id, defaults)` | Set default permissions |
| `clear_cache(project_id, env)` | Clear cached secrets |
| `clear_all_cache()` | Clear all cached data |

## Examples

### Actix Web Server

```rust
use actix_web::{web, App, HttpServer, Responder};
use keyenv::KeyEnv;
use std::env;

async fn index() -> impl Responder {
    "OK"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = KeyEnv::builder()
        .token(env::var("KEYENV_TOKEN").unwrap())
        .build()
        .unwrap();

    // Load secrets before starting server
    client.load_env(
        &env::var("KEYENV_PROJECT").unwrap(),
        "production"
    ).await.unwrap();

    HttpServer::new(|| {
        App::new().route("/", web::get().to(index))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
```

### Lambda Function

```rust
use keyenv::KeyEnv;
use lambda_runtime::{service_fn, LambdaEvent, Error};
use once_cell::sync::Lazy;
use std::env;

static CLIENT: Lazy<KeyEnv> = Lazy::new(|| {
    KeyEnv::builder()
        .token(env::var("KEYENV_TOKEN").unwrap())
        .cache_ttl(std::time::Duration::from_secs(300))
        .build()
        .unwrap()
});

async fn handler(_event: LambdaEvent<()>) -> Result<String, Error> {
    CLIENT.load_env(&env::var("KEYENV_PROJECT")?, "production").await?;
    Ok(env::var("API_KEY")?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    lambda_runtime::run(service_fn(handler)).await
}
```

## Features

- `rustls` - Use rustls for TLS (recommended for most platforms)
- `native-tls` - Use native TLS (OpenSSL on Linux, Secure Transport on macOS)

```toml
[dependencies]
keyenv = { version = "1.0", features = ["rustls"] }
```

## License

MIT License - see [LICENSE](LICENSE) for details.
