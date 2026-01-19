//! # KeyEnv Rust SDK
//!
//! Official Rust SDK for [KeyEnv](https://keyenv.dev) - Secrets management made simple.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use keyenv::KeyEnv;
//! use std::env;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), keyenv::Error> {
//!     let client = KeyEnv::builder()
//!         .token(env::var("KEYENV_TOKEN").expect("KEYENV_TOKEN not set"))
//!         .build()?;
//!
//!     // Load secrets into environment
//!     client.load_env("your-project-id", "production").await?;
//!
//!     println!("{}", env::var("DATABASE_URL").unwrap());
//!     Ok(())
//! }
//! ```
//!
//! ## Loading Secrets
//!
//! ### Load into Environment
//!
//! ```rust,no_run
//! # use keyenv::KeyEnv;
//! # async fn example(client: &KeyEnv) -> Result<(), keyenv::Error> {
//! let count = client.load_env("project-id", "production").await?;
//! println!("Loaded {} secrets", count);
//! # Ok(())
//! # }
//! ```
//!
//! ### Export as HashMap
//!
//! ```rust,no_run
//! # use keyenv::KeyEnv;
//! # async fn example(client: &KeyEnv) -> Result<(), keyenv::Error> {
//! let secrets = client.export_secrets_as_map("project-id", "production").await?;
//! println!("{}", secrets.get("DATABASE_URL").unwrap());
//! # Ok(())
//! # }
//! ```
//!
//! ## Managing Secrets
//!
//! ```rust,no_run
//! # use keyenv::KeyEnv;
//! # async fn example(client: &KeyEnv) -> Result<(), keyenv::Error> {
//! // Get a secret
//! let secret = client.get_secret("project-id", "production", "DATABASE_URL").await?;
//! println!("{}", secret.value);
//!
//! // Set a secret
//! client.set_secret("project-id", "production", "API_KEY", "sk_live_...").await?;
//!
//! // Delete a secret
//! client.delete_secret("project-id", "production", "OLD_KEY").await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Error Handling
//!
//! ```rust,no_run
//! use keyenv::{KeyEnv, Error};
//!
//! # async fn example(client: &KeyEnv) -> Result<(), keyenv::Error> {
//! match client.get_secret("project-id", "production", "MISSING_KEY").await {
//!     Ok(secret) => println!("{}", secret.value),
//!     Err(Error::Api { status, message, .. }) => {
//!         match status {
//!             401 => eprintln!("Invalid or expired token"),
//!             403 => eprintln!("Access denied"),
//!             404 => eprintln!("Secret not found"),
//!             _ => eprintln!("Error {}: {}", status, message),
//!         }
//!     }
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Caching
//!
//! Enable caching for better performance in serverless environments:
//!
//! ```rust,no_run
//! use keyenv::KeyEnv;
//! use std::time::Duration;
//!
//! # fn example() -> Result<(), keyenv::Error> {
//! let client = KeyEnv::builder()
//!     .token("your-token")
//!     .cache_ttl(Duration::from_secs(300))  // 5 minutes
//!     .build()?;
//! # Ok(())
//! # }
//! ```

mod client;
mod error;
mod types;

pub use client::{KeyEnv, KeyEnvBuilder, DEFAULT_BASE_URL, DEFAULT_TIMEOUT, VERSION};
pub use error::{Error, Result};
pub use types::{
    BulkImportOptions, BulkImportResult, CurrentUserResponse, DefaultPermission, Environment,
    MyPermissionsResponse, Permission, PermissionInput, Project, Secret, SecretHistory,
    SecretInput, SecretWithInheritance, SecretWithValue, SecretWithValueAndInheritance,
    ServiceToken, Team, User,
};
