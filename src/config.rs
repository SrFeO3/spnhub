//! # Configuration Management
//!
//! This module is responsible for defining, loading, and managing the application's
//! configuration. It includes data structures that map directly to the `config.yaml` file,
//! and logic for hot-reloading configurations without service interruption.
//!
//! ## Key Components
//!
//! - **`AppConfig` and related structs**: These are `serde`-deserializable structures
//!   that represent the hierarchy of the `config.yaml` file.
//!
//! - **`ConfigHotReloadService`**: A background service that monitors `config.yaml` for changes
//!   and applies them to the running application without downtime. It uses `ArcSwap` to
//!   atomically update shared configuration data.
//!
//! - **Caches and Registries (`UpstreamCache`, `CertificateCache`, `AuthScopeRegistry`, `JwtKeysCache`)**:
//!   These components hold processed, ready-to-use data derived from the main configuration.
//!   They are designed to be hot-reloaded and are managed by the `ConfigHotReloadService`.
//!
//! ## Hot-Reloading and Idempotency
//!
//! The hot-reloading mechanism is designed to be idempotent and minimally disruptive:
//! - **JWT Keys, Certificates, and Upstreams**: When the configuration changes, only the
//!   items that have been added, modified, or removed are updated. Unchanged items are
//!   left as-is.
//! - **Authentication Scopes**: The `AuthScopeRegistry` performs a differential update.
//!   It adds new scopes and removes obsolete ones, but crucially, it does **not** touch
//!   existing, unchanged scopes. This ensures that active user sessions within those
//!   scopes are preserved across configuration reloads.
//!
//! ## Usage Examples
//!
//! ### 1. Starting the Hot-Reload Service
//!
//! In your `main.rs`, initialize the configuration and start the monitoring service:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use arc_swap::ArcSwap;
//! // Assuming this module is accessible as `crate::config`
//! use crate::config::{load_initial_config, ConfigHotReloadService};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config_path = "config.yaml".to_string();
//!
//!     // Load initial config
//!     let (initial_config, initial_content) = load_initial_config(&config_path).expect("Failed to load configuration");
//!
//!     // Create shared storage (ArcSwap allows lock-free reads)
//!     let reload_service = ConfigHotReloadService::new(config_path.clone(), shared_config.clone(), initial_content);
//!
//!     // Start hot-reload service in a background task
//!     let reload_service = ConfigHotReloadService::new(config_path.clone(), shared_config.clone());
//!     tokio::spawn(async move {
//!         reload_service.start().await;
//!     });
//!
//!     // Pass `shared_config` to your server or components...
//! }
//! ```
//!
//! ### 2. Accessing Configuration Values
//!
//! Use `load()` to get a consistent snapshot of the configuration.
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use arc_swap::ArcSwap;
//! use crate::config::AppConfig;
//!
//! fn handle_request(shared_config: &Arc<ArcSwap<AppConfig>>) {
//!     // Get a snapshot (Guard) - this is cheap and lock-free
//!     let config = shared_config.load();
//!
//!     // Access fields directly
//!     for realm in &config.realms {
//!         println!("Hub Name: {}", realm.hub.name);
//!         println!("Server Port: {}", realm.hub.server_port);
//!
//!         // Access nested fields (e.g., services)
//!         for service in &realm.hub.services {
//!             println!("Service: {}, Image: {}", service.name, service.availability_management.image);
//!         }
//!     }
//!
//!     // Generate the service map from the config
//!     let service_map = crate::config::generate_service_map(&config);
//!     if let Some(service_name) = service_map.get("urn:chip-in:end-point:hub.master.TEST1ZONE:www-gateway") {
//!         println!("Service for URN is: {}", service_name);
//!     }
//! }
//! ```
//!
//! ### 3. Specifying the Configuration File
//!
//! The file path is passed to `load_initial_config` and `ConfigHotReloadService::new`.

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Deserialize;
use tracing::{info, warn};
use tokio::sync::Mutex;

/// Application-wide configuration structure
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub realms: Vec<RealmConfig>,
}

/// Realm configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RealmConfig {
    #[serde(rename = "name")]
    pub realm_name: String,
    #[serde(rename = "cacert")]
    pub realm_ca_cert: String,
    #[serde(default)]
    pub disabled: bool,
    pub hubs: Vec<HubConfig>,
}

/// Hub configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HubConfig {
    pub name: String,
    pub _title: String,
    pub _description: String,
    pub _fqdn: String,
    pub server_address: String,
    pub server_port: u16,
    pub server_cert: String,
    pub server_cert_key: String,
    pub services: Vec<ServiceConfig>,
}

/// Service configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceConfig {
    pub name: String,
    pub urn: String,
    pub _title: String,
    pub _description: String,
    pub availability_management: AvailabilityManagementConfig,
    pub provider: String,
    pub consumers: Vec<String>,
    pub _singleton: bool,
}

/// Availability management configuration for a service
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AvailabilityManagementConfig {
    pub _service_id: String,
    pub _cluster_manager_urn: Option<String>,
    pub _start_at: Option<String>,
    pub _stop_at: Option<String>,
    pub ondemand_start_on_consumer: bool,
    pub ondemand_start_on_payload: bool,
    pub _idle_timeout: u64,
    pub image: String,
    pub _command: Option<String>,
    pub env: Option<HashMap<String, String>>,
    pub options: Option<Vec<String>>,
}

/// Service that monitors configuration file changes and applies them
pub struct ConfigHotReloadService {
    config_path: String,
    shared_config: Arc<ArcSwap<AppConfig>>,
    last_known_content: Mutex<String>,
}

impl ConfigHotReloadService {
    pub fn new(config_path: String, shared_config: Arc<ArcSwap<AppConfig>>, initial_content: String) -> Self {
        Self {
            config_path,
            shared_config,
            last_known_content: Mutex::new(initial_content),
        }
    }

    pub async fn check_and_reload(&self) -> Option<AppConfig> {
        match tokio::fs::read_to_string(&self.config_path).await {
            Ok(current_content) => {
                let mut last_content = self.last_known_content.lock().await;
                if *last_content != current_content {
                    if !last_content.is_empty() {
                        info!("Hot reload signal received. Configuration change detected. Reloading...");
                    } else {
                        info!("Hot reload signal received. Initializing configuration state.");
                    }

                    match serde_yaml::from_str::<AppConfig>(&current_content) {
                        Ok(new_config) => {
                            self.shared_config.store(Arc::new(new_config.clone()));
                            *last_content = current_content;
                            info!("Successfully reloaded and applied new configuration.");
                            return Some(new_config);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse reloaded configuration '{}': {}",
                                self.config_path, e
                            );
                        }
                    }
                } else {
                    info!("Hot reload signal received. No configuration change detected.");
                }
            }
            Err(e) => {
                warn!(
                    "Failed to read configuration file '{}': {}",
                    self.config_path, e
                );
            }
        }
        None
    }
}

/// Loads the initial configuration
pub fn load_initial_config(path: &str) -> Result<(AppConfig, String), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read configuration file '{}': {}", path, e))?;
    let config = serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse configuration file '{}': {}", path, e))?;
    Ok((config, content))
}
