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
        let current_content = match tokio::fs::read_to_string(&self.config_path).await {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read configuration file '{}': {}", self.config_path, e);
                return None;
            }
        };

        let mut last_content = self.last_known_content.lock().await;

        if *last_content == current_content {
            info!("Hot reload signal received. No configuration change detected.");
            return None;
        }

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
                Some(new_config)
            }
            Err(e) => {
                warn!("Failed to parse reloaded configuration '{}': {}", self.config_path, e);
                None
            }
        }
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
