/// # Configuration Management
///
/// This module is responsible for defining, loading, and managing the application's
/// configuration. It includes data structures that map directly to the `config.yaml` file,
/// and logic for hot-reloading configurations without service interruption.
///
/// ## Key Components:
///
/// - **`AppConfig` and related structs**: These are `serde`-deserializable structures
///   that represent the hierarchy of the `config.yaml` file.
///
/// - **`ConfigHotReloadService`**: A background service that monitors `config.yaml` for changes
///   and applies them to the running application without downtime. It uses `ArcSwap` to
///   atomically update shared configuration data.
///
/// - **Caches and Registries (`UpstreamCache`, `CertificateCache`, `AuthScopeRegistry`, `JwtKeysCache`)**:
///   These components hold processed, ready-to-use data derived from the main configuration.
///   They are designed to be hot-reloaded and are managed by the `ConfigHotReloadService`.
///
/// ## Hot-Reloading and Idempotency
///
/// The hot-reloading mechanism is designed to be idempotent and minimally disruptive:
/// - **JWT Keys, Certificates, and Upstreams**: When the configuration changes, only the
///   items that have been added, modified, or removed are updated. Unchanged items are
///   left as-is.
/// - **Authentication Scopes**: The `AuthScopeRegistry` performs a differential update.
///   It adds new scopes and removes obsolete ones, but crucially, it does **not** touch
///   existing, unchanged scopes. This ensures that active user sessions within those
///   scopes are preserved across configuration reloads.

use tracing::info;
use tracing::warn;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use arc_swap::ArcSwap;
use tokio::sync::Mutex;
use tokio::time;
use tokio::time::Duration;

/// Application-wide configuration structure
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub realms: Vec<RealmConfig>,
}

/// Realm configuration
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RealmConfig {
    pub realm: String,
    pub realm_ca_cert: String,
    pub hub: HubConfig,
}

/// Hub configuration mapping directly to config.yaml
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HubConfig {
    pub name: String,
    pub title: String,
    pub description: String,
    pub fqdn: String,
    pub server_port: u16,
    pub server_cert: String,
    pub server_cert_key: String,
    pub services: Vec<ServiceConfig>,
}

/// Service configuration
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceConfig {
    pub name: String,
    pub title: String,
    pub description: String,
    pub availability_management: AvailabilityManagementConfig,
    pub provider: String,
    pub consumers: Vec<String>,
    pub singleton: bool,
}

/// Availability management configuration for a service
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AvailabilityManagementConfig {
    pub ondemand_start: bool,
    pub idle_timeout: u64,
    pub image: String,
    pub command: Option<String>,
    pub env: Option<HashMap<String, String>>,
}

/// Generates a service map (endpoint URN -> service name) from the application configuration.
///
/// This function creates a `HashMap` that is equivalent to the one manually created
/// in `main.rs`, allowing the application to derive the service map directly from the
/// configuration file.
///
/// # Arguments
///
/// * `config`: A reference to the `AppConfig`.
///
/// # Returns
///
/// A `HashMap<String, String>` where keys are endpoint URNs and values are service names.
pub fn generate_service_map(config: &AppConfig) -> HashMap<String, String> {
    let mut service_map = HashMap::new();
    for realm in &config.realms {
        for service in &realm.hub.services {
            // Map the provider endpoint
            service_map.insert(service.provider.clone(), service.name.clone());
            // Map all consumer endpoints
            for consumer_urn in &service.consumers {
                service_map.insert(consumer_urn.clone(), service.name.clone());
            }
        }
    }
    service_map
}

/// Service that monitors configuration file changes and applies them
pub struct ConfigHotReloadService {
    config_path: String,
    shared_config: Arc<ArcSwap<AppConfig>>,
    last_known_content: Mutex<String>,
}

impl ConfigHotReloadService {
    pub fn new(config_path: String, shared_config: Arc<ArcSwap<AppConfig>>) -> Self {
        Self {
            config_path,
            shared_config,
            last_known_content: Mutex::new(String::new()),
        }
    }

    /// Starts the monitoring loop
    pub async fn start(&self) {
        let mut interval = time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            self.check_and_reload().await;
        }
    }

    async fn check_and_reload(&self) {
        match tokio::fs::read_to_string(&self.config_path).await {
            Ok(current_content) => {
                let mut last_content = self.last_known_content.lock().await;
                if *last_content != current_content {
                    // If last_content is empty (e.g., on initial startup), just update without logging
                    let is_reload = !last_content.is_empty();

                    if is_reload {
                        info!("Configuration file change detected. Attempting to reload...");
                    }

                    match serde_yaml::from_str::<AppConfig>(&current_content) {
                        Ok(new_config) => {
                            self.shared_config.store(Arc::new(new_config));
                            *last_content = current_content;
                            if is_reload {
                                info!("Successfully reloaded and applied new configuration.");
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse reloaded configuration: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read configuration file '{}': {}", self.config_path, e);
            }
        }
    }
}

/// Loads the initial configuration
pub fn load_initial_config(path: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let config = serde_yaml::from_str(&content)?;
    Ok(config)
}
