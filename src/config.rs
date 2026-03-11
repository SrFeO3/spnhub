//! # Configuration Management
//!
//! This module defines the data structures for the application's configuration
//! and handles loading it from a local file or a remote multi-endpoint API.
//! It also supports hot-reloading the configuration without service interruption.
//!
//! ## Key Components
//!
//! - **`AppConfig` and related structs**: `serde`-deserializable structures that
//!   mirror the configuration file's hierarchy.
//!
//! - **`ConfigHotReloadService`**: A service that monitors the configuration source for changes.
//!
//! ## Hot-Reloading and Idempotency
//!
//! The hot-reloading process is designed for safety and consistency:
//! - **Atomic Updates**: A new configuration is fully loaded and parsed in the background.
//!   It is only applied by atomically swapping it into place, preventing partial states.
//! - **Failure Resilience**: If fetching or parsing fails, the operation is aborted, and the
//!   hub continues to run with the last known-good configuration.
//! - **Idempotency**: Applying the configuration is idempotent; unchanged services are not
//!   disrupted.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use serde_json;
use tracing::{info, warn, debug, error};
use tokio::sync::Mutex;

/// Application-wide configuration structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub realms: Vec<RealmConfig>,
}

/// Realm configuration
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
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
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
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
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
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
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AvailabilityManagementConfig {
    pub service_id: String,
    pub _cluster_manager_urn: Option<String>,
    pub _start_at: Option<String>,
    pub _stop_at: Option<String>,
    pub ondemand_start_on_consumer: bool,
    pub ondemand_start_on_payload: bool,
    pub idle_timeout: u64,
    pub image: String,
    pub command: Option<Vec<String>>,
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

    /// Checks for configuration changes and reloads if necessary.
    pub async fn check_and_reload(&self) -> Option<AppConfig> {
        let current_content = match get_config_content(&self.config_path).await {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to get configuration content from '{}' for reload: {}", self.config_path, e);
                return None;
            }
        };

        let mut last_content = self.last_known_content.lock().await;

        if *last_content == current_content {
            info!("Hot reload signal received. No configuration change detected.");
            return None;
        }

        let new_config = match serde_yaml::from_str::<AppConfig>(&current_content) {
            Ok(config) => config,
            Err(e) => {
                if let Some(location) = e.location() {
                    warn!(
                        eventType = "configParseError",
                        path = %self.config_path,
                        line = location.line(),
                        column = location.column(),
                        error = %e,
                        "Failed to parse reloaded configuration."
                    );
                } else {
                    warn!(
                        eventType = "configParseError",
                        path = %self.config_path,
                        error = %e,
                        "Failed to parse reloaded configuration."
                    );
                }
                return None;
            }
        };

        info!("[Debug] Fetched configuration for reload check:");
        for realm in &new_config.realms {
            debug!("[Debug] - Realm: '{}', disabled: {}", realm.realm_name, realm.disabled);
        }

        if !last_content.is_empty() {
            info!("Hot reload signal received. Configuration change detected. Reloading...");
        } else {
            info!("Hot reload signal received. Initializing configuration state.");
        }

        self.shared_config.store(Arc::new(new_config.clone()));
        *last_content = current_content;
        info!("Successfully reloaded and applied new configuration.");
        Some(new_config)
    }
}

/// Loads the initial configuration from the specified path (URL or file).
pub async fn load_initial_config(path: &str) -> Result<(AppConfig, String), Box<dyn std::error::Error + Send + Sync>> {    let content = get_config_content(path).await?;
    let config = match serde_yaml::from_str::<AppConfig>(&content) {
        Ok(config) => config,
        Err(e) => {
            if let Some(location) = e.location() {
                error!(
                    eventType = "configParseError",
                    file = path,
                    line = location.line(),
                    column = location.column(),
                    error = %e,
                    "Failed to parse initial configuration file."
                );
            } else {
                error!(
                    eventType = "configParseError",
                    file = path,
                    error = %e,
                    "Failed to parse initial configuration file."
                );
            }
            return Err(format!("Failed to parse configuration file '{}': {}", path, e).into());
        }
    };
    Ok((config, content))
}

/// Fetches or reads the configuration content from a given path (URL or file).
async fn get_config_content(path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if path.starts_with("http://") || path.starts_with("https://") {
        info!("Fetching configuration content from URL: {}", path);
        fetch_config_from_url(path).await.map(|(_config, content)| content)
    } else if let Some(file_path) = path.strip_prefix("file://") {
        info!("Reading configuration content from file: {}", file_path);
        tokio::fs::read_to_string(file_path)
            .await
            .map_err(|e| format!("Failed to read file '{}': {}", file_path, e).into())
    } else {
        // Treat as a local file path for backward compatibility if no scheme is present.
        info!("Reading configuration content from local path: {}", path);
        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("Failed to read file '{}': {}", path, e).into())
    }
}

// --- API Fetching Logic ---

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ApiRealm {
    name: String,
    #[allow(dead_code)]
    title: String,
    cacert: String,
    #[allow(dead_code)]
    #[serde(default)]
    description: Option<String>,
    #[allow(dead_code)]
    device_id_signing_key: String,
    #[allow(dead_code)]
    device_id_verification_key: String,
    disabled: bool,
}

impl ApiRealm {
    fn into_config(self, hubs: Vec<HubConfig>) -> RealmConfig {
        RealmConfig {
            realm_name: self.name,
            realm_ca_cert: self.cacert,
            disabled: self.disabled,
            hubs,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ApiHub {
    name: String,
    title: String,
    fqdn: String,
    server_cert: String,
    server_cert_key: String,
    #[allow(dead_code)]
    #[serde(default)]
    attributes: serde_json::Value,
    description: Option<String>,
    server_address: Option<String>,
    server_port: Option<u16>,
}

impl ApiHub {
    fn into_config(self, services: Vec<ServiceConfig>) -> HubConfig {
        HubConfig {
            name: self.name,
            _title: self.title,
            _description: self.description.unwrap_or_default(),
            _fqdn: self.fqdn,
            server_address: self.server_address.unwrap_or_else(|| "0.0.0.0".to_string()),
            server_port: self.server_port.unwrap_or(4433),
            server_cert: self.server_cert,
            server_cert_key: self.server_cert_key,
            services,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ApiService {
    name: String,
    urn: String,
    title: String,
    description: Option<String>,
    provider: String,
    consumers: Vec<String>,
    singleton: Option<bool>,
    availability_management: Option<ApiAvailabilityManagement>,
}

impl From<ApiService> for ServiceConfig {
    fn from(api: ApiService) -> Self {
        ServiceConfig {
            name: api.name,
            urn: api.urn,
            _title: api.title,
            _description: api.description.unwrap_or_default(),
            provider: api.provider,
            consumers: api.consumers,
            _singleton: api.singleton.unwrap_or(false),
            availability_management: api.availability_management.unwrap_or_default().into(),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ApiAvailabilityManagement {
    service_id: String,
    cluster_manager_urn: String,
    #[allow(dead_code)]
    #[serde(default)]
    description: Option<String>,
    start_at: Option<String>,
    stop_at: Option<String>,
    ondemand_start_on_consumer: Option<bool>,
    ondemand_start_on_payload: Option<bool>,
    idle_timeout: Option<i32>,
    image: Option<String>,
    command: Option<Vec<String>>, // This is Vec<String> in sample, but mapped to a single string below.
    options: Option<Vec<String>>,
    env: Option<HashMap<String, String>>,
    #[allow(dead_code)]
    #[serde(default)]
    mount_points: Option<Vec<ApiMountPoint>>,
}

impl Default for ApiAvailabilityManagement {
    fn default() -> Self {
        Self {
            service_id: String::new(),
            cluster_manager_urn: String::new(),
            description: None,
            start_at: None,
            stop_at: None,
            ondemand_start_on_consumer: None,
            ondemand_start_on_payload: None,
            idle_timeout: None,
            image: None,
            command: None,
            options: None,
            env: None,
            mount_points: None,
        }
    }
}

impl From<ApiAvailabilityManagement> for AvailabilityManagementConfig {
    fn from(api: ApiAvailabilityManagement) -> Self {
        AvailabilityManagementConfig {
            service_id: api.service_id,
            _cluster_manager_urn: Some(api.cluster_manager_urn),
            _start_at: api.start_at,
            _stop_at: api.stop_at,
            ondemand_start_on_consumer: api.ondemand_start_on_consumer.unwrap_or(false),
            ondemand_start_on_payload: api.ondemand_start_on_payload.unwrap_or(false),
            idle_timeout: api.idle_timeout.unwrap_or(0).max(0) as u64,
            image: api.image.unwrap_or_default(),
            command: api.command,
            env: api.env,
            options: api.options,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ApiMountPoint {
    #[allow(dead_code)]
    volume_size: i32,
    #[allow(dead_code)]
    target: String,
}

async fn fetch_config_from_url(url: &str) -> Result<(AppConfig, String), Box<dyn std::error::Error + Send + Sync>> {
    // Helper to fetch and deserialize, with better error reporting
    async fn fetch_and_deserialize<T: serde::de::DeserializeOwned>(client: &reqwest::Client, url: &str) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        info!("Fetching from {}", url);
        let response = client.get(url).send().await.map_err(|e| format!("Network error while fetching from {}: {}", url, e))?;
        let status = response.status();
        let body_text = response.text().await.map_err(|e| format!("Failed to read response body from {}: {}", url, e))?;
        if !status.is_success() {
            error!("API at {} returned error status {}: {}", url, status, &body_text);
            return Err(format!("API error for {}: status {}" , url, status).into());
        }
        serde_json::from_str::<T>(&body_text).map_err(|e| {
            error!(
                eventType = "jsonDeserializeError",
                url = url,
                line = e.line(),
                column = e.column(),
                error = %e,
                body = %body_text,
                "Failed to deserialize JSON"
            );
            format!("JSON deserialize error for {}: {}", url, e).into()
        })
    }

    let base_url = url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let realms_url = format!("{}/realms", base_url);
    let api_realms: Vec<ApiRealm> = fetch_and_deserialize(&client, &realms_url).await?;

    let mut realm_configs = Vec::new();
    for api_realm in api_realms {
        let hubs_url = format!("{}/realms/{}/hubs", base_url, api_realm.name);
        let api_hubs: Vec<ApiHub> = fetch_and_deserialize(&client, &hubs_url).await?;

        let mut hub_configs = Vec::new();
        for api_hub in api_hubs {
            let services_url = format!("{}/realms/{}/hubs/{}/services", base_url, api_realm.name, api_hub.name);
            let api_services: Vec<ApiService> = fetch_and_deserialize(&client, &services_url).await?;
            let services = api_services.into_iter().map(ServiceConfig::from).collect();
            hub_configs.push(api_hub.into_config(services));
        }

        realm_configs.push(api_realm.into_config(hub_configs));
    }

    let config = AppConfig { realms: realm_configs };
    // Serialize to YAML to use as "content" for change detection
    let content = serde_yaml::to_string(&config)?;
    Ok((config, content))
}
