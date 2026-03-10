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
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use futures::future::{join_all};
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
    pub _idle_timeout: u64,
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

    pub async fn check_and_reload(&self) -> Option<AppConfig> {
        let (new_config, current_content) = if self.config_path.starts_with("http://") || self.config_path.starts_with("https://") {
            match fetch_config_from_url(&self.config_path).await {
                Ok(res) => res,
                Err(e) => {
                    warn!("Failed to fetch configuration from '{}': {}", self.config_path, e);
                    return None;
                }
            }
        } else {
            let content = match tokio::fs::read_to_string(&self.config_path).await {
                Ok(content) => content,
                Err(e) => {
                    warn!("Failed to read configuration file '{}': {}", self.config_path, e);
                    return None;
                }
            };

            match serde_yaml::from_str::<AppConfig>(&content) {
                Ok(config) => (config, content),
                Err(e) => {
                    warn!("Failed to parse reloaded configuration '{}': {}", self.config_path, e);
                    return None;
                }
            }
        };

        info!("[Debug] Fetched configuration for reload check:");
        for realm in &new_config.realms {
            debug!("[Debug] - Realm: '{}', disabled: {}", realm.realm_name, realm.disabled);
        }

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

        self.shared_config.store(Arc::new(new_config.clone()));
        *last_content = current_content;
        info!("Successfully reloaded and applied new configuration.");
        Some(new_config)
    }
}

/// Loads the initial configuration
pub async fn load_initial_config(path: &str) -> Result<(AppConfig, String), Box<dyn std::error::Error + Send + Sync>> {
    if path.starts_with("http://") || path.starts_with("https://") {
        info!("Loading configuration from repository: {}", path);
        match fetch_config_from_url(path).await {
            Ok(res) => return Ok(res),
            Err(e) => {
                warn!("Failed to fetch configuration from repository: {}. Falling back to local file.", e);
            }
        }
    }
    info!("Loading configuration from file: {}", path);
    let content = tokio::fs::read_to_string(path).await
        .map_err(|e| format!("Failed to read configuration file '{}': {}", path, e))?;
    let config = serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse configuration file '{}': {}", path, e))?;
    Ok((config, content))
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
            error!("Failed to deserialize JSON from {}: {}. Body: '{}'", url, e, &body_text);
            format!("JSON deserialize error for {}: {}", url, e).into()
        })
    }

    let base_url = url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let realms_url = format!("{}/realms", base_url);
    let api_realms: Vec<ApiRealm> = fetch_and_deserialize(&client, &realms_url).await?;

    let mut realms = Vec::new();

    for api_realm in api_realms {
        let hubs_url = format!("{}/realms/{}/hubs", base_url, api_realm.name);
        let api_hubs: Vec<ApiHub> = fetch_and_deserialize(&client, &hubs_url).await?;

        let hub_tasks = api_hubs.into_iter().map(|api_hub| {
            let client = client.clone();
            let realm_name = api_realm.name.clone();
            let url = base_url.to_string();
            async move {
                let services_url = format!("{}/realms/{}/hubs/{}/services", url, realm_name, api_hub.name);
                let api_services: Vec<ApiService> = fetch_and_deserialize(&client, &services_url).await?;

                let services = api_services.into_iter().map(|s| {
                    let am = s.availability_management.unwrap_or_else(|| ApiAvailabilityManagement {
                        service_id: "".to_string(), cluster_manager_urn: "".to_string(), description: None, start_at: None, stop_at: None, ondemand_start_on_consumer: None, ondemand_start_on_payload: None, idle_timeout: None, image: None, command: None, options: None, env: None, mount_points: None
                   });

                    ServiceConfig {
                        name: s.name,
                        urn: s.urn,
                        _title: s.title,
                        _description: s.description.unwrap_or_default(),
                        provider: s.provider,
                        consumers: s.consumers,
                        _singleton: s.singleton.unwrap_or(false),
                        availability_management: AvailabilityManagementConfig {
                            service_id: am.service_id,
                            _cluster_manager_urn: Some(am.cluster_manager_urn),
                            _start_at: am.start_at,
                            _stop_at: am.stop_at,
                            ondemand_start_on_consumer: am.ondemand_start_on_consumer.unwrap_or(false),
                            ondemand_start_on_payload: am.ondemand_start_on_payload.unwrap_or(false),
                            _idle_timeout: am.idle_timeout.unwrap_or(0) as u64,
                            image: am.image.unwrap_or_default(),
                            command: am.command,
                            env: am.env,
                            options: am.options,
                        }
                    }
                }).collect();

                let result: Result<HubConfig, Box<dyn std::error::Error + Send + Sync>> = Ok(HubConfig {
                    name: api_hub.name,
                    _title: api_hub.title,
                    _description: api_hub.description.unwrap_or_default(),
                    _fqdn: api_hub.fqdn,
                    server_address: api_hub.server_address.unwrap_or("0.0.0.0".to_string()),
                    server_port: api_hub.server_port.unwrap_or(4433),
                    server_cert: api_hub.server_cert,
                    server_cert_key: api_hub.server_cert_key,
                    services,
                });
                result
            }
        });

        let hubs: Vec<HubConfig> = join_all(hub_tasks)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, Box<dyn std::error::Error + Send + Sync>>>()?;


        realms.push(RealmConfig {
            realm_name: api_realm.name,
            realm_ca_cert: api_realm.cacert,
            disabled: api_realm.disabled,
            hubs,
        });
    }

    let config = AppConfig { realms };
    // Serialize to YAML to use as "content" for change detection
    let content = serde_yaml::to_string(&config)?;
    Ok((config, content))
}
