//! # Microservice Management
//!
//! This module acts as the control-plane responsible for the lifecycle of microservices.
//!
//! It handles:
//! - Spawning (starting) providers.
//! - Stopping and removing providers.
//! - (Planned) Monitoring health.
//!
//! ## Runtime Assumptions
//! - Supports **Docker** and **Nomad** as backends.
//! - The backend is selected based on the `clusterManagerUrn` prefix (e.g., `nomad:`).
//!
//! ## Security Note
//! - This design assumes that the configuration file is benevolent and fully trusted.
//! - No extensive validation or sanitization is performed on parameters such as `options`, `command`, or `env`.
//!
//! ## Concurrency Model
//! - Uses asynchronous APIs via `tokio` to avoid blocking the main event loop.
//!
//! ## API Surface
//! - `start_provider`: Asynchronously starts a provider using the configured backend.
//! - `stop_provider`: Asynchronously stops and removes a provider.

use std::collections::HashMap;
use crate::config::AvailabilityManagementConfig;

/// --- Public Interface Definitions ---

/// A handle to a started container.
#[derive(Debug)]
pub struct ContainerHandle {
    /// Backend-specific container/task ID.
    pub id: String,
}

/// Errors that can occur during microservice startup.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("Docker error: {0}")]
    Docker(#[from] bollard::errors::Error),
    #[error("Nomad error: {0}")]
    Nomad(#[from] reqwest::Error),
    #[error("Error: {0}")]
    Other(String),
}

/// Errors that can occur during microservice shutdown.
#[derive(Debug, thiserror::Error)]
pub enum StopError {
    #[error("Docker error: {0}")]
    Docker(#[from] bollard::errors::Error),
    #[error("Nomad error: {0}")]
    Nomad(#[from] reqwest::Error),
    #[error("Error: {0}")]
    Other(String),
}

/// Starts a container for the specified provider configuration.
///
/// This function looks up the container image associated with the provided URN
/// in the application configuration and starts it.
pub async fn start_provider(
    config: &AvailabilityManagementConfig,
) -> Result<ContainerHandle, StartError> {
    let is_nomad = config._cluster_manager_urn
        .as_deref()
        .map(|urn| urn.starts_with("nomad:"))
        .unwrap_or(false);

    let result = if is_nomad {
        match nomad_backend::scale_task(config, 1).await {
            Ok(_) => Ok(ContainerHandle { id: config.service_id.clone() }),
            Err(e) => Err(StartError::Other(e.to_string())),
        }
    } else {
        docker_backend::start_container(
            &config.image,
            config.options.as_deref(),
            &config.service_id,
            config.env.as_ref(),
            config.command.as_deref(),
        )
        .await
    };

    match &result {
        Ok(handle) => tracing::info!("start_provider result: success, id={}", handle.id),
        Err(e) => tracing::info!("start_provider result: failure, error={}", e),
    }
    result
}

/// Stops and removes a microservice container.
pub async fn stop_provider(
    config: &AvailabilityManagementConfig,
) -> Result<(), StopError> {
    let is_nomad = config._cluster_manager_urn
        .as_deref()
        .map(|urn| urn.starts_with("nomad:"))
        .unwrap_or(false);

    if is_nomad {
        nomad_backend::scale_task(config, 0).await
            .map_err(|e| StopError::Other(e.to_string()))
    } else {
        docker_backend::stop_container(&config.service_id).await
    }
}

/// --- Docker Backend Implementation ---

mod docker_backend {
    use super::*;
    use bollard::Docker;
    use bollard::errors::Error as DockerError;
    use bollard::models::{ContainerCreateBody, HostConfig, PortBinding};
    use bollard::query_parameters::{CreateContainerOptions, RemoveContainerOptions, StartContainerOptions, StopContainerOptions};

    /// Starts a Docker container asynchronously.
    pub async fn start_container(
        image: &str,
        options: Option<&[String]>,
        service_id: &str,
        env: Option<&HashMap<String, String>>,
        command: Option<&[String]>,
    ) -> Result<ContainerHandle, StartError> {
        tracing::info!(
            serviceId = service_id,
            image,
            options = ?options,
            env = ?env,
            command = ?command,
            "Docker: Starting container."
        );

        // Prepare connection to the Unix domain socket. Involves I/O but is a very lightweight synchronous operation.
        let docker = Docker::connect_with_local_defaults()?;
        // Generate container name (sanitization process)
        let container_name = format!("spn_{}", service_id.replace(|c: char| !c.is_alphanumeric(), "_"));

        // Parse string array options into structures for the Docker API
        let mut network_mode = None;
        let mut binds = Vec::new();
        let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
        let mut privileged = false;
        let mut cap_add = Vec::new();

        if let Some(options) = options {
            let mut i = 0;
            while i < options.len() {
                match options[i].as_str() {
                    "-p" | "--publish" => {
                        if i + 1 < options.len() {
                            if let Some((host, container)) = options[i + 1].split_once(':') {
                                let container_port = format!("{}/tcp", container);
                                let binding = PortBinding {
                                    host_ip: Some("0.0.0.0".to_string()),
                                    host_port: Some(host.to_string()),
                                };
                                port_bindings.entry(container_port).or_default().get_or_insert_with(Vec::new).push(binding);
                            }
                            i += 1;
                        }
                    }
                    "--network" => {
                        if i + 1 < options.len() {
                            network_mode = Some(options[i + 1].to_string());
                            i += 1;
                        }
                    }
                    "-v" | "--volume" => {
                        if i + 1 < options.len() {
                            binds.push(options[i + 1].to_string());
                            i += 1;
                        }
                    }
                    "--privileged" => privileged = true,
                    "--cap-add" => {
                        if i + 1 < options.len() {
                            cap_add.push(options[i + 1].to_string());
                            i += 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        }

        let env_vars = env.map(|map| map.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>());

        let host_config = HostConfig {
            network_mode,
            binds: Some(binds),
            port_bindings: Some(port_bindings),
            privileged: Some(privileged),
            cap_add: Some(cap_add),
            ..Default::default()
        };

        let config = ContainerCreateBody {
            image: Some(image.to_string()),
            host_config: Some(host_config),
            env: env_vars,
            cmd: command.map(|v| v.to_vec()),
            ..Default::default()
        };

        let create_options = CreateContainerOptions { name: Some(container_name.clone()), ..Default::default() };

        // Create the container asynchronously
        let id = match docker.create_container(Some(create_options), config).await {
            Ok(c) => c.id,
            Err(DockerError::DockerResponseServerError { status_code: 409, .. }) => {
                // If it already exists, get its ID
                let inspect = docker.inspect_container(&container_name, None).await?;
                inspect.id.ok_or_else(|| StartError::Other("Container exists but has no ID".to_string()))?
            }
            Err(e) => return Err(e.into()),
        };

        // Start the container asynchronously
        match docker.start_container(&container_name, None::<StartContainerOptions>).await {
            Ok(_) => tracing::info!("Docker: Container {} started.", container_name),
            Err(DockerError::DockerResponseServerError { status_code: 304, .. }) => {
                tracing::info!("Docker: Container {} is already running.", container_name);
            }
            Err(e) => return Err(e.into()),
        }

        Ok(ContainerHandle { id })
    }

    /// Stops and removes a Docker container asynchronously.
    pub async fn stop_container(service_id: &str) -> Result<(), StopError> {
        tracing::info!(serviceId = service_id, "Docker: Stopping container.");

        let docker = Docker::connect_with_local_defaults()?;
        let container_name = format!("spn_{}", service_id.replace(|c: char| !c.is_alphanumeric(), "_"));

        // Asynchronous stop with a 10-second timeout
        let stop_options = Some(StopContainerOptions { signal: None, t: Some(10) });
        if let Err(e) = docker.stop_container(&container_name, stop_options).await {
            if let DockerError::DockerResponseServerError { status_code: 404, .. } = e {
                tracing::info!("Docker: Container {} not found.", container_name);
            } else {
                return Err(e.into());
            }
        } else {
            tracing::info!("Docker: Container {} stopped.", container_name);
        }

        // Forced removal (removes if stopped)
        let remove_options = Some(RemoveContainerOptions { force: true, ..Default::default() });
        if let Err(e) = docker.remove_container(&container_name, remove_options).await {
            if let DockerError::DockerResponseServerError { status_code: 404, .. } = e {
                // Already removed
            } else {
                tracing::warn!("Docker: Failed to remove container {}: {}", container_name, e);
            }
        } else {
            tracing::info!("Docker: Container {} removed.", container_name);
        }

        Ok(())
    }
}

/// --- Nomad Backend Implementation ---

mod nomad_backend {
    use super::*;
    use serde_json::json;

    /// Scales a Nomad task group to the specified count.
    pub async fn scale_task(config: &AvailabilityManagementConfig, count: i32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let urn = config._cluster_manager_urn.as_deref()
            .ok_or("Nomad cluster manager URN is missing")?;

        let base_url = urn.strip_prefix("nomad:")
            .ok_or("Invalid Nomad URN prefix (must start with 'nomad:')")?
            .trim_end_matches('/');

        let url = format!("{}/scale", base_url);
        let group_id = &config.image;

        tracing::info!(
            url = %url,
            group = group_id,
            count = count,
            "Nomad: Scaling task."
        );

        let body = json!({
            "Target": { "Group": group_id },
            "Count": count,
            "ErrorOnConflict": false
        });
        tracing::debug!("Nomad API Request Body: {}", serde_json::to_string(&body).unwrap_or_default());

        let client = reqwest::Client::new();
        let response = client.post(url).json(&body).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Empty response body".to_string());
            tracing::error!("Nomad API error response: status={}, body={}", status, error_text);
            return Err(format!("Nomad API error ({}): {}", status, error_text).into());
        }

        Ok(())
    }
}
