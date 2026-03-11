//! # Microservice Management
//!
//! This module acts as the control-plane responsible for the lifecycle of microservices.
//!
//! It handles:
//! - Spawning (starting) services.
//! - (Planned) Monitoring health (watching).
//! - (Planned) Stopping (graceful/forced shutdown).
//!
//! ## Runtime Assumptions
//! - Currently targets **Docker** as the container runtime.
//! - Future versions may support pluggable backends (e.g., containerd/CRI, Kubernetes).
//!
//! ## Concurrency Model
//! - Uses asynchronous APIs via `tokio` to avoid blocking the main event loop.
//!
//! ## API Surface
//! - `start_container`: Starts a container using a Docker image and options.
//!
//! ## Notes
//! - `options` is a list of strings (e.g., `["-p", "8080:80"]`).
//! - Health monitoring and stop APIs are pending implementation.

use std::collections::HashMap;

use bollard::Docker;
use bollard::errors::Error;
use bollard::models::{ContainerCreateBody, HostConfig, PortBinding};
use bollard::query_parameters::{CreateContainerOptions, RemoveContainerOptions, StartContainerOptions, StopContainerOptions};

use crate::config::AvailabilityManagementConfig;

/// A handle to a started container.
#[derive(Debug)]
pub struct ContainerHandle {
    /// The Docker container ID.
    pub id: String,
}

/// Errors that can occur during container startup.
#[derive(Debug)]
pub enum StartError {
    Docker(Error),
    Other(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Docker(e) => write!(f, "Docker error: {}", e),
            StartError::Other(e) => write!(f, "Error: {}", e),
        }
    }
}

impl std::error::Error for StartError {}

impl From<Error> for StartError {
    fn from(err: Error) -> Self {
        StartError::Docker(err)
    }
}

/// Errors that can occur during container shutdown.
#[derive(Debug)]
pub enum StopError {
    Docker(Error),
}

impl std::fmt::Display for StopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopError::Docker(e) => write!(f, "Docker error: {}", e),
        }
    }
}

impl std::error::Error for StopError {}

impl From<Error> for StopError {
    fn from(err: Error) -> Self {
        StopError::Docker(err)
    }
}

/// Starts a microservice container using Docker.
///
/// # Arguments
/// - `image`: Docker image tag/name (e.g., `"nginx:1.25"`).
/// - `options`: List of Docker CLI-like options (e.g., `["-p", "8080:80", "--network", "host"]`).
/// - `env`: Optional map of environment variables.
///
/// # Example Configuration (YAML)
/// ## Nginx Example
/// ```yaml
/// availabilityManagement:
///   image: "nginx:1.25"
///   options: ["-p", "8080:80", "--network", "host"]
///   env:
///     API_KEY: "secret"
///     DEBUG: "true"
/// ```
///
/// ## PostgreSQL Example
/// ```yaml
/// availabilityManagement:
///   image: "postgres:16"
///   options: "-p 5432:5432 -v /data/pgdata:/var/lib/postgresql/data"
///   env:
///     POSTGRES_PASSWORD: "mysecretpassword"
///     POSTGRES_USER: "spnuser"
///     POSTGRES_DB: "spndb"
/// ```
async fn start_container(
    image: &str,
    options: &[String],
    service_id: &str,
    env: Option<&HashMap<String, String>>,
    command: Option<&Vec<String>>,
) -> Result<ContainerHandle, StartError> {
    tracing::info!("Starting container for service: {}, image: {}, options: {:?}", service_id, image, options);

    let docker = Docker::connect_with_local_defaults()?;

    // Generate a dedicated container name from the unique service ID
    let container_name = format!("spn_{}", service_id.replace(|c: char| !c.is_alphanumeric(), "_"));

    // Parse options list to configure HostConfig
    let mut network_mode = None;
    let mut binds = Vec::new();
    let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
    let mut privileged = false;
    let mut cap_add = Vec::new();

    let parts = options;
    let mut i = 0;
    while i < parts.len() {
        match parts[i].as_str() {
            "-p" | "--publish" => {
                if i + 1 < parts.len() {
                    // Simple parser for host_port:container_port
                    if let Some((host, container)) = parts[i + 1].split_once(':') {
                        let container_port = format!("{}/tcp", container);
                        let binding = PortBinding {
                            host_ip: Some("0.0.0.0".to_string()),
                            host_port: Some(host.to_string()),
                        };
                        port_bindings
                            .entry(container_port)
                            .or_insert(None)
                            .get_or_insert_with(Vec::new)
                            .push(binding);
                    }
                    i += 1;
                }
            }
            "--network" => {
                if i + 1 < parts.len() {
                    network_mode = Some(parts[i + 1].to_string());
                    i += 1;
                }
            }
            "-v" | "--volume" => {
                if i + 1 < parts.len() {
                    binds.push(parts[i + 1].to_string());
                    i += 1;
                }
            }
            "--privileged" => privileged = true,
            "--cap-add" => {
                if i + 1 < parts.len() {
                    cap_add.push(parts[i + 1].to_string());
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    // Prepare environment variables
    let env_vars = env.map(|map| {
        map.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
    });

    // 1. Setup HostConfig
    let host_config = HostConfig {
        network_mode,
        binds: Some(binds),
        port_bindings: Some(port_bindings),
        privileged: Some(privileged),
        cap_add: Some(cap_add),
        ..Default::default()
    };

    tracing::info!("Service HostConfig: {:?}", host_config);
    tracing::info!("Service Env Vars: {:?}", env_vars);

    // 2. Container Config
    let config = ContainerCreateBody {
        image: Some(image.to_string()),
        host_config: Some(host_config),
        env: env_vars,
        cmd: command.cloned(),
        ..Default::default()
    };

    // 3. Create
    let create_options = CreateContainerOptions {
        name: Some(container_name.to_string()),
        ..Default::default()
    };

    tracing::info!("Creating/Checking container: {}...", container_name);
    let id = match docker.create_container(Some(create_options), config).await {
        Ok(container) => container.id,
        Err(Error::DockerResponseServerError {
            status_code: 409, ..
        }) => {
            // 409 Conflict: Container already exists.
            // We need to get the ID of the existing container.
            tracing::info!("Container {} already exists.", container_name);
            let inspect = docker.inspect_container(&container_name, None).await?;
            inspect
                .id
                .ok_or_else(|| StartError::Other("Container exists but has no ID".to_string()))?
        }
        Err(e) => {
            tracing::error!("Failed to create container {}: {}", container_name, e);
            if e.to_string().contains("Connect") || e.to_string().contains("Permission denied") {
                tracing::error!(
                    "Check permissions for /var/run/docker.sock. If running as non-root (appuser), ensure the user has access to the Docker socket."
                );
            }
            return Err(e.into());
        }
    };

    // 4. Start
    match docker
        .start_container(&container_name, None::<StartContainerOptions>)
        .await
    {
        Ok(_) => {
            tracing::info!("Container {} started successfully.", container_name);
        }
        Err(Error::DockerResponseServerError { status_code: 304, .. }) => {
            // 304 Not Modified: Container already started. This is not an error for our use case.
            tracing::info!("Container {} is already started.", container_name);
        }
        Err(e) => {
            // Any other error is fatal.
            tracing::error!("Failed to start container {}: {}", container_name, e);
            return Err(e.into());
        }
    }

    Ok(ContainerHandle { id })
}

/// Starts a container for the specified provider configuration.
///
/// This function looks up the container image associated with the provided URN
/// in the application configuration and starts it.
pub async fn start_provider(
    config: &AvailabilityManagementConfig,
) -> Result<ContainerHandle, StartError> {
    let result = start_container(
        &config.image,
        config.options.as_deref().unwrap_or(&[]),
        &config.service_id,
        config.env.as_ref(),
        config.command.as_ref(),
    )
    .await;

    match &result {
        Ok(handle) => tracing::info!("start_provider result: success, container_id={}", handle.id),
        Err(e) => tracing::info!("start_provider result: failure, error={}", e),
    }

    result
}

/// Stops and removes a microservice container using Docker.
///
/// # Arguments
/// - `config`: The availability management configuration containing the service ID.
pub async fn stop_provider(
    config: &AvailabilityManagementConfig,
) -> Result<(), StopError> {
    let service_id = &config.service_id;
    tracing::info!("Stopping container for service: {}", service_id);

    let docker = Docker::connect_with_local_defaults()?;

    let container_name = format!("spn_{}", service_id.replace(|c: char| !c.is_alphanumeric(), "_"));

    // Stop the container
    let stop_options = Some(StopContainerOptions{ signal: None, t: Some(10) }); // 10 second timeout
    if let Err(e) = docker.stop_container(&container_name, stop_options).await {
        if let Error::DockerResponseServerError { status_code: 404, .. } = e {
            tracing::info!("Container {} not found, assuming already stopped.", container_name);
        } else {
            tracing::error!("Failed to stop container {}: {}", container_name, e);
            return Err(e.into());
        }
    } else {
        tracing::info!("Container {} stopped successfully.", container_name);
    }

    // Remove the container
    let remove_options = Some(RemoveContainerOptions{ force: true, ..Default::default() });
    if let Err(e) = docker.remove_container(&container_name, remove_options).await {
         if let Error::DockerResponseServerError { status_code: 404, .. } = e {
            // Already removed, not an error.
         } else {
            tracing::warn!("Failed to remove container {}: {}", container_name, e);
         }
    } else {
        tracing::info!("Container {} removed successfully.", container_name);
    }

    Ok(())
}
