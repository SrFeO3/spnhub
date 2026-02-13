//! microservice.rs
////! Control-plane module responsible for the lifecycle of services:
//! - spawn (start)
//! - monitor health (watch)
//! - stop (graceful/forced shutdown)
//!
//! Runtime assumption:
//! - This version targets **Docker** as the container runtime.
//! - Future versions may introduce pluggable backends (e.g., containerd/CRI, Kubernetes).
//!
//! Concurrency model:
//! - Asynchronous APIs via `tokio` to avoid blocking the service itself.
//!
//! API surface (initial skeleton):
//! - `start_container(image: &str, options: &str) -> Result<ContainerHandle, StartError>`
//!   * Starts a container using a Docker image and an option string.
//!   * Returns success with a `ContainerHandle`, or failure with a reason (`StartError`).
//!
//! Notes:
//! - `options` is a raw string for now (e.g., `"--detach --rm --name svc-a -p 8080:80"`).
//!   Consider introducing a typed builder to avoid shell-arg pitfalls and injection risks.
//! - Health monitoring and stop APIs are intentionally left as TODOs in this skeleton.

use std::collections::HashMap;

use bollard::Docker;
use bollard::errors::Error;
use bollard::models::{ContainerCreateBody, HostConfig, PortBinding};
use bollard::query_parameters::{CreateContainerOptions, StartContainerOptions};

use crate::config::AvailabilityManagementConfig;

#[derive(Debug)]
pub struct ContainerHandle {
    pub id: String,
}

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

/// Start a microservice container using Docker.
///
/// # Arguments
/// - `image`: Docker image tag/name (e.g., `"nginx:1.25"`).
/// - `options`: Docker CLI-like options string (e.g., `"-p 8080:80 --network host"`)
/// - `env`: Optional environment variables map.
///
/// # Example Configuration (YAML)
/// ## Nginx Example
/// ```yaml
/// availabilityManagement:
///   image: "nginx:1.25"
///   options: "-p 8080:80 --network host"
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
    options: &str,
    env: Option<&HashMap<String, String>>,
) -> Result<ContainerHandle, StartError> {
    tracing::info!(
        "Starting container for image: {} with options: {}",
        image,
        options
    );

    let docker = Docker::connect_with_local_defaults()?;

    // Generate a dedicated container name (e.g., "nginx:latest" -> "spn_nginx_latest")
    let container_name = format!("spn_{}", image.replace(|c: char| !c.is_alphanumeric(), "_"));

    // Parse options string to configure HostConfig
    let mut network_mode = Some("spnnet".to_string());
    let mut binds = Vec::new();
    let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
    let mut privileged = false;
    let mut cap_add = Vec::new();

    let parts: Vec<&str> = options.split_whitespace().collect();
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
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

    // 2. Container Config
    let config = ContainerCreateBody {
        image: Some(image.to_string()),
        host_config: Some(host_config),
        env: env_vars,
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
    if let Err(e) = docker
        .start_container(&container_name, None::<StartContainerOptions>)
        .await
    {
        // 304 Not Modified: Container already started.
        if !matches!(
            e,
            Error::DockerResponseServerError {
                status_code: 304,
                ..
            }
        ) {
            tracing::error!("Failed to start container {}: {}", container_name, e);
            return Err(e.into());
        }
        tracing::info!("Container {} is already started.", container_name);
    } else {
        tracing::info!("Container {} started successfully.", container_name);
    }

    Ok(ContainerHandle { id })
}

/// Starts a container corresponding to the given provider URN.
///
/// This function looks up the container image associated with the provided URN
/// in the application configuration and starts it.
pub async fn start_provider(
    config: &AvailabilityManagementConfig,
) -> Result<ContainerHandle, StartError> {
    let result = start_container(
        &config.image,
        config.options.as_deref().unwrap_or(""),
        config.env.as_ref(),
    )
    .await;

    match &result {
        Ok(handle) => tracing::info!("start_provider result: success, container_id={}", handle.id),
        Err(e) => tracing::info!("start_provider result: failure, error={}", e),
    }

    result
}
