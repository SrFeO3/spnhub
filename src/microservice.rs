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

use bollard::Docker;
use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{CreateContainerOptions, StartContainerOptions};
use bollard::errors::Error;

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
/// - `options`: Not raw options passed to `docker run`
async fn start_container(image: &str, _options: &str) -> Result<ContainerHandle, StartError> {
    tracing::info!("Starting container for image: {}...", image);

    let docker = Docker::connect_with_unix_defaults()?;

    // Generate a dedicated container name (e.g., "nginx:latest" -> "spn_nginx_latest")
    let container_name = format!("spn_{}", image.replace(|c: char| !c.is_alphanumeric(), "_"));

    // 1. Setup HostConfig
    let host_config = HostConfig {
        network_mode: Some("spnnet".to_string()),
        ..Default::default()
    };

    // 2. Container Config
    let config = ContainerCreateBody {
        image: Some(image.to_string()),
        host_config: Some(host_config),
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
        Err(Error::DockerResponseServerError { status_code: 409, .. }) => {
            // 409 Conflict: Container already exists.
            // We need to get the ID of the existing container.
            tracing::info!("Container {} already exists.", container_name);
            let inspect = docker.inspect_container(&container_name, None).await?;
            inspect.id.ok_or_else(|| StartError::Other("Container exists but has no ID".to_string()))?
        }
        Err(e) => {
            tracing::error!("Failed to create container {}: {}", container_name, e);
            return Err(e.into());
        }
    };

    // 4. Start
    if let Err(e) = docker.start_container(&container_name, None::<StartContainerOptions>).await {
        // 304 Not Modified: Container already started.
        if !matches!(e, Error::DockerResponseServerError { status_code: 304, .. }) {
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
    start_container(&config.image, "").await
}
