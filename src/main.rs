// spn is an infrastructure system for building and managing distributed component applications,
// particularly those that are containerized. The spn system consists of two main parts that
// work in tandem: spn_hub and spn_agent. This is the source code for spn_hub.
//
// USAGE:
//   To run the hub with info-level logging:
//   RUST_LOG=info cargo run
//
// TODO:
//   - replace target provider on cunsumer, re-connected on provider
//   - Refactor utils.rs/create_quic_client_endpoint, which is currently marked as dead_code.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use clap::Parser;
use rustls::crypto::ring::default_provider;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{self, Duration, Instant};
use tracing::{Instrument, error, info, info_span, warn};
use tracing_subscriber::EnvFilter;

mod config;
mod microservice;
mod utils;

use crate::config::{ConfigHotReloadService, load_initial_config};

const MAX_CONCURRENT_UNI_STREAMS: u8 = 0;
const KEEP_ALIVE_INTERVAL_SECS: u64 = 50;
const DATAGRAM_RECEIVE_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Parser)]
struct Args {
    // command-line arguments or environment variables
    //#[arg(
    //    long,
    //    env = "SPNHUB_INVENTORY_URL",
    //    default_value = "192.168.10.130:2379"
    //)]
    // spn_inventory_url: String,
    #[arg(long, default_value = "conf/config.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // log
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .json()
        .with_current_span(false)
        .init();

    info!("Server started");

    // arg
    let args = Args::parse();

    // Load initial config
    let initial_config = load_initial_config(&args.config)?;
    let shared_config = Arc::new(ArcSwap::from_pointee(initial_config.clone()));

    // Start hot-reload service
    let reload_service = ConfigHotReloadService::new(args.config.clone(), shared_config.clone());
    tokio::spawn(async move {
        reload_service.start().await;
    });

    //  QUIC setup
    default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let config = shared_config.load();
    let mut handles = Vec::new();

    for realm in &config.realms {
        for hub in &realm.hubs {
            info!("Starting hub: {} (Realm: {})", hub.name, realm.realm_name);

            let (certs, key, truststore) = utils::load_certs_and_key_from_strings(
                &hub.server_cert,
                &hub.server_cert_key,
                &realm.realm_ca_cert,
            )?;

            let endpoint = utils::create_quic_server_endpoint(
                &hub.server_address,
                hub.server_port,
                certs,
                key,
                truststore,
                &[b"sc01-provider", b"sc01-consumer"],
            )?;

            // Create a shared state for provider connections and consumer connections
            let provider_connections = Arc::new(Mutex::new(HashMap::new()));
            let consumer_connections = Arc::new(Mutex::new(HashMap::new()));

            let mut service_map = HashMap::new();
            for service in &hub.services {
                service_map.insert(service.provider.clone(), service.name.clone());
                for consumer in &service.consumers {
                    service_map.insert(consumer.clone(), service.name.clone());
                }
            }
            info!("Service map for hub {}: {:?}", hub.name, service_map);
            let service_map = Arc::new(service_map);

            let server = Server::new(
                endpoint,
                provider_connections,
                consumer_connections,
                service_map,
                shared_config.clone(),
            )?;

            let handle = tokio::spawn(async move {
                server.run().await;
            });
            handles.push(handle);
        }
    }

    info!("All hubs started. Waiting for connections...");

    // Wait for Ctrl-C
    tokio::signal::ctrl_c().await?;
    info!("Ctrl-C received, shutting down...");

    // Wait for all servers to finish
    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

/// Manages the overall lifecycle of the server.
struct Server {
    /// The QUIC endpoint for the server.
    endpoint: quinn::Endpoint,
    /// A map storing provider connections.
    /// Key: Service name -> Inner Key: Provider URI (CN) -> Value: QUIC connection.
    provider_connections: Arc<Mutex<HashMap<String, HashMap<String, quinn::Connection>>>>,
    /// A map storing consumer connections.
    /// Key: Consumer URI (CN) -> Value: QUIC connection.
    consumer_connections: Arc<Mutex<HashMap<String, quinn::Connection>>>,
    /// A map for looking up the service name associated with a given URI (CN).
    service_map: Arc<HashMap<String, String>>,
    /// Shared application configuration for on-demand start.
    shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
}

impl Server {
    /// Creates a new server instance.
    fn new(
        endpoint: quinn::Endpoint,
        provider_connections: Arc<Mutex<HashMap<String, HashMap<String, quinn::Connection>>>>,
        consumer_connections: Arc<Mutex<HashMap<String, quinn::Connection>>>,
        service_map: Arc<HashMap<String, String>>,
        shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Listening on {}", endpoint.local_addr()?);
        Ok(Self {
            endpoint,
            provider_connections,
            consumer_connections,
            service_map,
            shared_config,
        })
    }

    /// Runs the main server loop to accept connections.
    async fn run(&self) {
        info!("Server is ready to accept connections.");

        // Spawn a background task for periodic statistics logging.
        let providers = self.provider_connections.clone();
        let consumers = self.consumer_connections.clone();
        let service_map = self.service_map.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(10));
            // Prevent tick buildup if processing lags
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                // 1. Create snapshots to minimize lock duration
                let (provider_snapshot, consumer_snapshot, provider_count, consumer_count) = {
                    let providers_lock = providers.lock().await;
                    let consumers_lock = consumers.lock().await;

                    let provider_count: usize = providers_lock.values().map(|v| v.len()).sum();
                    let consumer_count = consumers_lock.len();

                    let provider_snapshot: Vec<_> = providers_lock
                        .iter()
                        .flat_map(|(service, map)| {
                            map.iter()
                                .map(|(cn, conn)| (service.clone(), cn.clone(), conn.clone()))
                        })
                        .collect();

                    let consumer_snapshot: Vec<_> = consumers_lock
                        .iter()
                        .map(|(uri, conn)| (uri.clone(), conn.clone()))
                        .collect();

                    (
                        provider_snapshot,
                        consumer_snapshot,
                        provider_count,
                        consumer_count,
                    )
                }; // Locks are released here

                // Get tokio thread info (requires `tokio_unstable` feature).
                let tokio_workers = tokio::runtime::Handle::current().metrics().num_workers();
                let tokio_tasks = tokio::runtime::Handle::current()
                    .metrics()
                    .num_alive_tasks();

                info!(
                    message = "Server Stats",
                    total_connections = provider_count + consumer_count,
                    tokio_workers,
                    tokio_tasks,
                    provider_connections = provider_count,
                    consumer_connections = consumer_count,
                );

                // 2. Log stats outside the lock
                for (service, cn, conn) in provider_snapshot {
                    let stats = conn.stats();
                    info!(
                        type = "provider",
                        service,
                        cn,
                        id = conn.stable_id(),
                        rtt_ms = stats.path.rtt.as_millis(),
                        lost_packets = stats.path.lost_packets,
                        " - Provider connection stats"
                    );
                }

                for (uri, conn) in consumer_snapshot {
                    let stats = conn.stats();
                    let service = service_map
                        .get(&uri)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    info!(
                        type = "consumer",
                        service,
                        uri,
                        id = conn.stable_id(),
                        rtt_ms = stats.path.rtt.as_millis(),
                        lost_packets = stats.path.lost_packets,
                        " - Consumer connection stats"
                    );
                }
            }
        });

        loop {
            tokio::select! {
                Some(connecting) = self.endpoint.accept() => {
                    info!("Connection incoming from {}", connecting.remote_address());

                    let provider_connections = self.provider_connections.clone();
                    let consumer_connections = self.consumer_connections.clone();
                    let service_map = self.service_map.clone();
                    let shared_config = self.shared_config.clone();
                    // Spawn an asynchronous task for each new connection.
                    tokio::spawn(async move {
                        match connecting.await {
                            Ok(connection) => {
                                let span = info_span!(
                                    "connection",
                                    id = connection.stable_id(),
                                    remote = %connection.remote_address()
                                );

                                // The future created by the async block is instrumented with the span.
                                async move {
                                    // get connection information
                                    let (cert_cn_opt, alpn_opt) =
                                        utils::check_and_get_info_connection(connection.clone()).await;
                                    let (cn, alpn) = match (cert_cn_opt, alpn_opt) {
                                        (Some(cn), Some(alpn)) => (cn, alpn),
                                        _ => {
                                            warn!("Could not identify client by CN or ALPN. Closing connection.");
                                            // Close the connection with an application-defined error code (1).
                                            connection.close(1u32.into(), b"Missing CN or ALPN");
                                            return;
                                        }
                                    };

                                    info!("connected: cn={}, alpn={}", cn.clone(), alpn.clone());

                                    // Dispatch to the appropriate handler based on the ALPN protocol.
                                    let handle_result = match alpn.as_str() {
                                        "sc01-provider" => {
                                            let connection_id = connection.stable_id();
                                            ProviderHandler::new(
                                                connection.clone(),
                                                cn,
                                                provider_connections,
                                                service_map,
                                                shared_config.clone(),
                                            ).run()
                                                .instrument(info_span!("provider_handler", id = connection_id))
                                                .await
                                        }
                                        "sc01-consumer" => {
                                            // `handler` needs to be mutable because `run()` modifies its internal state
                                            // (e.g., `target_provider`).
                                            let connection_id = connection.stable_id();
                                            ConsumerHandler::new(
                                                connection.clone(),
                                                cn,
                                                provider_connections,
                                                consumer_connections,
                                                service_map,
                                                shared_config,
                                            ).run()
                                                .instrument(info_span!("consumer_handler", id = connection_id))
                                                .await
                                        }
                                        unsupported => {
                                            warn!(
                                                "Unsupported ALPN protocol: {}. Closing connection.",
                                                unsupported
                                            );
                                            connection.close(2u32.into(), b"Unsupported client role");
                                            Ok(()) // Return Ok to end the task for this connection gracefully.
                                        }
                                    };

                                    if let Err(e) = handle_result {
                                        error!("Connection handler failed: {}", e);
                                    }
                                }.instrument(span)
                                .await;
                            }
                            Err(e) => {
                                error!("Failed to establish connection: {}", e);
                            }
                        }
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl-C received, starting graceful shutdown.");
                    break;
                }
            }
        }
        // Close the endpoint to stop accepting new connections.
        // The integer code is an application-defined reason for closing. 0 is a generic "going away".
        self.endpoint.close(0u32.into(), b"server shutting down");

        // Wait for all connections to be gracefully shut down.
        self.endpoint.wait_idle().await;
        info!("Shutdown complete.");
    }
}

/// Holds contextual information for a single connection.
#[derive(Clone)]
struct ConnectionContext {
    connection: quinn::Connection,
    start_at: DateTime<Utc>,
    connection_id: usize,
    uri: String,
    endpoint_type: String,
    service: String,
}

/// Handles connections from clients with the "provider" role.
/// Providers send data over unidirectional streams.
struct ProviderHandler {
    context: ConnectionContext,
    provider_connections: Arc<Mutex<HashMap<String, HashMap<String, quinn::Connection>>>>,
}

impl ProviderHandler {
    /// Creates a new provider handler.
    fn new(
        connection: quinn::Connection,
        cn: String,
        provider_connections: Arc<Mutex<HashMap<String, HashMap<String, quinn::Connection>>>>,
        service_map: Arc<HashMap<String, String>>,
        _shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
    ) -> Self {
        let now = Utc::now();
        let conn_id = connection.stable_id();
        let service = service_map
            .get(&cn)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        // set idle timeout by availability management setting
        //let config = shared_config.load();
        //if let Some(service_config) = config.realms.iter()
        //    .flat_map(|r| &r.hubs)
        //    .flat_map(|h| &h.services)
        //    .find(|s| s.name == service)
        //{
        //    if service_config.availability_management.ondemand_start_on_payload {
        //        let idle_timeout = service_config.availability_management.idle_timeout;
        //        if idle_timeout > 0 {
        //            // connection.set_max_idle_timeout(Some(Duration::from_secs(idle_timeout)));
        //            warn!("Dynamic idle timeout setting is not supported by the current quinn version");
        //        }
        //    }
        //}

        let endpoint_type = "Provider".to_string();
        let context = ConnectionContext {
            connection: connection.clone(),
            start_at: now,
            connection_id: conn_id,
            uri: cn.clone(),
            endpoint_type: endpoint_type.clone(),
            service: service.clone(),
        };
        info!(
            type = &context.endpoint_type,
            uri = &context.uri,
            service = &context.service,
            id = context.connection_id,
            remote = %context.connection.remote_address(),
            start_at = %context.start_at,
            "QUIC Connection (spn session) established"
        );
        Self {
            context,
            provider_connections,
        }
    }

    /// Spawns a background task to listen for control datagrams.
    ///
    /// Supported control messages:
    /// - `notify_shutdown`: Notifies that the provider is starting a graceful shutdown.
    fn spawn_control_datagram_handler(&self) {
        let datagram_conn = self.context.connection.clone();
        let provider_uri = self.context.uri.clone();

        tokio::spawn(async move {
            while let Ok(bytes) = datagram_conn.read_datagram().await {
                let message = String::from_utf8_lossy(&bytes);
                info!("Received control datagram from provider '{}': {:?}", provider_uri, message);

                match message.trim() {
                    "notify_shutdown" => {
                        info!("Provider '{}' notified graceful shutdown start.", provider_uri);
                    }
                    _ => {
                        warn!("Unknown control message from provider '{}': {}", provider_uri, message);
                    }
                }
            }
        });
    }

    /// Runs a loop on the connection to accept streams from the provider.
    async fn run(&self) -> Result<(), quinn::ConnectionError> {
        // Start a background task to listen for control datagrams
        self.spawn_control_datagram_handler();

        // Add the connection to the shared map.
        {
            let mut providers_by_service = self.provider_connections.lock().await;
            providers_by_service
                .entry(self.context.service.clone())
                .or_default()
                .insert(self.context.uri.clone(), self.context.connection.clone());
            let total_services = providers_by_service.len();
            let total_providers: usize = providers_by_service.values().map(|v| v.len()).sum();
            info!(
                "Provider '{}' added to connection map. (Total services: {}, Total providers: {})",
                self.context.uri, total_services, total_providers
            );
            info!("Current provider connections state:");
            for (service, providers) in providers_by_service.iter() {
                for (cn, conn) in providers.iter() {
                    info!(
                        service = service.as_str(),
                        provider_cn = cn.as_str(),
                        connection_id = conn.stable_id()
                    );
                }
            }
        }

        // Wait for the connection to be closed for any reason. This is the main lifetime of the handler.
        let reason = self.context.connection.closed().await;
        let stats = self.context.connection.stats();
        // Remove the connection from the shared map upon disconnection.
        {
            let mut providers_by_service = self.provider_connections.lock().await;
            if let Some(providers_for_service) = providers_by_service.get_mut(&self.context.service)
            {
                providers_for_service.remove(&self.context.uri);
                // If this was the last provider for the service, remove the service entry itself.
                if providers_for_service.is_empty() {
                    providers_by_service.remove(&self.context.service);
                }
            }
            let total_providers: usize = providers_by_service.values().map(|v| v.len()).sum();
            info!(
                "Provider '{}' removed from connection map. (Total providers remaining: {})",
                self.context.uri, total_providers
            );
        }

        log_connection_close(
            &self.context.endpoint_type,
            &self.context.uri,
            &self.context.service,
            self.context.start_at,
            self.context.connection_id,
            &reason,
            stats,
        );

        Ok(())
    }
}

/// Handles connections from clients with the "consumer" role.
/// This is a placeholder for future implementation.
struct ConsumerHandler {
    context: ConnectionContext,
    target_provider: Option<quinn::Connection>,
    provider_connections: Arc<Mutex<HashMap<String, HashMap<String, quinn::Connection>>>>,
    consumer_connections: Arc<Mutex<HashMap<String, quinn::Connection>>>,
    /// Provider URN
    provider_urn: Option<String>,
    /// Availability management configuration for provider.
    availability_config: Option<crate::config::AvailabilityManagementConfig>,
    /// Tracks if the first stream has been accepted.
    first_stream_accepted: bool,
}

/// The outcome of the stream proxying loop, indicating why it terminated.
enum ProxyLoopResult {
    /// A recoverable error related to the provider occurred. The handler should try to find a new provider.
    ProviderError,
    /// A fatal error occurred, or the consumer connection was closed. This is the final reason for termination.
    ConnectionClosed(quinn::ConnectionError),
}

impl ConsumerHandler {
    /// Creates a new consumer handler.
    fn new(
        connection: quinn::Connection,
        cn: String,
        provider_connections: Arc<Mutex<HashMap<String, HashMap<String, quinn::Connection>>>>,
        consumer_connections: Arc<Mutex<HashMap<String, quinn::Connection>>>,
        service_map: Arc<HashMap<String, String>>,
        shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
    ) -> Self {
        let now = Utc::now();
        let conn_id = connection.stable_id();
        let service = service_map
            .get(&cn)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let endpoint_type = "Consumer".to_string();
        let context = ConnectionContext {
            connection: connection.clone(),
            start_at: now,
            connection_id: conn_id,
            uri: cn.clone(),
            endpoint_type: endpoint_type.clone(),
            service: service.clone(),
        };
        info!(
            type = &context.endpoint_type,
            uri = &context.uri,
            service = &context.service,
            id = context.connection_id,
            remote = %context.connection.remote_address(),
            start_at = %context.start_at,
            "QUIC Connection (spn session) established"
        );

        // Extract configuration needed for consumer handling
        let config = shared_config.load();
        let service_config = config
            .realms
            .iter()
            .flat_map(|r| &r.hubs)
            .flat_map(|h| &h.services)
            .find(|s| s.name == service);

        let (provider_urn, availability_config) = match service_config {
            Some(s) => (
                Some(s.provider.clone()),
                Some(s.availability_management.clone()),
            ),
            None => (None, None),
        };

        Self {
            context,
            target_provider: None,
            provider_connections,
            consumer_connections,
            provider_urn,
            availability_config,
            first_stream_accepted: false,
        }
    }

    /// Executes the on-demand start
    async fn execute_ondemand_start(
        urn: &str,
        am_config: &crate::config::AvailabilityManagementConfig,
        service_name: &str,
        trigger: &str,
    ) {
        let should_start = match trigger {
            "consumer" => am_config.ondemand_start_on_consumer,
            "payload" => am_config.ondemand_start_on_payload,
            _ => false,
        };

        if should_start {
            info!(
                "Starting container for provider (trigger: {}): {} (image: {})",
                trigger, urn, am_config.image
            );
            if let Err(e) = crate::microservice::start_provider(am_config).await {
                warn!(
                    "Failed to attempt on-demand start for service '{}' (URN: {}): {}",
                    service_name, urn, e
                );
            }
        } else {
            info!(
                "On-demand start ({}) is disabled for provider: {}",
                trigger, urn
            );
        }
    }

    /// Spawns a background task to listen for control datagrams.
    ///
    /// Supported control messages:
    /// - `request_provider_start`: Triggers on-demand provider start.
    /// - `notify_shutdown`: Notifies that the consumer is starting a graceful shutdown.
    fn spawn_control_datagram_handler(&self) {
        let datagram_conn = self.context.connection.clone();
        let provider_urn = self.provider_urn.clone();
        let availability_config = self.availability_config.clone();
        let service_name = self.context.service.clone();
        let consumer_uri = self.context.uri.clone();

        tokio::spawn(async move {
            // Wait for datagrams (signals) from the consumer in a loop
            while let Ok(bytes) = datagram_conn.read_datagram().await {
                let message = String::from_utf8_lossy(&bytes);
                info!("Received control datagram from consumer '{}': {:?}", consumer_uri, message);

                match message.trim() {
                    "request_provider_start" => {
                        if let (Some(urn), Some(am_config)) = (&provider_urn, &availability_config) {
                            let urn = urn.clone();
                            let am_config = am_config.clone();
                            let service_name = service_name.clone();
                            tokio::spawn(async move {
                                Self::execute_ondemand_start(
                                    &urn,
                                    &am_config,
                                    &service_name,
                                    "payload"
                                ).await;
                            });
                        }
                    }
                    "notify_shutdown" => {
                        info!("Consumer '{}' notified graceful shutdown start.", consumer_uri);
                    }
                    _ => {
                        warn!("Unknown control message from consumer '{}': {}", consumer_uri, message);
                    }
                }
            }
        });
    }

    /// Finds a provider with the same service and sets it as the target,
    /// retrying periodically until one is found or a timeout is reached.
    async fn find_and_set_target_provider(&mut self, interval: Duration, timeout: Duration) {
        let start_time = Instant::now();
        info!(
            "Searching for provider for service '{}' (timeout: {:?}, interval: {:?})",
            self.context.service, timeout, interval
        );
        let mut start_attempted = false;

        loop {
            // --- Lock Scope Start ---
            let found_provider = {
                let providers_by_service = self.provider_connections.lock().await;
                providers_by_service
                    .get(&self.context.service)
                    .and_then(|providers| providers.iter().next())
                    .map(|(cn, conn)| (cn.clone(), conn.clone()))
            }; // --- Lock Scope End ---

            if let Some((provider_cn, provider_conn)) = found_provider {
                info!(
                    "Found matching provider '{}' for service '{}'. Storing for later use.",
                    provider_cn, self.context.service
                );
                self.target_provider = Some(provider_conn);
                return; // Found it, exit the function.
            }

            // Attempt on-demand provider start on first consumer connected
            if !start_attempted {
                start_attempted = true;
                if let (Some(urn), Some(am_config)) =
                    (&self.provider_urn, &self.availability_config)
                {
                    let urn = urn.clone();
                    let am_config = am_config.clone();
                    let service = self.context.service.clone();
                    tokio::spawn(async move {
                        Self::execute_ondemand_start(&urn, &am_config, &service, "consumer").await;
                    });
                }
            }

            // Check for timeout
            if start_time.elapsed() >= timeout {
                warn!(
                    "Timed out waiting for a provider for service '{}' after {:?}",
                    self.context.service,
                    start_time.elapsed()
                );
                break; // Timeout reached, exit the loop.
            }

            // Wait for the next interval
            time::sleep(interval).await;
        }
    }

    /// Manages the proxying of all streams for a single, established provider connection.
    ///
    /// This function contains the primary `select!` loop that accepts new streams from the consumer
    /// and monitors for errors reported by the individual stream proxy tasks.
    async fn proxy_streams_with_provider(
        &mut self,
        provider_conn: quinn::Connection,
    ) -> ProxyLoopResult {
        /// Enum to distinguish between different kinds of stream proxy errors,
        /// so this loop can decide how to react. This is an implementation detail of this function.
        #[derive(Debug)]
        enum ProxyError {
            /// Indicates a problem with the provider connection, suggesting a retry might be needed.
            ProviderConnection(String),
            /// Indicates an error during data transfer for a specific stream.
            DataTransfer {
                msg: String,
                stream_id: quinn::StreamId,
            },
        }

        info!(
            "Starting to proxy streams to provider {}",
            provider_conn.stable_id()
        );
        // Channel for spawned tasks to signal errors back to this loop.
        let (error_tx, mut error_rx) = mpsc::channel::<ProxyError>(32);

        loop {
            tokio::select! {
                biased; // Prioritize checking for error signals.

                // An error was reported by a spawned stream proxy task.
                Some(proxy_error) = error_rx.recv() => {
                    match proxy_error {
                        ProxyError::ProviderConnection(msg) => {
                            warn!("Provider-side error detected: {}. Will try to find a new provider.", msg);
                            return ProxyLoopResult::ProviderError;
                        }
                        ProxyError::DataTransfer {msg, stream_id} => {
                            //ProxyError::DataTransfer(msg, stream_id) => {
                            // An error occurred on an individual stream (e.g., client closed it).
                            // This is not fatal to the connection. Log it and continue.
                            // The task handling that specific stream has already terminated.
                            warn!(
                                stream_id = %stream_id,
                                "Data transfer error on a stream: {}. The stream has been closed.", msg);
                        }
                    }
                }

                // Accept a new stream from the consumer.
                result = self.context.connection.accept_bi() => {
                    match result {
                        Ok((send, recv)) => {
                            if !self.first_stream_accepted {
                                info!("First stream accepted from consumer '{}'", self.context.uri);
                                self.first_stream_accepted = true;
                            }
                            info!("Bidirectional stream accepted from consumer '{}'", self.context.uri);
                            let consumer_context = self.context.clone();
                            let tx_clone = error_tx.clone();
                            let provider_conn_clone = provider_conn.clone();
                            tokio::spawn(async move {
                                let stream_id = recv.id();
                                let connection_id = consumer_context.connection_id;

                                if let Err(e) = proxy_consumer_stream_to_provider(
                                    send,
                                    recv,
                                    provider_conn_clone,
                                    consumer_context,
                                )
                                .instrument(info_span!(
                                    "consumer_stream",
                                    conn_id = connection_id,
                                    stream_id = %stream_id
                                ))
                                .await
                                {
                                    // Downcast the error to check its type
                                    if e.downcast_ref::<quinn::ConnectionError>().is_some() {
                                        // This is a provider-side connection error
                                        let _ = tx_clone
                                            .send(ProxyError::ProviderConnection(e.to_string()))
                                            .await;
                                    } else {
                                        // This is likely a data transfer (I/O) error
                                        let _ = tx_clone
                                            .send(ProxyError::DataTransfer {
                                                msg: e.to_string(),
                                                stream_id,
                                            })
                                            .await;
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            // The consumer connection itself was closed.
                            return ProxyLoopResult::ConnectionClosed(e);
                        }
                    }
                }
            }
        }
    }

    /// Runs the main consumer connection logic.
    ///
    /// This method orchestrates finding a provider and then handing off to the stream
    /// proxying loop. It will re-attempt to find a provider if the connection to an
    /// existing one fails.
    async fn run(mut self) -> Result<(), quinn::ConnectionError> {
        info!(
            "Consumer handler is running for '{}'. Searching for a provider with service '{}'.",
            self.context.uri, self.context.service
        );

        // Start a background task to listen for control datagram
        self.spawn_control_datagram_handler();

        // Add the connection to the shared map.
        {
            let mut consumers = self.consumer_connections.lock().await;
            consumers.insert(self.context.uri.clone(), self.context.connection.clone());
            info!(
                "Consumer '{}' added to connection map. (Total: {})",
                self.context.uri,
                consumers.len()
            );
        }

        let reason = 'main_loop: loop {
            // 1. Find a provider.
            let search_interval = Duration::from_secs(1);
            let search_timeout = Duration::from_secs(600);
            self.find_and_set_target_provider(search_interval, search_timeout)
                .await;

            let provider_conn = match self.target_provider.clone() {
                Some(conn) => conn,
                None => {
                    warn!(
                        "No active provider found for service '{}'. Closing connection.",
                        self.context.service
                    );
                    let app_close = quinn::ApplicationClose {
                        error_code: 100u32.into(), // Custom error code for "no provider found"
                        reason: b"No provider available for the requested service"
                            .to_vec()
                            .into(),
                    };
                    break 'main_loop quinn::ConnectionError::ApplicationClosed(app_close);
                }
            };

            // 2. Start proxying streams with the found provider.
            match self.proxy_streams_with_provider(provider_conn).await {
                ProxyLoopResult::ProviderError => {
                    // A recoverable provider error occurred, loop again to find a new one.
                    continue 'main_loop;
                }
                ProxyLoopResult::ConnectionClosed(e) => {
                    // A fatal error or normal connection closure occurred.
                    break 'main_loop e;
                }
            }
        };

        // Remove the connection from the shared map upon disconnection.
        {
            let mut consumers = self.consumer_connections.lock().await;
            consumers.remove(&self.context.uri);
            info!(
                "Consumer '{}' removed from connection map. (Total remaining: {})",
                self.context.uri,
                consumers.len()
            );
        }

        let stats = self.context.connection.stats();
        log_connection_close(
            &self.context.endpoint_type,
            &self.context.uri,
            &self.context.service,
            self.context.start_at,
            self.context.connection_id,
            &reason,
            stats,
        );

        Ok(())
    }
}

/// Forwards data between a consumer's stream and a new stream to a provider.
/// This function acts as a proxy for a single request.
async fn proxy_consumer_stream_to_provider(
    mut consumer_send: quinn::SendStream,
    mut consumer_recv: quinn::RecvStream,
    provider_conn: quinn::Connection,
    consumer_context: ConnectionContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let start_at = Utc::now();
    //let stream_id = consumer_recv.id();
    // Consumer-side identifiers
    let consumer_connection_id = consumer_context.connection_id;
    let consumer_stream_id = consumer_recv.id();

    // Provider-side identifiers
    let provider_connection_id = provider_conn.stable_id();
    let (mut provider_send, mut provider_recv) = provider_conn.open_bi().await?;
    let provider_stream_id = provider_send.id();

    info!(
        message = "QUIC stream proxy (spn con) start",
        start_at = %start_at,
        consumer_connection_id,
        consumer_stream_id = %consumer_stream_id,
        provider_connection_id,
        provider_stream_id = %provider_stream_id,
        endpoint_type = &consumer_context.endpoint_type,
        uri = &consumer_context.uri,
        service = &consumer_context.service,
        "Proxying stream"
    );

    // Proxy data in both directions concurrently.
    let consumer_to_provider = tokio::io::copy(&mut consumer_recv, &mut provider_send);
    let provider_to_consumer = tokio::io::copy(&mut provider_recv, &mut consumer_send);

    let result = tokio::try_join!(consumer_to_provider, provider_to_consumer);
    let duration = Utc::now() - start_at;

    match result {
        Ok((bytes_c2p, bytes_p2c)) => {
            info!(
                message = "QUIC stream proxy (spn con) finished",
                start_at = %start_at,
                duration_ms = duration.num_milliseconds(),
                consumer_connection_id,
                consumer_stream_id = %consumer_stream_id,
                provider_connection_id,
                provider_stream_id = %provider_stream_id,
                endpoint_type = &consumer_context.endpoint_type,
                uri = &consumer_context.uri,
                service = &consumer_context.service,
                total_sent_bytes = bytes_c2p,
                total_receive_bytes = bytes_p2c,
            );
        }
        Err(e) => {
            info!(
                message = "QUIC stream proxy (spn con) finished with error",
                start_at = %start_at,
                duration_ms = duration.num_milliseconds(),
                consumer_connection_id,
                consumer_stream_id = %consumer_stream_id,
                provider_connection_id,
                provider_stream_id = %provider_stream_id,
                endpoint_type = &consumer_context.endpoint_type,
                uri = &consumer_context.uri,
                service = &consumer_context.service,
                error = %e,
                "Stream proxying failed"
            );
            return Err(e.into());
        }
    }

    // The streams will be closed automatically when they are dropped.
    Ok(())
}

/// Logs the details of a connection closure.
fn log_connection_close(
    endpoint_type: &str,
    uri: &str,
    service: &str,
    start_at: DateTime<Utc>,
    connection_id: usize,
    reason: &quinn::ConnectionError,
    _stats: quinn::ConnectionStats,
) {
    // Log the detailed reason for connection closure.
    match reason {
        quinn::ConnectionError::ApplicationClosed(app_close) => {
            info!(
                "{} connection for '{}' closed by the application. Code: {}, Reason: '{}'",
                endpoint_type,
                uri,
                app_close.error_code,
                String::from_utf8_lossy(&app_close.reason)
            );
        }
        quinn::ConnectionError::ConnectionClosed(conn_close) => {
            info!(
                "{} connection for '{}' closed by the peer. Code: {}, Reason: '{}'",
                endpoint_type,
                uri,
                conn_close.error_code,
                String::from_utf8_lossy(&conn_close.reason)
            );
        }
        quinn::ConnectionError::TimedOut => {
            warn!("{} connection for '{}' timed out.", endpoint_type, uri);
        }
        quinn::ConnectionError::LocallyClosed => {
            info!(
                "{} connection for '{}' was closed locally.",
                endpoint_type, uri
            );
        }
        quinn::ConnectionError::TransportError(transport_error) => {
            error!(
                "{} connection for '{}' failed due to a transport error. Code: {:?}, Reason: '{}'",
                endpoint_type, uri, transport_error.code, transport_error.reason
            );
        }
        other_error => {
            error!(
                "{} connection for '{}' closed with an unexpected error: {:?}",
                endpoint_type, uri, other_error
            );
        }
    }

    let duration = Utc::now() - start_at;
    let total_streams = -1; // AI USO stats.uni_streams + stats.bi_streams;
    info!(
        type = endpoint_type,
        uri = uri,
        service = service,
        id = connection_id,
        duration_s = duration.num_seconds(),
        reason = ?reason,
        total_streams = total_streams,
        "QUIC Connection (spn session) closed"
    );
}
