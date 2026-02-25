//! # SPN Hub Server
//!
//! `spn` is an infrastructure system for building and managing distributed component applications,
//! particularly those that are containerized. The system consists of two main parts that
//! work in tandem: `spn_hub` and `spn_agent`. This crate implements `spn_hub`.
//!
//! ## Usage
//! To run the hub with info-level logging:
//! `RUST_LOG=info cargo run`
//!
//! ## TODO
//! - Replace target provider on consumer reconnection.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use rustls::crypto::ring::default_provider;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{self, Duration, Instant};
use tracing::{Instrument, error, info, info_span, warn};
use tracing_subscriber::EnvFilter;

mod config;
mod microservice;
mod utils;

use crate::config::{AppConfig, ConfigHotReloadService, HubConfig, RealmConfig, load_initial_config};

const MAX_CONCURRENT_UNI_STREAMS: u8 = 0;
const DATAGRAM_RECEIVE_BUFFER_SIZE: usize = 1024 * 1024;

const KEEP_ALIVE_INTERVAL_SECS: u64 = 5;
const IDLE_TIMEOUT_SECS: u64 = 20;

const GRACEFUL_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Command-line arguments.
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

/// Holds service information looked up from the config.
#[derive(Clone, Debug)]
struct ServiceInfo {
    name: String,
    urn: String,
}

type HubKey = (String, String); // (RealmName, HubName)

#[derive(Clone, Copy, Debug)]
enum ShutdownMode {
    Graceful,
    Immediate,
}

struct RunningHub {
    handle: tokio::task::JoinHandle<()>,
    shutdown_tx: mpsc::Sender<ShutdownMode>,
    config: HubConfig,
    realm_ca_cert: String,
    endpoint: quinn::Endpoint,
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
    let (initial_config, initial_content) = load_initial_config(&args.config)?;
    let shared_config = Arc::new(ArcSwap::from_pointee(initial_config.clone()));

    // Start hot-reload service
    let reload_service = ConfigHotReloadService::new(args.config.clone(), shared_config.clone(), initial_content);

    //  QUIC setup
    default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let mut running_hubs: HashMap<HubKey, RunningHub> = HashMap::new();

    // Initial start
    reconcile_hubs(&initial_config, &mut running_hubs, shared_config.clone()).await;

    info!("All hubs started. Waiting for connections...");

    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    let shutdown_mode;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C (SIGINT) received, shutting down immediately...");
                shutdown_mode = ShutdownMode::Immediate;
                break;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received, shutting down gracefully...");
                shutdown_mode = ShutdownMode::Graceful;
                break;
            }
            _ = sigusr1.recv() => {
                info!("SIGUSR1 received, reloading configuration...");
                if let Some(new_config) = reload_service.check_and_reload().await {
                    reconcile_hubs(&new_config, &mut running_hubs, shared_config.clone()).await;
                }
            }
        }
    }

    // Wait for all servers to finish
    for (_, hub) in running_hubs {
        let _ = hub.shutdown_tx.send(shutdown_mode).await;
        let _ = hub.handle.await;
    }

    Ok(())
}

async fn reconcile_hubs(
    config: &AppConfig,
    running_hubs: &mut HashMap<HubKey, RunningHub>,
    shared_config: Arc<ArcSwap<AppConfig>>,
) {
    // 1. Identify hubs that need to be stopped (removed or port changed)
    let mut to_stop = Vec::new();
    for (key, running_hub) in running_hubs.iter_mut() {
        let (realm_name, hub_name) = key;

        // Find corresponding hub in new config
        let new_config_entry = config.realms.iter()
            .find(|r| r.realm_name == *realm_name && !r.disabled)
            .and_then(|r| r.hubs.iter().find(|h| h.name == *hub_name).map(|h| (r, h)));

        match new_config_entry {
            None => {
                // Not found in new config (or realm disabled) -> Remove
                to_stop.push(key.clone());
            },
            Some((new_realm, new_hub)) => {
                // Check if restart is needed (Address/Port change)
                if running_hub.config.server_address != new_hub.server_address ||
                   running_hub.config.server_port != new_hub.server_port {
                    info!("Network configuration changed for hub: {} (Realm: {}). Restarting...", hub_name, realm_name);
                    to_stop.push(key.clone());
                } else {
                    // Check if certificate update is needed
                    if running_hub.config.server_cert != new_hub.server_cert ||
                       running_hub.config.server_cert_key != new_hub.server_cert_key ||
                       running_hub.realm_ca_cert != new_realm.realm_ca_cert {
                        info!("Certificate changed for hub: {}. Reloading certificates...", hub_name);
                        match utils::load_certs_and_key_from_strings(&new_hub.server_cert, &new_hub.server_cert_key, &new_realm.realm_ca_cert) {
                            Ok((certs, key, truststore)) => {
                                match utils::create_server_config(certs, key, truststore, &[b"sc01-provider", b"sc01-consumer"]) {
                                    Ok(server_config) => {
                                        running_hub.endpoint.set_server_config(Some(server_config));
                                        info!("Certificates reloaded for hub: {}", hub_name);
                                    }
                                    Err(e) => {
                                        error!("Failed to create server config for hub {}: {}", hub_name, e);
                                        continue;
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to load certificates for hub {}: {}", hub_name, e);
                                continue;
                            }
                        }
                    }

                    // Update stored config state
                    running_hub.config = new_hub.clone();
                    running_hub.realm_ca_cert = new_realm.realm_ca_cert.clone();
                }
            }
        }
    }

    // 2. Stop removed/restarting hubs
    for k in to_stop {
        if let Some(hub) = running_hubs.remove(&k) {
            info!("Stopping hub: {} (Realm: {})", k.1, k.0);
            let _ = hub.shutdown_tx.send(ShutdownMode::Graceful).await;
            let _ = hub.handle.await; // Wait for release port
            info!("Hub stopped: {} (Realm: {})", k.1, k.0);
        }
    }

    // 3. Start new hubs
    for realm in &config.realms {
        if realm.disabled {
            info!("Skipping disabled realm: {}", realm.realm_name);
            continue;
        }
        for hub in &realm.hubs {
            let key = (realm.realm_name.clone(), hub.name.clone());
            if !running_hubs.contains_key(&key) {
                info!("Starting hub: {} (Realm: {})", hub.name, realm.realm_name);
                match start_hub(realm, hub, shared_config.clone()).await {
                    Ok(running_hub) => {
                        running_hubs.insert(key, running_hub);
                    }
                    Err(e) => {
                        error!("Failed to start hub {}: {}", hub.name, e);
                    }
                }
            }
        }
    }
}

async fn start_hub(
    realm: &RealmConfig,
    hub: &HubConfig,
    shared_config: Arc<ArcSwap<AppConfig>>,
) -> Result<RunningHub, Box<dyn std::error::Error>> {
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

    let provider_connections = Arc::new(RwLock::new(HashMap::new()));
    let consumer_connections = Arc::new(RwLock::new(HashMap::new()));

    let mut service_map: HashMap<String, ServiceInfo> = HashMap::new();
    for service in &hub.services {
        let service_info = ServiceInfo {
            name: service.name.clone(),
            urn: service.urn.clone(),
        };
        service_map.insert(service.provider.clone(), service_info.clone());
        for consumer in &service.consumers {
            service_map.insert(consumer.clone(), service_info.clone());
        }
    }
    info!("Service map for hub {}: {:?}", hub.name, service_map);
    let service_map = Arc::new(service_map);

    let server = Server::new(
        realm.realm_name.clone(),
        hub.name.clone(),
        endpoint.clone(),
        provider_connections,
        consumer_connections,
        service_map,
        shared_config,
    )?;

    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    let handle = tokio::spawn(async move {
        server.run(shutdown_rx).await;
    });

    Ok(RunningHub {
        handle,
        shutdown_tx,
        config: hub.clone(),
        realm_ca_cert: realm.realm_ca_cert.clone(),
        endpoint,
    })
}

/// Manages the overall lifecycle of the server.
struct Server {
    realm_name: String,
    hub_name: String,
    /// The QUIC endpoint bound to the server socket.
    endpoint: quinn::Endpoint,
    /// A map storing provider connections.
    /// Key: Service name -> Inner Key: Connection ID -> Value: Provider Entry.
    provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
    /// A map storing consumer connections.
    /// Key: Consumer URI (CN) -> Inner Key: Connection ID -> Value: QUIC connection.
    consumer_connections: Arc<RwLock<HashMap<String, HashMap<usize, ConsumerEntry>>>>,
    /// A map for looking up the service name associated with a given endpoint URI (CN).
    service_map: Arc<HashMap<String, ServiceInfo>>,
    /// Shared application configuration, used for features like on-demand start.
    shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
}

impl Server {
    /// Creates a new server instance.
    fn new(
        realm_name: String,
        hub_name: String,
        endpoint: quinn::Endpoint,
        provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
        consumer_connections: Arc<RwLock<HashMap<String, HashMap<usize, ConsumerEntry>>>>,
        service_map: Arc<HashMap<String, ServiceInfo>>,
        shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Listening on {} (Realm: {}, Hub: {})", endpoint.local_addr()?, realm_name, hub_name);
        Ok(Self {
            realm_name,
            hub_name,
            endpoint,
            provider_connections,
            consumer_connections,
            service_map,
            shared_config,
        })
    }

    /// Runs the main server loop to accept connections.
    async fn run(&self, mut shutdown_rx: mpsc::Receiver<ShutdownMode>) {
        info!("Server (Realm: {}, Hub: {}) is ready to accept connections.", self.realm_name, self.hub_name);

        let mut stats_interval = time::interval(Duration::from_secs(10));
        // Prevent tick buildup if processing lags
        stats_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = stats_interval.tick() => {
                    Self::report_stats(
                        &self.realm_name,
                        &self.hub_name,
                        &self.provider_connections,
                        &self.consumer_connections,
                        &self.service_map
                    ).await;
                }
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
                mode = shutdown_rx.recv() => {
                    let mode = mode.unwrap_or(ShutdownMode::Immediate);
                    match mode {
                        ShutdownMode::Graceful => {
                            info!("Shutdown signal received (Graceful), starting graceful shutdown.");

                            // Send notify_shutdown to all providers
                            {
                                let providers = self.provider_connections.read().await;
                                for (service_name, provider_map) in providers.iter() {
                            for entry in provider_map.values() {
                                info!("Sending notify_shutdown to provider: {} ({})", entry.uri, service_name);
                                        let _ = entry.connection.send_datagram(b"notify_shutdown".to_vec().into());
                                    }
                                }
                            }

                            // Send notify_shutdown to all consumers
                            {
                                let consumers = self.consumer_connections.read().await;
                                for (uri, consumer_map) in consumers.iter() {
                                    for (id, entry) in consumer_map.iter() {
                                        info!("Sending notify_shutdown to consumer: {} (ID: {})", uri, id);
                                        let _ = entry.connection.send_datagram(b"notify_shutdown".to_vec().into());
                                    }
                                }
                            }

                            // Wait for connections to drain
                            let timeout = GRACEFUL_SHUTDOWN_DRAIN_TIMEOUT;
                            let start = Instant::now();
                            info!("Waiting for connections to drain (timeout: {:?})", timeout);

                            loop {
                                if start.elapsed() >= timeout {
                                    warn!("Graceful shutdown timeout reached. Forcing close.");
                                    break;
                                }

                                let p_count = self.provider_connections.read().await.values().map(|m| m.len()).sum::<usize>();
                                let c_count = self.consumer_connections.read().await.values().map(|m| m.len()).sum::<usize>();

                                if p_count == 0 && c_count == 0 {
                                    info!("All connections drained.");
                                    break;
                                }
                                time::sleep(Duration::from_millis(500)).await;
                            }
                        }
                        ShutdownMode::Immediate => {
                            info!("Shutdown signal received (Immediate), shutting down.");
                        }
                    }
                    break;
                }
            }
        }
        // Close the endpoint to stop accepting new connections.
        // The integer code is an application-defined reason for closing. 0 is a generic "going away".
        self.endpoint.close(0u32.into(), b"server shutting down");

        // Wait for all connections to be gracefully shut down.
        self.endpoint.wait_idle().await;
        info!("Shutdown complete (Realm: {}, Hub: {}).", self.realm_name, self.hub_name);
    }

    /// Reports server statistics.
    async fn report_stats(
        realm_name: &str,
        hub_name: &str,
        providers: &Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
        consumers: &Arc<RwLock<HashMap<String, HashMap<usize, ConsumerEntry>>>>,
        service_map: &Arc<HashMap<String, ServiceInfo>>,
    ) {
        // 1. Create snapshots to minimize lock duration
        let (provider_snapshot, consumer_snapshot, provider_count, consumer_count) = {
            let providers_lock = providers.read().await;
            let consumers_lock = consumers.read().await;

            let provider_count: usize = providers_lock.values().map(|v| v.len()).sum();
            let consumer_count: usize = consumers_lock.values().map(|v| v.len()).sum();

            let provider_snapshot: Vec<_> = providers_lock
                .iter()
                .flat_map(|(service, map)| {
                    map.values().map(|entry| {
                        (service.clone(), entry.uri.clone(), entry.connection.clone(), entry.status.clone())
                    })
                })
                .collect();

            let consumer_snapshot: Vec<_> = consumers_lock
                .iter()
                .flat_map(|(uri, conns)| {
                    conns.iter().map(move |(_id, entry)| (uri.clone(), entry.connection.clone()))
                })
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
            message = "Stats",
            realm = realm_name,
            hub = hub_name,
            total_connections = provider_count + consumer_count,
            tokio_workers,
            tokio_tasks,
            provider_connections = provider_count,
            consumer_connections = consumer_count,
        );

        // 2. Log stats outside the lock
        for (service, cn, conn, status) in provider_snapshot {
            let stats = conn.stats();
            info!(
                type = "provider",
                realm = realm_name,
                hub = hub_name,
                service,
                cn,
                id = conn.stable_id(),
                status = ?status,
                rtt_ms = stats.path.rtt.as_millis(),
                lost_packets = stats.path.lost_packets,
                " -Provider"
            );
        }

        for (uri, conn) in consumer_snapshot {
            let stats = conn.stats();
            let service = service_map.get(&uri).map(|s| s.name.as_str()).unwrap_or("unknown");
            info!(
                type = "consumer",
                realm = realm_name,
                hub = hub_name,
                service,
                uri,
                id = conn.stable_id(),
                rtt_ms = stats.path.rtt.as_millis(),
                lost_packets = stats.path.lost_packets,
                " -Consumer"
            );
        }
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
    service_urn: String,
    stream_count: Arc<AtomicUsize>,
}

/// Represents the operational status of a provider.
#[derive(Clone, Debug, PartialEq)]
enum ProviderStatus {
    /// The provider is active and can accept new consumer streams.
    Active,
    /// The provider is shutting down and will not accept new consumer streams.
    ShuttingDown,
    /// The provider is waiting for the active provider to disconnect.
    StandBy,
}

/// Stores the provider's connection and its current status.
#[derive(Clone)]
struct ProviderEntry {
    connection: quinn::Connection,
    status: ProviderStatus,
    stream_count: Arc<AtomicUsize>,
    uri: String,
    created_at: DateTime<Utc>,
}

/// Stores the consumer's connection.
#[derive(Clone)]
struct ConsumerEntry {
    connection: quinn::Connection,
}

/// Handles connections from clients with the "provider" role.
/// Providers register themselves and wait for incoming requests (proxied streams).
struct ProviderHandler {
    context: ConnectionContext,
    provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
}

impl ProviderHandler {
    /// Creates a new provider handler.
    fn new(
        connection: quinn::Connection,
        cn: String,
        provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
        service_map: Arc<HashMap<String, ServiceInfo>>,
        _shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
    ) -> Self {
        let now = Utc::now();
        let conn_id = connection.stable_id();
        let service_info = service_map
            .get(&cn)
            .cloned()
            .unwrap_or_else(|| ServiceInfo {
                name: "unknown".to_string(),
                urn: "unknown".to_string(),
            });

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

        let endpoint_type = "serviceProvider".to_string();
        let context = ConnectionContext {
            connection: connection.clone(),
            start_at: now,
            connection_id: conn_id,
            uri: cn.clone(),
            endpoint_type: endpoint_type.clone(),
            service: service_info.name.clone(),
            service_urn: service_info.urn.clone(),
            stream_count: Arc::new(AtomicUsize::new(0)),
        };
        info!(
            eventType = "startSpnSession",
            timestamp = %context.start_at,
            spnSessionId = context.connection_id,
            spnEndPoint = &context.uri,
            endPointType = &context.endpoint_type,
            serviceUrn = &context.service_urn,
            remote = %context.connection.remote_address(),
            "SPN session (QUIC Connection) established"
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
        let connection_id = self.context.connection_id;
        let service_name = self.context.service.clone();
        let provider_connections = self.provider_connections.clone();

        tokio::spawn(async move {
            while let Ok(bytes) = datagram_conn.read_datagram().await {
                let message = String::from_utf8_lossy(&bytes);
                info!("Received control datagram from provider '{}': {:?}", provider_uri, message);

                match message.trim() {
                    "notify_shutdown" => {
                        info!("Provider '{}' notified graceful shutdown. Marking as ShuttingDown.", provider_uri);
                        let mut providers_by_service = provider_connections.write().await;
                        if let Some(providers_for_service) = providers_by_service.get_mut(&service_name) {
                            if let Some(provider_entry) = providers_for_service.get_mut(&connection_id) {
                                provider_entry.status = ProviderStatus::ShuttingDown;
                                info!("Provider '{}' status set to ShuttingDown. It will no longer accept new consumers.", provider_uri);
                            }
                        }
                        // The provider client is expected to close the connection after its own grace period.
                        // The connection.closed().await in the run() loop will handle the final cleanup.
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

        // Register the connection.
        {
            let mut providers_by_service = self.provider_connections.write().await;
            let service_map = providers_by_service
                .entry(self.context.service.clone())
                .or_default();

            // Check if there is ANY Active provider for this service
            let has_active = service_map.values().any(|v| v.status == ProviderStatus::Active);
            let status = if has_active { ProviderStatus::StandBy } else { ProviderStatus::Active };

            let entry = ProviderEntry {
                connection: self.context.connection.clone(),
                status: status.clone(),
                stream_count: self.context.stream_count.clone(),
                uri: self.context.uri.clone(),
                created_at: self.context.start_at,
            };
            service_map.insert(self.context.connection_id, entry);

            let total_services = providers_by_service.len();
            let total_providers: usize = providers_by_service.values().map(|v| v.len()).sum();
            info!(
                "Provider '{}' registered as {:?}. (Total services: {}, Total providers: {})",
                self.context.uri, status, total_services, total_providers
            );
            info!("Current provider connections state:");
            for (service, providers) in providers_by_service.iter() {
                for (conn_id, entry) in providers.iter() {
                    info!(
                        service = service.as_str(),
                        provider_cn = entry.uri.as_str(),
                        connection_id = conn_id,
                        status = ?entry.status
                    );
                }
            }
        }

        // Wait for the connection to be closed for any reason. This is the main lifetime of the handler.
        let reason = self.context.connection.closed().await;
        let stats = self.context.connection.stats();

        // Remove the connection from the shared map upon disconnection.
        {
            let mut providers_by_service = self.provider_connections.write().await;
            if let Some(providers_for_service) = providers_by_service.get_mut(&self.context.service)
            {
                if providers_for_service.remove(&self.context.connection_id).is_some() {
                    if providers_for_service.is_empty() {
                        providers_by_service.remove(&self.context.service);
                    }
                    let total_providers: usize = providers_by_service.values().map(|v| v.len()).sum();
                    info!(
                        "Provider '{}' removed from connection map. (Total providers remaining: {})",
                        self.context.uri, total_providers
                    );
                }
            }
        }

        log_connection_close(&self.context, &reason, stats);

        Ok(())
    }
}

/// Handles connections from clients with the "consumer" role.
/// Consumers initiate bidirectional streams to request data from providers.
struct ConsumerHandler {
    context: ConnectionContext,
    target_provider: Option<(quinn::Connection, Arc<AtomicUsize>)>,
    provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
    consumer_connections: Arc<RwLock<HashMap<String, HashMap<usize, ConsumerEntry>>>>,
    /// Provider URN
    provider_urn: Option<String>,
    /// Availability management configuration for provider.
    availability_config: Option<crate::config::AvailabilityManagementConfig>,
    /// Tracks if the first stream has been accepted.
    first_stream_accepted: bool,
}

/// Represents the outcome of the stream proxying loop.
enum ProxyLoopResult {
    /// A recoverable error related to the provider occurred (e.g., connection lost). The handler should attempt to find a new provider.
    ProviderError,
    /// A fatal error occurred, or the consumer connection was closed. The handler should terminate.
    ConnectionClosed(quinn::ConnectionError),
}

impl ConsumerHandler {
    /// Creates a new consumer handler.
    fn new(
        connection: quinn::Connection,
        cn: String,
        provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
        consumer_connections: Arc<RwLock<HashMap<String, HashMap<usize, ConsumerEntry>>>>,
        service_map: Arc<HashMap<String, ServiceInfo>>,
        shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
    ) -> Self {
        let now = Utc::now();
        let conn_id = connection.stable_id();
        let service_info = service_map
            .get(&cn)
            .cloned()
            .unwrap_or_else(|| ServiceInfo {
                name: "unknown".to_string(),
                urn: "unknown".to_string(),
            });
        let endpoint_type = "serviceConsumer".to_string();
        let context = ConnectionContext {
            connection: connection.clone(),
            start_at: now,
            connection_id: conn_id,
            uri: cn.clone(),
            endpoint_type: endpoint_type.clone(),
            service: service_info.name.clone(),
            service_urn: service_info.urn.clone(),
            stream_count: Arc::new(AtomicUsize::new(0)),
        };
        info!(
            eventType = "startSpnSession",
            timestamp = %context.start_at,
            spnSessionId = context.connection_id,
            spnEndPoint = &context.uri,
            endPointType = &context.endpoint_type,
            serviceUrn = &context.service_urn,
            remote = %context.connection.remote_address(),
            "SPN session (QUIC Connection) established"
        );

        // Extract configuration needed for consumer handling
        let config = shared_config.load();
        let service_config = config
            .realms
            .iter()
            .flat_map(|r| &r.hubs)
            .flat_map(|h| &h.services)
            .find(|s| s.name == context.service);

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

    /// Executes the on-demand start logic for a provider.
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
    /// retrying periodically until one is found or the timeout is reached.
    async fn find_and_set_target_provider(&mut self, interval: Duration, timeout: Duration) {
        let start_time = Instant::now();
        info!(
            "Searching for provider for service '{}' (timeout: {:?}, interval: {:?})",
            self.context.service, timeout, interval
        );
        let mut start_attempted = false;

        loop {
            // 1. Try to find an Active provider (Read Lock)
            let found_active = {
                let providers = self.provider_connections.read().await;
                providers.get(&self.context.service)
                    .and_then(|map| map.values().find(|e| e.status == ProviderStatus::Active))
                    .map(|e| (e.uri.clone(), e.connection.clone(), e.stream_count.clone()))
            };

            if let Some((cn, conn, count)) = found_active {
                info!("Found matching provider '{}' for service '{}'.", cn, self.context.service);
                self.target_provider = Some((conn, count));
                return;
            }

            // 2. If no Active found, try to promote a StandBy provider (Write Lock)
            let promoted = {
                let mut providers = self.provider_connections.write().await;
                let service_map = providers.entry(self.context.service.clone()).or_default();

                // Double check Active (race condition)
                if let Some(active) = service_map.values().find(|e| e.status == ProviderStatus::Active) {
                     Some((active.uri.clone(), active.connection.clone(), active.stream_count.clone()))
                } else {
                    // Find a StandBy provider to promote
                    let standby_key = service_map.iter()
                        .filter(|(_, e)| e.status == ProviderStatus::StandBy)
                        .min_by_key(|(_, e)| e.created_at)
                        .map(|(k, _)| *k);

                    if let Some(key) = standby_key {
                        if let Some(entry) = service_map.get_mut(&key) {
                            entry.status = ProviderStatus::Active;
                            info!("Promoted provider '{}' to Active for service '{}'", entry.uri, self.context.service);
                            Some((entry.uri.clone(), entry.connection.clone(), entry.stream_count.clone()))
                        } else { None }
                    } else {
                        None
                    }
                }
            };

            if let Some((_, conn, count)) = promoted {
                self.target_provider = Some((conn, count));
                return;
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

    /// Manages the proxying of streams for a single, established provider connection.
    ///
    /// This function contains the primary `select!` loop that accepts new streams from the consumer
    /// and monitors for errors reported by the individual stream proxy tasks.
    async fn proxy_streams_with_provider(
        &mut self,
        provider_conn: quinn::Connection,
        provider_stream_count: Arc<AtomicUsize>,
    ) -> ProxyLoopResult {
        /// Internal enum to distinguish between different kinds of stream proxy errors,
        /// allowing the loop to decide how to react.
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
                            self.context.stream_count.fetch_add(1, Ordering::Relaxed);
                            let consumer_context = self.context.clone();
                            let tx_clone = error_tx.clone();
                            let provider_conn_clone = provider_conn.clone();
                            let provider_stream_count_clone = provider_stream_count.clone();
                            tokio::spawn(async move {
                                let stream_id = recv.id();
                                let connection_id = consumer_context.connection_id;

                                if let Err(e) = proxy_consumer_stream_to_provider(
                                    send,
                                    recv,
                                    provider_conn_clone,
                                    provider_stream_count_clone,
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

    /// Executes the main logic for handling a consumer connection.
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
            let mut consumers_by_uri = self.consumer_connections.write().await;
            let entry = ConsumerEntry { connection: self.context.connection.clone() };
            consumers_by_uri
                .entry(self.context.uri.clone())
                .or_default()
                .insert(self.context.connection_id, entry);
            let total_consumers: usize = consumers_by_uri.values().map(|v| v.len()).sum();
            info!(
                "Consumer '{}' added to connection map. (Total: {})",
                self.context.uri, total_consumers
            );
        }

        let reason = 'main_loop: loop {
            // 1. Find a provider.
            let search_interval = Duration::from_secs(1);
            let search_timeout = Duration::from_secs(600);
            self.find_and_set_target_provider(search_interval, search_timeout)
                .await;

            let (provider_conn, provider_stream_count) = match self.target_provider.clone() {
                Some(val) => val,
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
            match self.proxy_streams_with_provider(provider_conn, provider_stream_count).await {
                ProxyLoopResult::ProviderError => {
                    // A recoverable provider error occurred, loop again to find a new one.
                    // Brief pause to avoid busy loop if the broken provider is not yet removed from the map.
                    time::sleep(Duration::from_millis(500)).await;
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
            let mut consumers_by_uri = self.consumer_connections.write().await;
            if let Some(conns_for_uri) = consumers_by_uri.get_mut(&self.context.uri) {
                conns_for_uri.remove(&self.context.connection_id);
                if conns_for_uri.is_empty() {
                    consumers_by_uri.remove(&self.context.uri);
                }
            }
            let total_consumers: usize = consumers_by_uri.values().map(|v| v.len()).sum();
            info!(
                "Consumer '{}' removed from connection map. (Total remaining: {})",
                self.context.uri, total_consumers
            );
        }

        let stats = self.context.connection.stats();
        log_connection_close(&self.context, &reason, stats);

        Ok(())
    }
}

/// Forwards data between a consumer's stream and a new stream opened to a provider.
/// This function acts as a proxy for a single request/response interaction.
async fn proxy_consumer_stream_to_provider(
    mut consumer_send: quinn::SendStream,
    mut consumer_recv: quinn::RecvStream,
    provider_conn: quinn::Connection,
    provider_stream_count: Arc<AtomicUsize>,
    consumer_context: ConnectionContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //let stream_id = consumer_recv.id();
    // Consumer-side identifiers
    let consumer_connection_id = consumer_context.connection_id;
    let consumer_stream_id = consumer_recv.id();

    // Provider-side identifiers
    let provider_connection_id = provider_conn.stable_id();
    let (mut provider_send, mut provider_recv) = provider_conn.open_bi().await?;
    provider_stream_count.fetch_add(1, Ordering::Relaxed);
    let provider_stream_id = provider_send.id();
    let spn_connection_id = format!("{}-{}", consumer_stream_id, provider_stream_id);
    let start_at = Utc::now();

    info!(
        eventType = "startSpnConnection",
        timestamp = %start_at,
        spnConnectionId = &spn_connection_id,
        consumerSideSpnSessionId = consumer_connection_id,
        providerSideSpnSessionId = provider_connection_id,
        "SPN connection start"
    );

    // Proxy data in both directions concurrently.
    let consumer_to_provider = async {
        tokio::io::copy(&mut consumer_recv, &mut provider_send)
            .await
            .map_err(|e| (e, "Consumer->Provider"))
    };
    let provider_to_consumer = async {
        tokio::io::copy(&mut provider_recv, &mut consumer_send)
            .await
            .map_err(|e| (e, "Provider->Consumer"))
    };

    let result = tokio::try_join!(consumer_to_provider, provider_to_consumer);
    let duration = Utc::now() - start_at;

    match result {
        Ok((bytes_c2p, bytes_p2c)) => {
            info!(
                eventType = "endSpnConnection",
                timestamp = %Utc::now(),
                spnConnectionId = &spn_connection_id,
                consumerSideSpnSessionId = consumer_connection_id,
                providerSideSpnSessionId = provider_connection_id,
                totalSentBytes = bytes_c2p,
                totalReceiveBytes = bytes_p2c,
                elapsedTime = duration.num_milliseconds(),
                disconnectReason = "closed",
                "SPN connection (QUIC srream) finished"
            );
            // The streams will be closed automatically when they are dropped.
            Ok(())
        }
        Err((e, direction)) => { // This is (std::io::Error, &str)
            info!(
                eventType = "endSpnConnection",
                timestamp = %Utc::now(),
                spnConnectionId = &spn_connection_id,
                consumerSideSpnSessionId = consumer_connection_id,
                providerSideSpnSessionId = provider_connection_id,
                elapsedTime = duration.num_milliseconds(),
                disconnectReason = "error",
                error_direction = direction,
                error_details = %e,
                "SPN connection (QUIC srream) finished"
            );
            Err(e.into())
        }
    }
}

/// Maps a quinn::ConnectionError to a reason string defined in the spec.
fn map_reason_to_string(reason: &quinn::ConnectionError) -> &str {
    match reason {
        quinn::ConnectionError::ApplicationClosed(_) => "terminatedByPeer",
        quinn::ConnectionError::ConnectionClosed(_) => "terminatedByPeer",
        quinn::ConnectionError::LocallyClosed => "shutdown",
        _ => "error",
    }
}

/// Logs the details of a connection closure.
fn log_connection_close(
    context: &ConnectionContext,
    reason: &quinn::ConnectionError,
    _stats: quinn::ConnectionStats,
) {
    // Log the detailed reason for connection closure.
    match reason {
        quinn::ConnectionError::ApplicationClosed(app_close) => {
            info!(
                "{} connection for '{}' closed by the application. Code: {}, Reason: '{}'",
                context.endpoint_type,
                context.uri,
                app_close.error_code,
                String::from_utf8_lossy(&app_close.reason)
            );
        }
        quinn::ConnectionError::ConnectionClosed(conn_close) => {
            info!(
                "{} connection for '{}' closed by the peer. Code: {}, Reason: '{}'",
                context.endpoint_type,
                context.uri,
                conn_close.error_code,
                String::from_utf8_lossy(&conn_close.reason)
            );
        }
        quinn::ConnectionError::TimedOut => {
            warn!("{} connection for '{}' timed out.", context.endpoint_type, context.uri);
        }
        quinn::ConnectionError::LocallyClosed => {
            info!(
                "{} connection for '{}' was closed locally.",
                context.endpoint_type, context.uri
            );
        }
        quinn::ConnectionError::TransportError(transport_error) => {
            error!(
                "{} connection for '{}' failed due to a transport error. Code: {:?}, Reason: '{}'",
                context.endpoint_type, context.uri, transport_error.code, transport_error.reason
            );
        }
        other_error => {
            error!(
                "{} connection for '{}' closed with an unexpected error: {:?}",
                context.endpoint_type, context.uri, other_error
            );
        }
    }

    let duration = Utc::now() - context.start_at;
    let total_connections = context.stream_count.load(Ordering::Relaxed);
    let terminate_reason = map_reason_to_string(reason);

    info!(
        eventType = "endSpnSession",
        timestamp = %Utc::now(),
        spnSessionId = context.connection_id,
        spnEndPoint = &context.uri,
        endPointType = &context.endpoint_type,
        serviceUrn = &context.service_urn,
        totalConnectionCount = total_connections,
        elapsedTime = duration.num_seconds(),
        terminateReason = terminate_reason,
        "SPN session (QUIC Connection) closed"
    );
}
