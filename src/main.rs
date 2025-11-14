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
//   - FIXME01 on contol session closing behavior
//   - Refactor utils.rs/create_quic_client_endpoint, which is currently marked as dead_code.

use chrono::{DateTime, Utc};
use clap::Parser;
use quinn::RecvStream;
use rustls::crypto::ring::default_provider;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time;
use tokio::time::Duration;
use tokio::time::Instant;
use tracing::Instrument;
use tracing::{error, info, info_span, warn};
use tracing_subscriber::EnvFilter;

mod utils;

const MAX_CONCURRENT_UNI_STREAMS: u8 = 0;
const KEEP_ALIVE_INTERVAL_SECS: u64 = 50;
const MAX_IDLE_TIMEOUT_SECS: u64 = 60;

#[derive(Parser)]
struct Args {
    // command-line arguments or environment variables
    #[arg(long, env = "SPNHUB_SERVER_ADDRESS", default_value = "0.0.0.0")]
    fc_server_address: String,
    #[arg(long, env = "SPNHUB_SERVER_PORT", default_value = "4433")]
    fc_server_port: u16,
    #[arg(
        long,
        env = "SPNHUB_INVENTORY_URL",
        default_value = "192.168.10.130:2379"
    )]
    fc_inventory_url: String,
    #[arg(
        long,
        env = "SPNHUB_SERVER_TRUST_CLIENT_CERTIFICATE_ROOT",
        default_value = "../cert_client/ca.pem"
    )]
    fc_server_trust_client_cert_ca: String,
    #[arg(
        long,
        env = "SPNHUB_SERVER_TLS_CERTIFICATE",
        default_value = "../cert_server/server-spnhub.pem"
    )]
    fc_server_tls_cert: String,
    #[arg(
        long,
        env = "SPNHUB_SERVER_TLS_CERTIFICATE_KEY",
        default_value = "../cert_server/server-key-spnhub.pem"
    )]
    fc_server_tls_cert_key: String,
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

    info!("Server started (Event-Driven Architecture)");

    // arg
    let args = Args::parse();
    let sc_server_address: &String = &args.fc_server_address;
    let sc_server_port: &u16 = &args.fc_server_port;
    let sc_inventory_url = &args.fc_inventory_url;
    let sc_server_turst_client_cert_ca: &String = &args.fc_server_trust_client_cert_ca;
    let sc_server_tls_cert: &String = &args.fc_server_tls_cert;
    let sc_server_tls_cert_key: &String = &args.fc_server_tls_cert_key;

    info!(
        "Command-line arguments parsed: {},{},{},{},{},{}",
        sc_server_address,
        sc_server_port,
        sc_inventory_url,
        sc_server_turst_client_cert_ca,
        sc_server_tls_cert,
        sc_server_tls_cert_key
    );

    //  QUIC setup
    default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let (certs, key, truststore) = utils::load_certs_and_key(
        sc_server_tls_cert,
        sc_server_tls_cert_key,
        sc_server_turst_client_cert_ca,
    )?;

    let endpoint = utils::create_quic_server_endpoint(
        &sc_server_address,
        *sc_server_port,
        certs,
        key,
        truststore,
        &[b"sc01-provider", b"sc01-consumer"],
    )?;

    info!("Run server");
    // Create a shared state for provider connections and consumer connections
    let provider_connections: Arc<Mutex<HashMap<String, HashMap<String, quinn::Connection>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let consumer_connections: Arc<Mutex<HashMap<String, quinn::Connection>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Test endpoint-uri and service map
    let mut service_map_data: HashMap<String, String> = HashMap::new();
    service_map_data.insert(
        "urn:chip-in:end-point:hub.master.TEST1ZONE:www-contents-server".to_string(),
        "www".to_string(),
    );
    service_map_data.insert(
        "urn:chip-in:end-point:hub.master.TEST1ZONE:www-gateway".to_string(),
        "www".to_string(),
    );
    service_map_data.insert(
        "urn:chip-in:end-point:hub.master.TEST1ZONE:database-server".to_string(),
        "db".to_string(),
    );
    service_map_data.insert(
        "urn:chip-in:end-point:hub.master.TEST1ZONE:database-client".to_string(),
        "db".to_string(),
    );
    service_map_data.insert(
        "urn:chip-in:end-point:hub.master.TEST1ZONE:api-server".to_string(),
        "api".to_string(),
    );
    service_map_data.insert(
        "urn:chip-in:end-point:hub.master.TEST1ZONE:api-gateway".to_string(),
        "api".to_string(),
    );
    service_map_data.insert(
        "urn:chip-in:end-point:hub.master.TEST1ZONE:auth-server".to_string(),
        "auth".to_string(),
    );
    service_map_data.insert(
        "urn:chip-in:end-point:hub.master.TEST1ZONE:auth-gateway".to_string(),
        "auth".to_string(),
    );
    let service_map = Arc::new(service_map_data);

    // Instantiate and run the server
    let server = Server::new(
        endpoint,
        provider_connections,
        consumer_connections,
        service_map,
    )?;
    server.run().await;

    Ok(())
}

/// Manages the overall lifecycle of the server.
struct Server {
    endpoint: quinn::Endpoint,
    provider_connections: Arc<Mutex<HashMap<String, HashMap<String, quinn::Connection>>>>,
    consumer_connections: Arc<Mutex<HashMap<String, quinn::Connection>>>,
    service_map: Arc<HashMap<String, String>>,
}

impl Server {
    /// Creates a new server instance.
    fn new(
        endpoint: quinn::Endpoint,
        provider_connections: Arc<Mutex<HashMap<String, HashMap<String, quinn::Connection>>>>,
        consumer_connections: Arc<Mutex<HashMap<String, quinn::Connection>>>,
        service_map: Arc<HashMap<String, String>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Listening on {}", endpoint.local_addr()?);
        Ok(Self {
            endpoint,
            provider_connections,
            consumer_connections,
            service_map,
        })
    }

    /// Runs the main server loop to accept connections.
    async fn run(&self) {
        info!("Server is ready to accept connections.");

        // Spawn a background task for periodic statistics logging.
        let providers = self.provider_connections.clone();
        let consumers = self.consumer_connections.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let providers_lock = providers.lock().await;
                let consumers_lock = consumers.lock().await;

                let provider_count: usize = providers_lock.values().map(|v| v.len()).sum();
                let consumer_count = consumers_lock.len();

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

                for (service, conns) in providers_lock.iter() {
                    for (cn, conn) in conns.iter() {
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
                }

                for (uri, conn) in consumers_lock.iter() {
                    let stats = conn.stats();
                    info!(
                        type = "consumer",
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
    ) -> Self {
        let now = Utc::now();
        let conn_id = connection.stable_id();
        let service = service_map
            .get(&cn)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
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

    /// Runs a loop on the connection to accept streams from the provider.
    async fn run(&self) -> Result<(), quinn::ConnectionError> {
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

        // No main function for data, only wait
        // but, accept the single control stream from the provider endpoint.
        // FIXME01: The termination of this control session incorrectly tears down the entire QUIC connection.
        match self.context.connection.accept_uni().await {
            Ok(stream) => {
                info!(
                    "Provider control stream accepted from '{}'",
                    self.context.uri
                );
                let span = info_span!("control_stream_handler");
                tokio::spawn(
                    handle_provider_control_stream(stream, self.context.clone()).instrument(span),
                );
            }
            Err(e) => {
                // If we fail to get the control stream, we can't proceed.
                // Log the error and let the connection close naturally.
                error!(
                    "Failed to accept provider control stream from '{}': {}. The connection will be closed.",
                    self.context.uri, e
                );
            }
        };

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
        Self {
            context,
            target_provider: None,
            provider_connections,
            consumer_connections,
        }
    }

    /// Finds a provider with the same service and sets it as the target,
    /// retrying periodically until one is found or a timeout is reached.
    async fn find_and_set_target_provider(&mut self, interval: Duration, timeout: Duration) {
        let start_time = Instant::now();
        info!(
            "Searching for provider for service '{}' (timeout: {:?}, interval: {:?})",
            self.context.service, timeout, interval
        );

        loop {
            // --- Lock Scope Start ---
            {
                let providers_by_service = self.provider_connections.lock().await;
                if let Some(providers_for_service) = providers_by_service.get(&self.context.service)
                {
                    // For simplicity, take the first available provider for this service.
                    if let Some((provider_cn, provider_conn)) = providers_for_service.iter().next()
                    {
                        info!(
                            "Found matching provider '{}' for service '{}'. Storing for later use.",
                            provider_cn, self.context.service
                        );
                        self.target_provider = Some(provider_conn.clone());
                        return; // Found it, exit the function.
                    }
                }
            } // --- Lock Scope End ---

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
            let search_timeout = Duration::from_secs(10);
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

/// Handles a single unidirectional control stream from a provider, reading event data and processing it.
async fn handle_provider_control_stream(mut stream: RecvStream, context: ConnectionContext) {
    let start_at = Utc::now();
    let stream_id = stream.id();
    info!(
        message = "Stream started",
        start_at = %start_at,
        connection_id = context.connection_id,
        stream_id = %stream_id,
        endpoint_type = &context.endpoint_type,
        uri = &context.uri,
        service = &context.service,
    );

    // Set a reasonable limit for the event size to prevent memory exhaustion.
    const MAX_EVENT_SIZE: usize = 1_024 * 1_024; // 1MB
    match stream.read_to_end(MAX_EVENT_SIZE).await {
        Ok(data) => {
            warn!(
                "Received {} bytes: {}",
                data.len(),
                String::from_utf8_lossy(&data)
            );
            // Here, you would deserialize and process the event data.
        }
        Err(e) => warn!("Failed to read data from stream: {}", e),
    }
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
