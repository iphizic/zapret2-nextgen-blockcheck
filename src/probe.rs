use crate::types::*;
use async_trait::async_trait;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName};
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Once},
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::process::Command;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpSocket,
    time::timeout,
};
use tokio_rustls::TlsConnector;

#[async_trait]
pub trait ProbeBackend: Send + Sync {
    async fn probe(&self, task: ProbeTask, ctx: ProbeContext) -> ProbeResult;
}

pub struct PreparedSocket {
    pub transport: PreparedTransport,
    pub assigned_source_port: u16,
}

pub enum PreparedTransport {
    Tcp(TcpSocket),
    Quic(Endpoint),
}

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("socket create failed: {0}")]
    SocketCreate(std::io::Error),
    #[error("bind failed: {0}")]
    Bind(std::io::Error),
    #[error("local_addr failed: {0}")]
    LocalAddr(std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsProbeVersion {
    Tls12,
    Tls13,
}

#[derive(Clone)]
pub struct NativeTcpTlsHttpProbe {
    pub bind_ipv4: IpAddr,
    pub bind_ipv6: IpAddr,

    tls12_config: Arc<ClientConfig>,
    tls13_config: Arc<ClientConfig>,
    tls_config_error: Option<Arc<String>>,
}

impl NativeTcpTlsHttpProbe {
    pub fn new(
        bind_ipv4: IpAddr,
        bind_ipv6: IpAddr,
        _max_read_bytes: usize,
        _user_agent: String,
    ) -> Self {
        install_rustls_provider();
        let (tls12_config, tls12_error) = build_tls_config(Vec::new(), TlsProbeVersion::Tls12);

        let (tls13_config, tls13_error) = build_tls_config(Vec::new(), TlsProbeVersion::Tls13);

        Self {
            bind_ipv4,
            bind_ipv6,
            tls12_config: Arc::new(tls12_config),
            tls13_config: Arc::new(tls13_config),
            tls_config_error: tls12_error.or(tls13_error).map(Arc::new),
        }
    }

    #[allow(dead_code)]
    pub fn with_extra_root_certs(mut self, certs: Vec<CertificateDer<'static>>) -> Self {
        install_rustls_provider();
        let (tls12_config, tls12_error) = build_tls_config(certs.clone(), TlsProbeVersion::Tls12);

        let (tls13_config, tls13_error) = build_tls_config(certs, TlsProbeVersion::Tls13);

        self.tls12_config = Arc::new(tls12_config);
        self.tls13_config = Arc::new(tls13_config);
        self.tls_config_error = tls12_error.or(tls13_error).map(Arc::new);

        self
    }

    #[allow(dead_code)]
    pub fn prepare_socket(&self, target_ip: IpAddr) -> Result<PreparedSocket, ProbeError> {
        self.prepare_tcp_socket(target_ip)
    }

    pub fn prepare_transport(
        &self,
        protocol: ProbeProtocol,
        target_ip: IpAddr,
    ) -> Result<PreparedSocket, ProbeError> {
        match protocol {
            ProbeProtocol::QuicHttp3Future => self.prepare_quic_endpoint(target_ip),
            _ => self.prepare_tcp_socket(target_ip),
        }
    }

    fn prepare_tcp_socket(&self, target_ip: IpAddr) -> Result<PreparedSocket, ProbeError> {
        let socket = match target_ip {
            IpAddr::V4(_) => TcpSocket::new_v4().map_err(ProbeError::SocketCreate)?,
            IpAddr::V6(_) => TcpSocket::new_v6().map_err(ProbeError::SocketCreate)?,
        };
        let bind_ip = match target_ip {
            IpAddr::V4(_) => self.bind_ipv4,
            IpAddr::V6(_) => self.bind_ipv6,
        };
        socket
            .bind(SocketAddr::new(bind_ip, 0))
            .map_err(ProbeError::Bind)?;
        let assigned_source_port = socket.local_addr().map_err(ProbeError::LocalAddr)?.port();
        Ok(PreparedSocket {
            transport: PreparedTransport::Tcp(socket),
            assigned_source_port,
        })
    }

    fn prepare_quic_endpoint(&self, target_ip: IpAddr) -> Result<PreparedSocket, ProbeError> {
        let bind_ip = match target_ip {
            IpAddr::V4(_) => self.bind_ipv4,
            IpAddr::V6(_) => self.bind_ipv6,
        };
        let endpoint = Endpoint::client(SocketAddr::new(bind_ip, 0)).map_err(ProbeError::Bind)?;
        let assigned_source_port = endpoint.local_addr().map_err(ProbeError::LocalAddr)?.port();
        Ok(PreparedSocket {
            transport: PreparedTransport::Quic(endpoint),
            assigned_source_port,
        })
    }

    pub async fn probe_with_prepared_socket(
        &self,
        task: ProbeTask,
        ctx: ProbeContext,
        prepared: PreparedSocket,
    ) -> ProbeResult {
        let total_start = Instant::now();
        let mut connect_ms = None;
        let remote = SocketAddr::new(task.target_ip, task.target_port);
        let assigned_source_port = prepared.assigned_source_port;

        if let Some(token) = &ctx.cancellation {
            if token.is_cancelled() {
                return cancelled_result(
                    &task,
                    ctx.qnum,
                    assigned_source_port,
                    total_start.elapsed().as_millis() as u64,
                );
            }
        }

        let socket = match prepared.transport {
            PreparedTransport::Tcp(socket) => socket,
            PreparedTransport::Quic(endpoint) => {
                return self
                    .quic_probe(task, ctx, assigned_source_port, endpoint, total_start)
                    .await
            }
        };

        let kind = probe_failure_kind(ctx.baseline);
        let connect_start = Instant::now();
        let stream = match cancellable_timeout(
            Duration::from_millis(task.timeouts.connect_ms),
            ctx.cancellation.as_ref(),
            socket.connect(remote),
        )
        .await
        {
            Ok(Ok(s)) => {
                connect_ms = Some(connect_start.elapsed().as_millis() as u64);
                s
            }
            Ok(Err(e)) => {
                return failure(
                    &task,
                    ctx.qnum,
                    assigned_source_port,
                    ProbeOutcome::Refused,
                    kind,
                    ProbeErrorClass::ConnectFailed,
                    e.to_string(),
                    total_start,
                    connect_ms,
                    None,
                    None,
                )
            }
            Err(ProbeWaitError::Timeout) => {
                return failure(
                    &task,
                    ctx.qnum,
                    assigned_source_port,
                    ProbeOutcome::Timeout,
                    kind,
                    ProbeErrorClass::ConnectTimeout,
                    "connect timeout",
                    total_start,
                    connect_ms,
                    None,
                    None,
                )
            }
            Err(ProbeWaitError::Cancelled) => {
                return cancelled_result(
                    &task,
                    ctx.qnum,
                    assigned_source_port,
                    total_start.elapsed().as_millis() as u64,
                )
            }
        };

        match task.protocol {
            ProbeProtocol::HttpPlain => {
                self.http_plain(
                    task,
                    ctx,
                    assigned_source_port,
                    stream,
                    total_start,
                    connect_ms,
                )
                .await
            }

            ProbeProtocol::Tls12Http11 => {
                self.https_http11(
                    task,
                    ctx,
                    assigned_source_port,
                    stream,
                    total_start,
                    connect_ms,
                    TlsProbeVersion::Tls12,
                )
                .await
            }

            ProbeProtocol::Tls13Http11 => {
                self.https_http11(
                    task,
                    ctx,
                    assigned_source_port,
                    stream,
                    total_start,
                    connect_ms,
                    TlsProbeVersion::Tls13,
                )
                .await
            }

            ProbeProtocol::QuicHttp3Future => failure(
                &task,
                ctx.qnum,
                assigned_source_port,
                ProbeOutcome::InternalError,
                FailureKind::InfrastructureFailure,
                ProbeErrorClass::InternalError,
                "QUIC probe reached TCP path unexpectedly",
                total_start,
                connect_ms,
                None,
                None,
            ),
        }
    }

    async fn quic_probe(
        &self,
        task: ProbeTask,
        ctx: ProbeContext,
        source_port: u16,
        mut endpoint: Endpoint,
        total_start: Instant,
    ) -> ProbeResult {
        let kind = probe_failure_kind(ctx.baseline);
        let mut quic_config = match build_quic_client_config() {
            Ok(config) => config,
            Err(e) => {
                return failure(
                    &task,
                    ctx.qnum,
                    source_port,
                    ProbeOutcome::InternalError,
                    FailureKind::InfrastructureFailure,
                    ProbeErrorClass::TlsFailed,
                    e,
                    total_start,
                    None,
                    None,
                    None,
                )
            }
        };
        quic_config.transport_config(Arc::new(quinn::TransportConfig::default()));
        endpoint.set_default_client_config(quic_config);

        let connect_start = Instant::now();
        let connecting = match endpoint.connect(
            SocketAddr::new(task.target_ip, task.target_port),
            &task.target_host,
        ) {
            Ok(connecting) => connecting,
            Err(e) => {
                return failure(
                    &task,
                    ctx.qnum,
                    source_port,
                    ProbeOutcome::InternalError,
                    FailureKind::InfrastructureFailure,
                    ProbeErrorClass::ConnectFailed,
                    e.to_string(),
                    total_start,
                    None,
                    None,
                    None,
                )
            }
        };

        let connection = match cancellable_timeout(
            Duration::from_millis(task.timeouts.connect_ms.max(task.timeouts.tls_ms)),
            ctx.cancellation.as_ref(),
            connecting,
        )
        .await
        {
            Ok(Ok(connection)) => connection,
            Ok(Err(e)) => {
                return failure(
                    &task,
                    ctx.qnum,
                    source_port,
                    ProbeOutcome::TlsAlert,
                    kind,
                    ProbeErrorClass::TlsFailed,
                    e.to_string(),
                    total_start,
                    None,
                    None,
                    None,
                )
            }
            Err(ProbeWaitError::Timeout) => {
                return failure(
                    &task,
                    ctx.qnum,
                    source_port,
                    ProbeOutcome::Timeout,
                    kind,
                    ProbeErrorClass::ConnectTimeout,
                    "QUIC connect timeout",
                    total_start,
                    None,
                    None,
                    None,
                )
            }
            Err(ProbeWaitError::Cancelled) => {
                return cancelled_result(
                    &task,
                    ctx.qnum,
                    source_port,
                    total_start.elapsed().as_millis() as u64,
                )
            }
        };
        let connect_ms = Some(connect_start.elapsed().as_millis() as u64);
        connection.close(0u32.into(), b"zapret-checker");
        endpoint.close(0u32.into(), b"zapret-checker");

        ProbeResult {
            strategy_id: task.strategy_id,
            worker_id: task.worker_id,
            qnum: if ctx.baseline { None } else { Some(ctx.qnum) },
            assigned_source_port: Some(source_port),
            target_host: task.target_host,
            target_ip: task.target_ip,
            target_port: task.target_port,
            protocol: task.protocol,
            path: task.request.path_and_query,
            method: task.request.method,
            read_mode: task.request.read_mode,
            setup_ms: None,
            connect_ms,
            tls_ms: connect_ms,
            first_byte_ms: None,
            total_ms: total_start.elapsed().as_millis() as u64,
            outcome: ProbeOutcome::Success,
            http_status: None,
            bytes_read: 0,
            header_bytes: 0,
            body_bytes: 0,
            failure_kind: None,
            error_class: None,
            error_message: None,
        }
    }

    async fn https_http11(
        &self,
        task: ProbeTask,
        ctx: ProbeContext,
        source_port: u16,
        stream: tokio::net::TcpStream,
        total_start: Instant,
        connect_ms: Option<u64>,
        tls_version: TlsProbeVersion,
    ) -> ProbeResult {
        let tls_start = Instant::now();
        if let Some(error) = &self.tls_config_error {
            return failure(
                &task,
                ctx.qnum,
                source_port,
                ProbeOutcome::InternalError,
                FailureKind::InfrastructureFailure,
                ProbeErrorClass::TlsFailed,
                error.as_ref().clone(),
                total_start,
                connect_ms,
                None,
                None,
            );
        }
        let tls_config = match tls_version {
            TlsProbeVersion::Tls12 => self.tls12_config.clone(),
            TlsProbeVersion::Tls13 => self.tls13_config.clone(),
        };

        let connector = TlsConnector::from(tls_config);
        let server_name = match ServerName::try_from(task.target_host.clone()) {
            Ok(s) => s,
            Err(e) => {
                return failure(
                    &task,
                    ctx.qnum,
                    source_port,
                    ProbeOutcome::TlsAlert,
                    FailureKind::InfrastructureFailure,
                    ProbeErrorClass::TlsFailed,
                    e.to_string(),
                    total_start,
                    connect_ms,
                    None,
                    None,
                )
            }
        };
        let kind = probe_failure_kind(ctx.baseline);
        let tls = match cancellable_timeout(
            Duration::from_millis(task.timeouts.tls_ms),
            ctx.cancellation.as_ref(),
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return failure(
                    &task,
                    ctx.qnum,
                    source_port,
                    ProbeOutcome::TlsAlert,
                    kind,
                    ProbeErrorClass::TlsFailed,
                    e.to_string(),
                    total_start,
                    connect_ms,
                    None,
                    None,
                )
            }
            Err(ProbeWaitError::Timeout) => {
                return failure(
                    &task,
                    ctx.qnum,
                    source_port,
                    ProbeOutcome::Timeout,
                    kind,
                    ProbeErrorClass::TlsTimeout,
                    "TLS timeout",
                    total_start,
                    connect_ms,
                    None,
                    None,
                )
            }
            Err(ProbeWaitError::Cancelled) => {
                return cancelled_result(
                    &task,
                    ctx.qnum,
                    source_port,
                    total_start.elapsed().as_millis() as u64,
                )
            }
        };
        let tls_ms = Some(tls_start.elapsed().as_millis() as u64);
        self.http_over_stream(task, ctx, source_port, tls, total_start, connect_ms, tls_ms)
            .await
    }

    async fn http_plain(
        &self,
        task: ProbeTask,
        ctx: ProbeContext,
        source_port: u16,
        stream: tokio::net::TcpStream,
        total_start: Instant,
        connect_ms: Option<u64>,
    ) -> ProbeResult {
        self.http_over_stream(
            task,
            ctx,
            source_port,
            stream,
            total_start,
            connect_ms,
            None,
        )
        .await
    }

    async fn http_over_stream<S>(
        &self,
        task: ProbeTask,
        ctx: ProbeContext,
        source_port: u16,
        mut stream: S,
        total_start: Instant,
        connect_ms: Option<u64>,
        tls_ms: Option<u64>,
    ) -> ProbeResult
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let kind = probe_failure_kind(ctx.baseline);
        let req = build_http_request(&task);
        if let Err(e) = stream.write_all(req.as_bytes()).await {
            return failure(
                &task,
                ctx.qnum,
                source_port,
                ProbeOutcome::EmptyResponse,
                kind,
                ProbeErrorClass::ReadFailed,
                e.to_string(),
                total_start,
                connect_ms,
                tls_ms,
                None,
            );
        }
        let first_byte_start = Instant::now();
        let max_read_bytes = task.request.max_read_bytes.max(1);
        let mut buf = Vec::with_capacity(max_read_bytes);
        let mut chunk = [0u8; 4096];
        let n = match cancellable_timeout(
            Duration::from_millis(task.timeouts.first_byte_ms),
            ctx.cancellation.as_ref(),
            stream.read(&mut chunk),
        )
        .await
        {
            Ok(Ok(0)) => {
                return failure(
                    &task,
                    ctx.qnum,
                    source_port,
                    ProbeOutcome::EmptyResponse,
                    kind,
                    ProbeErrorClass::ReadFailed,
                    "empty response",
                    total_start,
                    connect_ms,
                    tls_ms,
                    None,
                )
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                return failure(
                    &task,
                    ctx.qnum,
                    source_port,
                    ProbeOutcome::TcpReset,
                    kind,
                    ProbeErrorClass::ReadFailed,
                    e.to_string(),
                    total_start,
                    connect_ms,
                    tls_ms,
                    None,
                )
            }
            Err(ProbeWaitError::Timeout) => {
                return failure(
                    &task,
                    ctx.qnum,
                    source_port,
                    ProbeOutcome::Timeout,
                    kind,
                    ProbeErrorClass::FirstByteTimeout,
                    "first byte timeout",
                    total_start,
                    connect_ms,
                    tls_ms,
                    None,
                )
            }
            Err(ProbeWaitError::Cancelled) => {
                return cancelled_result(
                    &task,
                    ctx.qnum,
                    source_port,
                    total_start.elapsed().as_millis() as u64,
                )
            }
        };
        let first_byte_ms = Some(first_byte_start.elapsed().as_millis() as u64);
        buf.extend_from_slice(&chunk[..n.min(max_read_bytes)]);
        let mut read = parse_http_response_read(&buf, first_byte_ms);

        while !http_read_criteria_met(
            &read,
            task.request.method,
            task.request.read_mode,
            task.request.min_body_bytes,
        ) && buf.len() < max_read_bytes
        {
            if let Some(token) = &ctx.cancellation {
                if token.is_cancelled() {
                    return cancelled_result(
                        &task,
                        ctx.qnum,
                        source_port,
                        total_start.elapsed().as_millis() as u64,
                    );
                }
            }
            let elapsed_ms = total_start.elapsed().as_millis() as u64;
            if elapsed_ms >= task.timeouts.total_ms {
                if http_timeout_can_succeed(
                    &read,
                    task.request.method,
                    task.request.read_mode,
                    task.request.min_body_bytes,
                ) {
                    break;
                }
                return failure(
                    &task,
                    ctx.qnum,
                    source_port,
                    ProbeOutcome::Timeout,
                    kind,
                    ProbeErrorClass::ReadTimeout,
                    "read timeout",
                    total_start,
                    connect_ms,
                    tls_ms,
                    first_byte_ms,
                );
            }
            let remaining = max_read_bytes - buf.len();
            let read_len = remaining.min(chunk.len());
            let read_timeout_ms = (task.timeouts.total_ms - elapsed_ms).max(1);
            match cancellable_timeout(
                Duration::from_millis(read_timeout_ms),
                ctx.cancellation.as_ref(),
                stream.read(&mut chunk[..read_len]),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&chunk[..n]);
                    read = parse_http_response_read(&buf, first_byte_ms);
                }
                Ok(Err(e)) => {
                    if http_read_criteria_met(
                        &read,
                        task.request.method,
                        task.request.read_mode,
                        task.request.min_body_bytes,
                    ) {
                        break;
                    }
                    return failure(
                        &task,
                        ctx.qnum,
                        source_port,
                        ProbeOutcome::TcpReset,
                        kind,
                        ProbeErrorClass::ReadFailed,
                        e.to_string(),
                        total_start,
                        connect_ms,
                        tls_ms,
                        first_byte_ms,
                    );
                }
                Err(ProbeWaitError::Timeout) => {
                    if http_timeout_can_succeed(
                        &read,
                        task.request.method,
                        task.request.read_mode,
                        task.request.min_body_bytes,
                    ) {
                        break;
                    }
                    return failure(
                        &task,
                        ctx.qnum,
                        source_port,
                        ProbeOutcome::Timeout,
                        kind,
                        ProbeErrorClass::ReadTimeout,
                        "read timeout",
                        total_start,
                        connect_ms,
                        tls_ms,
                        first_byte_ms,
                    );
                }
                Err(ProbeWaitError::Cancelled) => {
                    return cancelled_result(
                        &task,
                        ctx.qnum,
                        source_port,
                        total_start.elapsed().as_millis() as u64,
                    )
                }
            }
        }

        let (outcome, error_class, error_message) = classify_http_response(
            read.status,
            read.headers_complete,
            read.body_bytes,
            task.request.method,
            task.request.read_mode,
            task.request.min_body_bytes,
        );
        let failure_kind = if outcome == ProbeOutcome::Success {
            None
        } else {
            Some(probe_failure_kind(ctx.baseline))
        };

        ProbeResult {
            strategy_id: task.strategy_id,
            worker_id: task.worker_id,
            qnum: if ctx.baseline { None } else { Some(ctx.qnum) },
            assigned_source_port: Some(source_port),
            target_host: task.target_host,
            target_ip: task.target_ip,
            target_port: task.target_port,
            protocol: task.protocol,
            path: task.request.path_and_query,
            method: task.request.method,
            read_mode: task.request.read_mode,
            setup_ms: None,
            connect_ms,
            tls_ms,
            first_byte_ms,
            total_ms: total_start.elapsed().as_millis() as u64,
            outcome,
            http_status: read.status,
            bytes_read: read.total_bytes,
            header_bytes: read.header_bytes,
            body_bytes: read.body_bytes,
            failure_kind,
            error_class,
            error_message,
        }
    }
}

fn http_timeout_can_succeed(
    read: &HttpResponseRead,
    method: HttpMethod,
    read_mode: ReadMode,
    min_body_bytes: usize,
) -> bool {
    if http_read_criteria_met(read, method, read_mode, min_body_bytes) {
        return true;
    }
    read_mode == ReadMode::Full
        && read.headers_complete
        && status_is_success(read.status)
        && read.body_bytes >= min_body_bytes
}

pub fn build_http_request(task: &ProbeTask) -> String {
    let path = if task.request.path_and_query.is_empty() {
        "/"
    } else {
        &task.request.path_and_query
    };
    format!(
        "{} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        task.request.method.as_str(),
        host_header(&task.target_host, task.target_port, task.protocol),
        task.request.user_agent,
    )
}

fn host_header(host: &str, port: u16, protocol: ProbeProtocol) -> String {
    if port == protocol.default_port() {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

fn install_rustls_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn build_tls_config(
    extra_root_certs: Vec<CertificateDer<'static>>,
    version: TlsProbeVersion,
) -> (ClientConfig, Option<String>) {
    let mut root_store = RootCertStore::empty();

    let cert_result = rustls_native_certs::load_native_certs();
    let error = if !cert_result.errors.is_empty() && cert_result.certs.is_empty() {
        Some(format!("{:?}", cert_result.errors))
    } else {
        None
    };

    for cert in cert_result.certs {
        let _ = root_store.add(cert);
    }

    for cert in extra_root_certs {
        let _ = root_store.add(cert);
    }

    let versions = match version {
        TlsProbeVersion::Tls12 => vec![&rustls::version::TLS12],
        TlsProbeVersion::Tls13 => vec![&rustls::version::TLS13],
    };

    let cfg = ClientConfig::builder_with_protocol_versions(&versions)
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (cfg, error)
}

fn build_quic_client_config() -> Result<QuinnClientConfig, String> {
    let mut root_store = RootCertStore::empty();
    let cert_result = rustls_native_certs::load_native_certs();
    if !cert_result.errors.is_empty() && cert_result.certs.is_empty() {
        return Err(format!("{:?}", cert_result.errors));
    }
    for cert in cert_result.certs {
        let _ = root_store.add(cert);
    }
    let mut crypto = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(root_store)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(crypto))
        .map_err(|e| e.to_string())?;
    Ok(QuinnClientConfig::new(Arc::new(crypto)))
}

#[async_trait]
impl ProbeBackend for NativeTcpTlsHttpProbe {
    async fn probe(&self, task: ProbeTask, ctx: ProbeContext) -> ProbeResult {
        let start = Instant::now();
        let total = Duration::from_millis(task.timeouts.total_ms);
        let mut result = match self.prepare_transport(task.protocol, task.target_ip) {
            Ok(prepared) => match cancellable_timeout(
                total,
                ctx.cancellation.as_ref(),
                self.probe_with_prepared_socket(task.clone(), ctx.clone(), prepared),
            )
            .await
            {
                Ok(result) => result,
                Err(ProbeWaitError::Timeout) => ProbeResult {
                    strategy_id: task.strategy_id.clone(),
                    worker_id: task.worker_id,
                    qnum: if ctx.baseline { None } else { Some(ctx.qnum) },
                    assigned_source_port: None,
                    target_host: task.target_host.clone(),
                    target_ip: task.target_ip,
                    target_port: task.target_port,
                    protocol: task.protocol,
                    path: task.request.path_and_query.clone(),
                    method: task.request.method,
                    read_mode: task.request.read_mode,
                    setup_ms: None,
                    connect_ms: None,
                    tls_ms: None,
                    first_byte_ms: None,
                    total_ms: start.elapsed().as_millis() as u64,
                    outcome: ProbeOutcome::Timeout,
                    http_status: None,
                    bytes_read: 0,
                    header_bytes: 0,
                    body_bytes: 0,
                    failure_kind: Some(probe_failure_kind(ctx.baseline)),
                    error_class: Some(ProbeErrorClass::ReadTimeout),
                    error_message: Some("total timeout".into()),
                },
                Err(ProbeWaitError::Cancelled) => ProbeResult {
                    strategy_id: task.strategy_id.clone(),
                    worker_id: task.worker_id,
                    qnum: if ctx.baseline { None } else { Some(ctx.qnum) },
                    assigned_source_port: None,
                    target_host: task.target_host.clone(),
                    target_ip: task.target_ip,
                    target_port: task.target_port,
                    protocol: task.protocol,
                    path: task.request.path_and_query.clone(),
                    method: task.request.method,
                    read_mode: task.request.read_mode,
                    setup_ms: None,
                    connect_ms: None,
                    tls_ms: None,
                    first_byte_ms: None,
                    total_ms: start.elapsed().as_millis() as u64,
                    outcome: ProbeOutcome::Cancelled,
                    http_status: None,
                    bytes_read: 0,
                    header_bytes: 0,
                    body_bytes: 0,
                    failure_kind: Some(FailureKind::Cancelled),
                    error_class: Some(ProbeErrorClass::Cancelled),
                    error_message: Some("cancelled".into()),
                },
            },
            Err(e) => ProbeResult::infrastructure_failure(
                &task,
                if ctx.baseline { None } else { Some(ctx.qnum) },
                None,
                ProbeErrorClass::BindFailed,
                e.to_string(),
                start.elapsed().as_millis() as u64,
            ),
        };
        if ctx.baseline {
            result.qnum = None;
        }
        result
    }
}

pub struct CurlProbeFallback;

#[async_trait]
impl ProbeBackend for CurlProbeFallback {
    async fn probe(&self, task: ProbeTask, ctx: ProbeContext) -> ProbeResult {
        let start = Instant::now();
        let scheme = match task.protocol {
            ProbeProtocol::HttpPlain => "http",
            ProbeProtocol::Tls12Http11 => "https",
            ProbeProtocol::Tls13Http11 => "https",
            ProbeProtocol::QuicHttp3Future => "https",
        };
        let path = if task.request.path_and_query.is_empty() {
            "/"
        } else {
            &task.request.path_and_query
        };
        let url = format!(
            "{scheme}://{}:{port}{path}",
            task.target_host,
            port = task.target_port
        );
        let resolve = format!(
            "{}:{}:{}",
            task.target_host, task.target_port, task.target_ip
        );
        let mut cmd = Command::new("curl");

        cmd.arg("--silent")
            .arg("--show-error")
            .arg("--http1.1")
            .arg("--resolve")
            .arg(resolve)
            .arg("--connect-timeout")
            .arg(format!("{:.3}", task.timeouts.connect_ms as f64 / 1000.0))
            .arg("--max-time")
            .arg(format!("{:.3}", task.timeouts.total_ms as f64 / 1000.0))
            .arg("--user-agent")
            .arg(task.request.user_agent.clone())
            .arg("--output")
            .arg("/dev/null")
            .arg("--write-out")
            .arg("%{http_code} %{size_header} %{size_download}");

        if task.request.method == HttpMethod::Head {
            cmd.arg("--head");
        }

        match task.protocol {
            ProbeProtocol::Tls12Http11 => {
                cmd.arg("--tlsv1.2").arg("--tls-max").arg("1.2");
            }
            ProbeProtocol::Tls13Http11 => {
                cmd.arg("--tlsv1.3").arg("--tls-max").arg("1.3");
            }
            _ => {}
        }

        let output = timeout(
            Duration::from_millis(task.timeouts.total_ms),
            cmd.arg(url).output(),
        )
        .await;
        let output = match output {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                return ProbeResult::infrastructure_failure(
                    &task,
                    if ctx.baseline { None } else { Some(ctx.qnum) },
                    None,
                    ProbeErrorClass::CurlFailed,
                    e.to_string(),
                    start.elapsed().as_millis() as u64,
                )
            }
            Err(_) => {
                return failure(
                    &task,
                    ctx.qnum,
                    0,
                    ProbeOutcome::Timeout,
                    probe_failure_kind(ctx.baseline),
                    ProbeErrorClass::ReadTimeout,
                    "curl total timeout",
                    start,
                    None,
                    None,
                    None,
                )
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut parts = stdout.split_whitespace();
        let status = parts
            .next()
            .and_then(|line| line.parse::<u16>().ok())
            .filter(|s| *s != 0);
        let header_bytes = parts
            .next()
            .and_then(|line| line.parse::<f64>().ok())
            .map(|v| v as usize)
            .unwrap_or(0);
        let body_bytes = parts
            .next()
            .and_then(|line| line.parse::<f64>().ok())
            .map(|v| v as usize)
            .unwrap_or(0);
        let headers_complete = output.status.success() && status.is_some();
        let (outcome, error_class, error_message) = if output.status.success() {
            classify_http_response(
                status,
                headers_complete,
                body_bytes,
                task.request.method,
                task.request.read_mode,
                task.request.min_body_bytes,
            )
        } else {
            (
                ProbeOutcome::InternalError,
                Some(ProbeErrorClass::CurlFailed),
                Some(String::from_utf8_lossy(&output.stderr).to_string()),
            )
        };
        let failure_kind = if outcome == ProbeOutcome::Success {
            None
        } else if output.status.success() {
            Some(probe_failure_kind(ctx.baseline))
        } else {
            Some(FailureKind::InfrastructureFailure)
        };
        ProbeResult {
            strategy_id: task.strategy_id,
            worker_id: task.worker_id,
            qnum: if ctx.baseline { None } else { Some(ctx.qnum) },
            assigned_source_port: None,
            target_host: task.target_host,
            target_ip: task.target_ip,
            target_port: task.target_port,
            protocol: task.protocol,
            path: task.request.path_and_query,
            method: task.request.method,
            read_mode: task.request.read_mode,
            setup_ms: None,
            connect_ms: None,
            tls_ms: None,
            first_byte_ms: None,
            total_ms: start.elapsed().as_millis() as u64,
            outcome,
            http_status: status,
            bytes_read: header_bytes + body_bytes,
            header_bytes,
            body_bytes,
            failure_kind,
            error_class,
            error_message,
        }
    }
}

pub fn parse_http_status(bytes: &[u8]) -> Result<u16, ProbeErrorClass> {
    let s = std::str::from_utf8(bytes).map_err(|_| ProbeErrorClass::InvalidHttpResponse)?;
    let line = s
        .lines()
        .next()
        .ok_or(ProbeErrorClass::InvalidHttpResponse)?;
    let mut parts = line.split_whitespace();
    let proto = parts.next().ok_or(ProbeErrorClass::InvalidHttpResponse)?;
    if !proto.starts_with("HTTP/") {
        return Err(ProbeErrorClass::InvalidHttpResponse);
    }
    parts
        .next()
        .ok_or(ProbeErrorClass::InvalidHttpResponse)?
        .parse::<u16>()
        .map_err(|_| ProbeErrorClass::InvalidHttpResponse)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpResponseRead {
    pub status: Option<u16>,
    pub header_bytes: usize,
    pub body_bytes: usize,
    pub total_bytes: usize,
    pub first_byte_ms: Option<u64>,
    pub headers_complete: bool,
}

pub fn parse_http_response_read(bytes: &[u8], first_byte_ms: Option<u64>) -> HttpResponseRead {
    let headers_end = bytes.windows(4).position(|w| w == b"\r\n\r\n");
    let headers_complete = headers_end.is_some();
    let header_bytes = headers_end.map(|idx| idx + 4).unwrap_or(0);
    let body_bytes = if headers_complete {
        bytes.len().saturating_sub(header_bytes)
    } else {
        0
    };
    let status = if headers_complete {
        parse_http_status(&bytes[..header_bytes]).ok()
    } else {
        None
    };
    HttpResponseRead {
        status,
        header_bytes,
        body_bytes,
        total_bytes: bytes.len(),
        first_byte_ms,
        headers_complete,
    }
}

fn cancelled_result(task: &ProbeTask, qnum: u16, source_port: u16, total_ms: u64) -> ProbeResult {
    failure(
        task,
        qnum,
        source_port,
        ProbeOutcome::Cancelled,
        FailureKind::Cancelled,
        ProbeErrorClass::Cancelled,
        "cancelled",
        Instant::now() - std::time::Duration::from_millis(total_ms),
        None,
        None,
        None,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeWaitError {
    Timeout,
    Cancelled,
}

async fn cancellable_timeout<F, T>(
    duration: Duration,
    cancellation: Option<&tokio_util::sync::CancellationToken>,
    future: F,
) -> Result<T, ProbeWaitError>
where
    F: Future<Output = T>,
{
    if let Some(token) = cancellation {
        tokio::select! {
            result = timeout(duration, future) => result.map_err(|_| ProbeWaitError::Timeout),
            _ = token.cancelled() => Err(ProbeWaitError::Cancelled),
        }
    } else {
        timeout(duration, future)
            .await
            .map_err(|_| ProbeWaitError::Timeout)
    }
}

fn probe_failure_kind(baseline: bool) -> FailureKind {
    if baseline {
        FailureKind::TargetFailure
    } else {
        FailureKind::StrategyFailure
    }
}

#[allow(dead_code)]
pub fn probe_outcome_for_http_status(status: Option<u16>) -> ProbeOutcome {
    match status {
        Some(200..=399) => ProbeOutcome::Success,
        Some(403) | Some(451) => ProbeOutcome::HttpBlockPage,
        Some(_) => ProbeOutcome::HttpBlockPage,
        None => ProbeOutcome::EmptyResponse,
    }
}

fn status_is_success(status: Option<u16>) -> bool {
    matches!(status, Some(200..=399))
}

pub fn classify_http_response(
    status: Option<u16>,
    headers_complete: bool,
    body_bytes: usize,
    method: HttpMethod,
    read_mode: ReadMode,
    min_body_bytes: usize,
) -> (ProbeOutcome, Option<ProbeErrorClass>, Option<String>) {
    if !headers_complete {
        return (
            ProbeOutcome::EmptyResponse,
            Some(ProbeErrorClass::InvalidHttpResponse),
            Some("HTTP response headers incomplete".into()),
        );
    }
    if status.is_none() {
        return (
            ProbeOutcome::EmptyResponse,
            Some(ProbeErrorClass::InvalidHttpResponse),
            Some("invalid HTTP response status".into()),
        );
    }
    if status_is_success(status) {
        if method == HttpMethod::Head || read_mode == ReadMode::Headers {
            return (ProbeOutcome::Success, None, None);
        }
        if body_bytes >= min_body_bytes {
            return (ProbeOutcome::Success, None, None);
        }
        return (
            ProbeOutcome::BodyTooSmall,
            Some(ProbeErrorClass::BodyTooSmall),
            Some(format!(
                "HTTP body too small: got {body_bytes} bytes, need {min_body_bytes}"
            )),
        );
    }
    match status {
        Some(403 | 451 | 400..=599) => (
            ProbeOutcome::HttpBlockPage,
            Some(ProbeErrorClass::InvalidHttpResponse),
            Some("HTTP block page/status".into()),
        ),
        _ => (
            ProbeOutcome::EmptyResponse,
            Some(ProbeErrorClass::InvalidHttpResponse),
            Some("unexpected HTTP status".into()),
        ),
    }
}

fn http_read_criteria_met(
    read: &HttpResponseRead,
    method: HttpMethod,
    read_mode: ReadMode,
    min_body_bytes: usize,
) -> bool {
    if !read.headers_complete {
        return false;
    }
    if method == HttpMethod::Head || read_mode == ReadMode::Headers {
        return true;
    }
    match read_mode {
        ReadMode::Headers => true,
        ReadMode::Body => read.body_bytes >= min_body_bytes,
        ReadMode::Full => false,
    }
}

fn failure(
    task: &ProbeTask,
    qnum: u16,
    source_port: u16,
    outcome: ProbeOutcome,
    kind: FailureKind,
    cls: ProbeErrorClass,
    msg: impl Into<String>,
    total_start: Instant,
    connect_ms: Option<u64>,
    tls_ms: Option<u64>,
    first_byte_ms: Option<u64>,
) -> ProbeResult {
    ProbeResult {
        strategy_id: task.strategy_id.clone(),
        worker_id: task.worker_id,
        qnum: Some(qnum),
        assigned_source_port: Some(source_port),
        target_host: task.target_host.clone(),
        target_ip: task.target_ip,
        target_port: task.target_port,
        protocol: task.protocol,
        path: task.request.path_and_query.clone(),
        method: task.request.method,
        read_mode: task.request.read_mode,
        setup_ms: None,
        connect_ms,
        tls_ms,
        first_byte_ms,
        total_ms: total_start.elapsed().as_millis() as u64,
        outcome,
        http_status: None,
        bytes_read: 0,
        header_bytes: 0,
        body_bytes: 0,
        failure_kind: Some(kind),
        error_class: Some(cls),
        error_message: Some(msg.into()),
    }
}
