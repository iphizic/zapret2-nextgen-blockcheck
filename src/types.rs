use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeProtocol {
    HttpPlain,
    Tls12Http11,
    Tls13Http11,
    QuicHttp3Future,
}

impl ProbeProtocol {
    pub fn catalog_key(self) -> &'static str {
        match self {
            Self::HttpPlain => "http",
            Self::Tls12Http11 => "tls12",
            Self::Tls13Http11 => "tls13",
            Self::QuicHttp3Future => "quic",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::HttpPlain => 80,
            Self::Tls12Http11 | Self::Tls13Http11 | Self::QuicHttp3Future => 443,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum HttpMethod {
    Get,
    Head,
}

impl HttpMethod {
    pub fn parse_config(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Ok(Self::Get),
            "HEAD" => Ok(Self::Head),
            _ => anyhow::bail!("unsupported probe.method: {s}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum ReadMode {
    Headers,
    Body,
    Full,
}

impl ReadMode {
    pub fn parse_config(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "headers" => Ok(Self::Headers),
            "body" => Ok(Self::Body),
            "full" => Ok(Self::Full),
            _ => anyhow::bail!("unsupported probe.read_mode: {s}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetScheme {
    Http,
    Https,
}

#[derive(Debug, Clone)]
pub struct TargetRequest {
    pub original: String,
    pub scheme: TargetScheme,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub protocol: ProbeProtocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyProbeTarget {
    pub original: String,
    pub host: String,
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: ProbeProtocol,
    pub request: HttpRequestSpec,
}

pub fn parse_target_request(
    host: Option<String>,
    url: Option<String>,
    selected_protocol: ProbeProtocol,
    explicit_protocol_from_cli: bool,
) -> anyhow::Result<TargetRequest> {
    if host.is_some() == url.is_some() {
        anyhow::bail!("specify exactly one of --host or --url");
    }

    if let Some(host_input) = host {
        let (host, explicit_port, path_and_query) = split_host_path(&host_input)?;
        let (scheme, port) = match selected_protocol {
            ProbeProtocol::HttpPlain => (TargetScheme::Http, 80),
            ProbeProtocol::Tls12Http11 | ProbeProtocol::Tls13Http11 => (TargetScheme::Https, 443),
            ProbeProtocol::QuicHttp3Future => anyhow::bail!("QUIC HTTP/3 probe is not implemented"),
        };
        return Ok(TargetRequest {
            original: host_input,
            scheme,
            host,
            port: explicit_port.unwrap_or(port),
            path_and_query,
            protocol: selected_protocol,
        });
    }

    let url_text = url.expect("validated exactly one target");
    let parsed = url::Url::parse(&url_text)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("target URL must include host"))?
        .to_string();
    let (scheme, default_port, protocol) = match parsed.scheme() {
        "http" => {
            if explicit_protocol_from_cli && !matches!(selected_protocol, ProbeProtocol::HttpPlain)
            {
                anyhow::bail!("--probe-protocol conflicts with http:// URL");
            }
            (TargetScheme::Http, 80, ProbeProtocol::HttpPlain)
        }
        "https" => {
            let protocol = match selected_protocol {
                ProbeProtocol::Tls12Http11 | ProbeProtocol::Tls13Http11 => selected_protocol,
                ProbeProtocol::HttpPlain if explicit_protocol_from_cli => {
                    anyhow::bail!("--probe-protocol conflicts with https:// URL")
                }
                ProbeProtocol::HttpPlain => ProbeProtocol::Tls12Http11,
                ProbeProtocol::QuicHttp3Future => {
                    anyhow::bail!("QUIC HTTP/3 probe is not implemented")
                }
            };
            (TargetScheme::Https, 443, protocol)
        }
        other => anyhow::bail!("unsupported URL scheme: {other}"),
    };
    let mut path_and_query = normalize_path(parsed.path());
    if let Some(query) = parsed.query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }
    Ok(TargetRequest {
        original: url_text,
        scheme,
        host,
        port: parsed.port().unwrap_or(default_port),
        path_and_query,
        protocol,
    })
}

fn split_host_path(input: &str) -> anyhow::Result<(String, Option<u16>, String)> {
    let split_at = input.find(['/', '?']).unwrap_or(input.len());
    let authority = &input[..split_at];
    let (host, port) = split_authority_host_port(authority)?;
    if host.is_empty() {
        anyhow::bail!("--host must include host");
    }
    let rest = &input[split_at..];
    let path_and_query = if rest.is_empty() {
        "/".to_string()
    } else if rest.starts_with('/') {
        rest.to_string()
    } else {
        format!("/{rest}")
    };
    Ok((host, port, path_and_query))
}

fn split_authority_host_port(authority: &str) -> anyhow::Result<(String, Option<u16>)> {
    if authority.is_empty() {
        anyhow::bail!("--host must include host");
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let Some(bracket_at) = rest.find(']') else {
            anyhow::bail!("invalid bracketed IPv6 host");
        };
        let host = rest[..bracket_at].to_string();
        let tail = &rest[bracket_at + 1..];
        let port = if tail.is_empty() {
            None
        } else if let Some(port) = tail.strip_prefix(':') {
            Some(parse_host_port(port)?)
        } else {
            anyhow::bail!("invalid bracketed IPv6 host");
        };
        return Ok((host, port));
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if !host.contains(':') && !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Ok((host.to_string(), Some(parse_host_port(port)?)));
        }
    }

    Ok((authority.to_string(), None))
}

fn parse_host_port(port: &str) -> anyhow::Result<u16> {
    port.parse::<u16>()
        .map_err(|_| anyhow::anyhow!("invalid host port: {port}"))
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeTimeouts {
    pub connect_ms: u64,
    pub tls_ms: u64,
    pub first_byte_ms: u64,
    pub total_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyTask {
    pub strategy_id: String,
    pub strategy_args: Vec<String>,
    pub target_host: String,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub protocol: ProbeProtocol,
    pub path: String,
    pub request: HttpRequestSpec,
    pub timeouts: ProbeTimeouts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestSpec {
    pub method: HttpMethod,
    pub path_and_query: String,
    pub user_agent: String,
    pub read_mode: ReadMode,
    pub min_body_bytes: usize,
    pub dpi_detection_bytes: usize,
    pub verify_transfer_bytes: usize,
    pub max_read_bytes: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum TransferLevel {
    #[default]
    None,
    Connected,
    TlsHandshake,
    Headers,
    Body,
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeTask {
    pub strategy_id: String,
    pub worker_id: usize,
    pub strategy_args: Vec<String>,
    pub target_host: String,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub protocol: ProbeProtocol,
    pub path: String,
    pub request: HttpRequestSpec,
    pub timeouts: ProbeTimeouts,
}

impl ProbeTask {
    pub fn from_strategy_task(task: StrategyTask, worker_id: usize) -> Self {
        Self {
            strategy_id: task.strategy_id,
            worker_id,
            strategy_args: task.strategy_args,
            target_host: task.target_host,
            target_ip: task.target_ip,
            target_port: task.target_port,
            protocol: task.protocol,
            path: task.path,
            request: task.request,
            timeouts: task.timeouts,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeContext {
    pub qnum: u16,
    pub cancellation: Option<tokio_util::sync::CancellationToken>,
    pub baseline: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FailureKind {
    StrategyFailure,
    InfrastructureFailure,
    TargetFailure,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeOutcome {
    Success,
    Timeout,
    TcpReset,
    TlsAlert,
    HttpBlockPage,
    EmptyResponse,
    DnsFailure,
    NetworkUnreachable,
    Refused,
    Cancelled,
    InternalError,
    BodyTooSmall,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeErrorClass {
    SocketCreateFailed,
    BindFailed,
    LocalAddrFailed,
    QueueUnavailable,
    FirewallInstallFailed,
    FirewallRemoveFailed,
    NfqwsStartFailed,
    NfqwsExitedEarly,
    NfqwsStopFailed,
    ConnectTimeout,
    ConnectFailed,
    TlsTimeout,
    TlsFailed,
    FirstByteTimeout,
    ReadTimeout,
    ReadFailed,
    InvalidHttpResponse,
    CurlFailed,
    ProcessFailed,
    Cancelled,
    InternalError,
    BodyTooSmall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub strategy_id: String,
    pub worker_id: usize,
    pub qnum: Option<u16>,
    pub assigned_source_port: Option<u16>,
    pub target_host: String,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub protocol: ProbeProtocol,
    pub path: String,
    pub method: HttpMethod,
    pub read_mode: ReadMode,
    pub setup_ms: Option<u64>,
    pub connect_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub first_byte_ms: Option<u64>,
    pub total_ms: u64,
    pub outcome: ProbeOutcome,
    pub http_status: Option<u16>,
    pub bytes_read: usize,
    pub header_bytes: usize,
    pub body_bytes: usize,
    pub total_bytes: usize,
    pub transfer_level: TransferLevel,
    pub dpi_suspicious: bool,
    pub failure_kind: Option<FailureKind>,
    pub error_class: Option<ProbeErrorClass>,
    pub error_message: Option<String>,
}

impl ProbeResult {
    pub fn infrastructure_failure(
        task: &ProbeTask,
        qnum: Option<u16>,
        source_port: Option<u16>,
        cls: ProbeErrorClass,
        msg: impl Into<String>,
        total_ms: u64,
    ) -> Self {
        Self {
            strategy_id: task.strategy_id.clone(),
            worker_id: task.worker_id,
            qnum,
            assigned_source_port: source_port,
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
            total_ms,
            outcome: ProbeOutcome::InternalError,
            http_status: None,
            bytes_read: 0,
            header_bytes: 0,
            body_bytes: 0,
            total_bytes: 0,
            transfer_level: TransferLevel::None,
            dpi_suspicious: false,
            failure_kind: Some(FailureKind::InfrastructureFailure),
            error_class: Some(cls),
            error_message: Some(msg.into()),
        }
    }
}
