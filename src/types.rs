use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeProtocol {
    HttpsHttp11,
    HttpPlain,
    QuicHttp3Future,
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
    pub timeouts: ProbeTimeouts,
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
    pub setup_ms: Option<u64>,
    pub connect_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub first_byte_ms: Option<u64>,
    pub total_ms: u64,
    pub outcome: ProbeOutcome,
    pub http_status: Option<u16>,
    pub bytes_read: usize,
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
            setup_ms: None,
            connect_ms: None,
            tls_ms: None,
            first_byte_ms: None,
            total_ms,
            outcome: ProbeOutcome::InternalError,
            http_status: None,
            bytes_read: 0,
            failure_kind: Some(FailureKind::InfrastructureFailure),
            error_class: Some(cls),
            error_message: Some(msg.into()),
        }
    }
}
