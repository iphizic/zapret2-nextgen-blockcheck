use crate::{firewall::*, isolation::IsolationMode, nfqws::*, probe::*, types::*};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::timeout;
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerAssignment {
    pub worker_id: usize,
    pub qnum: u16,
    pub fwmark: Option<u32>,
    pub source_port: Option<u16>,
}

#[derive(Clone)]
pub struct WorkerRuntime {
    pub firewall: Arc<dyn FirewallManager>,
    pub nfqws: Arc<dyn NfqwsManager>,
    pub native_probe: NativeTcpTlsHttpProbe,
    pub nfqws_binary: PathBuf,
    pub nfqws_library_paths: Vec<PathBuf>,
    pub nfqws_base_args: Vec<String>,
    pub nfqws_start_grace_ms: u64,
    pub nfqws_log_stdout: bool,
    pub nfqws_log_stderr: bool,
    pub firewall_hook: FirewallHook,
    pub isolation_mode: IsolationMode,
}

impl WorkerRuntime {
    pub async fn run_strategy_task(
        &self,
        task: StrategyTask,
        assignment: WorkerAssignment,
        cancellation: Option<tokio_util::sync::CancellationToken>,
    ) -> ProbeResult {
        self.run_worker_task(
            ProbeTask::from_strategy_task(task, assignment.worker_id),
            assignment,
            cancellation,
        )
        .await
    }

    pub async fn run_worker_task(
        &self,
        task: ProbeTask,
        assignment: WorkerAssignment,
        cancellation: Option<tokio_util::sync::CancellationToken>,
    ) -> ProbeResult {
        let total_start = Instant::now();
        let prepared = match self.isolation_mode {
            IsolationMode::SourcePort => self
                .native_probe
                .prepare_transport(task.protocol, task.target_ip),
            IsolationMode::Fwmark => self.native_probe.prepare_transport_fwmark(
                task.protocol,
                task.target_ip,
                assignment
                    .fwmark
                    .expect("fwmark assignment required in fwmark isolation mode"),
            ),
        };
        let prepared = match prepared {
            Ok(s) => s,
            Err(e) => {
                return ProbeResult::infrastructure_failure(
                    &task,
                    Some(assignment.qnum),
                    None,
                    ProbeErrorClass::BindFailed,
                    e.to_string(),
                    total_start.elapsed().as_millis() as u64,
                );
            }
        };
        let mut source_port = prepared.assigned_source_port;
        let qnum = assignment.qnum;

        debug!(
            worker_id = task.worker_id,
            strategy_id = %task.strategy_id,
            qnum,
            source_port,
            fwmark = ?assignment.fwmark,
            isolation = ?self.isolation_mode,
            "prepared socket"
        );

        let nfq_cfg = NfqwsInstanceConfig {
            qnum,
            binary: self.nfqws_binary.clone(),
            library_paths: self.nfqws_library_paths.clone(),
            base_args: self.nfqws_base_args.clone(),
            strategy_args: task.strategy_args.clone(),
            worker_id: task.worker_id,
            strategy_id: task.strategy_id.clone(),
            start_grace_ms: self.nfqws_start_grace_ms,
            log_stdout: self.nfqws_log_stdout,
            log_stderr: self.nfqws_log_stderr,
        };
        let nfq_handle = match self.nfqws.start(nfq_cfg).await {
            Ok(h) => h,
            Err(e) => {
                return ProbeResult::infrastructure_failure(
                    &task,
                    Some(qnum),
                    Some(source_port),
                    ProbeErrorClass::NfqwsStartFailed,
                    e.to_string(),
                    total_start.elapsed().as_millis() as u64,
                );
            }
        };

        let per_task_rule = self.isolation_mode == IsolationMode::SourcePort;
        let rule = WorkerFirewallRule {
            worker_id: task.worker_id,
            qnum,
            source_port,
            target_ip: task.target_ip,
            target_port: task.target_port,
            protocol: match task.protocol {
                ProbeProtocol::QuicHttp3Future => L4Protocol::Udp,
                _ => L4Protocol::Tcp,
            },
            hook: self.firewall_hook,
        };
        if per_task_rule {
            if let Err(e) = self.firewall.install_worker_rule(rule.clone()).await {
                let _ = self.nfqws.stop(nfq_handle).await;
                return ProbeResult::infrastructure_failure(
                    &task,
                    Some(qnum),
                    Some(source_port),
                    ProbeErrorClass::FirewallInstallFailed,
                    e.to_string(),
                    total_start.elapsed().as_millis() as u64,
                );
            }
        }
        let setup_ms = total_start.elapsed().as_millis() as u64;

        let ctx = ProbeContext {
            qnum,
            cancellation,
            baseline: false,
        };
        let mut result = match timeout(
            Duration::from_millis(task.timeouts.total_ms),
            self.native_probe
                .probe_with_prepared_socket(task.clone(), ctx, prepared),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => ProbeResult {
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
                connect_ms: None,
                tls_ms: None,
                first_byte_ms: None,
                total_ms: total_start.elapsed().as_millis() as u64,
                outcome: ProbeOutcome::Timeout,
                http_status: None,
                bytes_read: 0,
                header_bytes: 0,
                body_bytes: 0,
                total_bytes: 0,
                transfer_level: TransferLevel::None,
                dpi_suspicious: false,
                failure_kind: Some(FailureKind::StrategyFailure),
                error_class: Some(ProbeErrorClass::ReadTimeout),
                error_message: Some("total timeout".into()),
            },
        };

        if result.assigned_source_port.unwrap_or(0) != 0 {
            source_port = result.assigned_source_port.unwrap_or(source_port);
        }

        result.setup_ms = Some(setup_ms);
        if per_task_rule {
            if let Err(e) = self.firewall.remove_worker_rule(rule).await {
                warn!(worker_id = task.worker_id, qnum, error = %e, "firewall remove failed");
                if result.error_class.is_none() {
                    result.error_class = Some(ProbeErrorClass::FirewallRemoveFailed);
                }
            }
        }
        if let Err(e) = self.nfqws.stop(nfq_handle).await {
            warn!(worker_id = task.worker_id, qnum, error = %e, "nfqws stop failed");
            if result.error_class.is_none() {
                result.error_class = Some(ProbeErrorClass::NfqwsStopFailed);
            }
        }
        result.qnum = Some(qnum);
        result.assigned_source_port = Some(source_port);
        debug!(
            worker_id = result.worker_id,
            strategy_id = %result.strategy_id,
            qnum,
            assigned_source_port = source_port,
            fwmark = ?assignment.fwmark,
            target_host = %result.target_host,
            target_ip = %result.target_ip,
            target_port = result.target_port,
            firewall_hook = ?self.firewall_hook,
            connect_ms = ?result.connect_ms,
            tls_ms = ?result.tls_ms,
            first_byte_ms = ?result.first_byte_ms,
            total_ms = result.total_ms,
            http_status = ?result.http_status,
            bytes_read = result.bytes_read,
            outcome = ?result.outcome,
            failure_kind = ?result.failure_kind,
            error_class = ?result.error_class,
            "probe finished"
        );
        result
    }
}
