pub use crate::isolation::generate_assignments;
use crate::{
    config::{IsolationConfig, WorkersConfig},
    graph::StrategyNode,
    types::*,
    worker::{WorkerAssignment, WorkerRuntime},
};
use async_trait::async_trait;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, Notify},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct WorkerPoolConfig {
    pub workers: WorkersConfig,
    pub isolation: IsolationConfig,
    pub stop_at_success: usize,
}

#[derive(Debug, Clone)]
pub struct IndexedPoolTask {
    pub strategy_index: usize,
    pub node: StrategyNode,
    pub targets: Vec<StrategyProbeTarget>,
    pub timeouts: ProbeTimeouts,
}

#[derive(Debug, Clone)]
pub struct IndexedPoolResult {
    pub strategy_index: usize,
    pub node: StrategyNode,
    pub result: ProbeResult,
    pub attempts: Vec<ProbeResult>,
    pub worker_id: usize,
    pub qnum: u16,
}

#[derive(Clone)]
pub struct EnqueueContext {
    pub task_tx: mpsc::Sender<IndexedPoolTask>,
    pub stop_state: Arc<StopState>,
    pub cancel: CancellationToken,
}

impl EnqueueContext {
    pub async fn enqueue(&self, task: IndexedPoolTask) -> bool {
        if self.cancel.is_cancelled() || self.stop_state.should_stop_enqueueing() {
            return false;
        }
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => false,
            _ = self.stop_state.stopped() => false,
            result = self.task_tx.send(task) => result.is_ok(),
        }
    }

    pub fn should_stop(&self) -> bool {
        self.cancel.is_cancelled() || self.stop_state.should_stop_enqueueing()
    }
}

pub struct StopState {
    limit: usize,
    success_count: AtomicUsize,
    stop_enqueue: AtomicBool,
    notify: Notify,
}

impl StopState {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            success_count: AtomicUsize::new(0),
            stop_enqueue: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    pub fn should_stop_enqueueing(&self) -> bool {
        self.stop_enqueue.load(Ordering::Acquire)
    }

    pub fn record_success(&self) {
        if self.limit == 0 {
            return;
        }
        let count = self.success_count.fetch_add(1, Ordering::AcqRel) + 1;
        if count >= self.limit {
            self.stop_enqueue.store(true, Ordering::Release);
            self.notify.notify_waiters();
        }
    }

    pub async fn stopped(&self) {
        if self.should_stop_enqueueing() {
            return;
        }
        self.notify.notified().await;
    }
}

#[async_trait]
pub trait PoolWorkerBackend: Send + Sync {
    async fn run_strategy(
        &self,
        assignment: WorkerAssignment,
        node: StrategyNode,
        targets: Vec<StrategyProbeTarget>,
        timeouts: ProbeTimeouts,
        cancel: CancellationToken,
    ) -> (ProbeResult, Vec<ProbeResult>);
}

#[async_trait]
impl PoolWorkerBackend for WorkerRuntime {
    async fn run_strategy(
        &self,
        assignment: WorkerAssignment,
        node: StrategyNode,
        targets: Vec<StrategyProbeTarget>,
        timeouts: ProbeTimeouts,
        cancel: CancellationToken,
    ) -> (ProbeResult, Vec<ProbeResult>) {
        run_strategy_tests(self, node, assignment, targets, timeouts, cancel).await
    }
}

pub struct WorkerPool<B: PoolWorkerBackend> {
    config: WorkerPoolConfig,
    backend: Arc<B>,
    assignments: Vec<WorkerAssignment>,
}

impl<B: PoolWorkerBackend + 'static> WorkerPool<B> {
    pub fn new(config: WorkerPoolConfig, backend: B, assignments: Vec<WorkerAssignment>) -> Self {
        Self {
            config,
            backend: Arc::new(backend),
            assignments,
        }
    }

    pub fn assignments(&self) -> &[WorkerAssignment] {
        &self.assignments
    }

    pub fn worker_count(&self) -> usize {
        self.assignments.len()
    }

    pub async fn run<P, Fut, R>(
        &self,
        cancel: CancellationToken,
        producer: P,
        mut on_result: R,
    ) -> Vec<IndexedPoolResult>
    where
        P: FnOnce(EnqueueContext) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
        R: FnMut(&IndexedPoolResult) + Send,
    {
        let stop_state = Arc::new(StopState::new(self.config.stop_at_success));
        let (task_tx, task_rx) = mpsc::channel(self.config.workers.task_channel_size);
        let (result_tx, mut result_rx) = mpsc::channel(self.config.workers.result_channel_size);
        let task_rx = Arc::new(tokio::sync::Mutex::new(task_rx));

        let mut worker_handles = Vec::with_capacity(self.assignments.len());
        for assignment in self.assignments.clone() {
            let backend = self.backend.clone();
            let task_rx = task_rx.clone();
            let result_tx = result_tx.clone();
            let worker_cancel = cancel.clone();
            let worker_stop_state = stop_state.clone();
            worker_handles.push(tokio::spawn(async move {
                worker_loop(
                    backend,
                    assignment,
                    task_rx,
                    result_tx,
                    worker_cancel,
                    worker_stop_state,
                )
                .await;
            }));
        }
        drop(result_tx);

        let enqueue = EnqueueContext {
            task_tx: task_tx.clone(),
            stop_state: stop_state.clone(),
            cancel: cancel.clone(),
        };
        let producer_handle = tokio::spawn(producer(enqueue));
        drop(task_tx);

        let mut results = Vec::new();
        loop {
            tokio::select! {
                maybe = result_rx.recv() => {
                    match maybe {
                        Some(result) => {
                            if result.result.outcome == ProbeOutcome::Success {
                                stop_state.record_success();
                            }
                            on_result(&result);
                            results.push(result);
                        }
                        None => break,
                    }
                }
                _ = cancel.cancelled() => {
                    break;
                }
            }
        }

        let _ = producer_handle.await;

        let drain_until =
            Instant::now() + Duration::from_millis(self.config.workers.shutdown_timeout_ms);
        while Instant::now() < drain_until {
            match timeout(Duration::from_millis(10), result_rx.recv()).await {
                Ok(Some(result)) => {
                    if result.result.outcome == ProbeOutcome::Success {
                        stop_state.record_success();
                    }
                    on_result(&result);
                    results.push(result);
                }
                Ok(None) => break,
                Err(_) => {}
            }
        }

        for handle in worker_handles {
            let _ = timeout(
                Duration::from_millis(self.config.workers.shutdown_timeout_ms),
                handle,
            )
            .await;
        }

        results.sort_by_key(|item| item.strategy_index);
        results
    }

    pub async fn run_tasks(
        &self,
        tasks: impl IntoIterator<Item = IndexedPoolTask>,
        cancel: CancellationToken,
    ) -> Vec<IndexedPoolResult> {
        let tasks = tasks.into_iter().collect::<Vec<_>>();
        self.run(
            cancel,
            |ctx| async move {
                for task in tasks {
                    if !ctx.enqueue(task).await {
                        break;
                    }
                }
            },
            |_| {},
        )
        .await
    }
}

async fn worker_loop<B: PoolWorkerBackend>(
    backend: Arc<B>,
    assignment: WorkerAssignment,
    task_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<IndexedPoolTask>>>,
    result_tx: mpsc::Sender<IndexedPoolResult>,
    cancel: CancellationToken,
    stop_state: Arc<StopState>,
) {
    loop {
        if stop_state.should_stop_enqueueing() {
            return;
        }
        let task = loop {
            if stop_state.should_stop_enqueueing() {
                return;
            }
            let received = {
                let mut receiver = task_rx.lock().await;
                receiver.try_recv()
            };
            match received {
                Ok(task) => break task,
                Err(mpsc::error::TryRecvError::Empty) => {
                    if cancel.is_cancelled() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => return,
            }
        };
        if cancel.is_cancelled() {
            break;
        }

        let (result, attempts) = backend
            .run_strategy(
                assignment,
                task.node.clone(),
                task.targets,
                task.timeouts,
                cancel.clone(),
            )
            .await;

        let indexed = IndexedPoolResult {
            strategy_index: task.strategy_index,
            node: task.node,
            worker_id: assignment.worker_id,
            qnum: assignment.qnum,
            result,
            attempts,
        };
        if result_tx.send(indexed).await.is_err() {
            break;
        }
    }
}

async fn run_strategy_tests(
    runtime: &WorkerRuntime,
    node: StrategyNode,
    assignment: WorkerAssignment,
    targets: Vec<StrategyProbeTarget>,
    timeouts: ProbeTimeouts,
    token: CancellationToken,
) -> (ProbeResult, Vec<ProbeResult>) {
    let mut attempts = Vec::new();
    let mut last_result = None;
    let mut first_failure = None;

    for target in targets {
        let task = StrategyTask {
            strategy_id: node.id.clone(),
            strategy_args: node.args.clone(),
            target_host: target.host,
            target_ip: target.ip,
            target_port: target.port,
            protocol: target.protocol,
            path: target.request.path_and_query.clone(),
            request: target.request,
            timeouts: timeouts.clone(),
        };
        let result = runtime
            .run_strategy_task(task, assignment, Some(token.clone()))
            .await;
        let success = result.outcome == ProbeOutcome::Success;
        last_result = Some(result.clone());
        attempts.push(result);
        if !success {
            first_failure.get_or_insert_with(|| attempts.last().expect("attempt exists").clone());
        }
    }

    let result = first_failure
        .unwrap_or_else(|| last_result.expect("at least one strategy target is required"));
    (result, attempts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{StrategyComponent, StrategyNode};
    use crate::{
        firewall::{FirewallError, FirewallHook, FirewallManager, WorkerFirewallRule},
        nfqws::{NfqwsError, NfqwsHandle, NfqwsInstanceConfig, NfqwsManager},
        probe::NativeTcpTlsHttpProbe,
    };
    use parking_lot::Mutex;
    use std::{
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr},
        path::PathBuf,
    };
    use tokio::process::Command;

    struct NoopFirewall;

    #[async_trait]
    impl FirewallManager for NoopFirewall {
        async fn setup(&self) -> Result<(), FirewallError> {
            Ok(())
        }

        async fn install_worker_rule(
            &self,
            _rule: WorkerFirewallRule,
        ) -> Result<(), FirewallError> {
            Ok(())
        }

        async fn remove_worker_rule(&self, _rule: WorkerFirewallRule) -> Result<(), FirewallError> {
            Ok(())
        }

        async fn cleanup_all(&self) -> Result<(), FirewallError> {
            Ok(())
        }
    }

    struct SleepNfqws;

    #[async_trait]
    impl NfqwsManager for SleepNfqws {
        async fn start(&self, cfg: NfqwsInstanceConfig) -> Result<NfqwsHandle, NfqwsError> {
            let child = Command::new("sleep")
                .arg("60")
                .spawn()
                .map_err(|e| NfqwsError::StartFailed(e.to_string()))?;
            Ok(NfqwsHandle {
                qnum: cfg.qnum,
                worker_id: cfg.worker_id,
                strategy_id: cfg.strategy_id,
                child,
            })
        }

        async fn stop(&self, mut handle: NfqwsHandle) -> Result<(), NfqwsError> {
            let _ = handle.child.kill().await;
            Ok(())
        }
    }

    struct MockBackend {
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
        delay_ms: u64,
        outcomes: Arc<Mutex<VecDeque<ProbeOutcome>>>,
        started: Arc<Mutex<Vec<usize>>>,
    }

    impl Clone for MockBackend {
        fn clone(&self) -> Self {
            Self {
                active: self.active.clone(),
                max_active: self.max_active.clone(),
                delay_ms: self.delay_ms,
                outcomes: self.outcomes.clone(),
                started: self.started.clone(),
            }
        }
    }

    impl MockBackend {
        fn new(delay_ms: u64, outcomes: Vec<ProbeOutcome>) -> Self {
            Self {
                active: Arc::new(AtomicUsize::new(0)),
                max_active: Arc::new(AtomicUsize::new(0)),
                delay_ms,
                outcomes: Arc::new(Mutex::new(outcomes.into())),
                started: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn max_active(&self) -> usize {
            self.max_active.load(Ordering::Acquire)
        }

        fn started_indices(&self) -> Vec<usize> {
            self.started.lock().clone()
        }
    }

    #[async_trait]
    impl PoolWorkerBackend for MockBackend {
        async fn run_strategy(
            &self,
            assignment: WorkerAssignment,
            node: StrategyNode,
            _targets: Vec<StrategyProbeTarget>,
            _timeouts: ProbeTimeouts,
            _cancel: CancellationToken,
        ) -> (ProbeResult, Vec<ProbeResult>) {
            if let Ok(index) = node.id.parse::<usize>() {
                self.started.lock().push(index);
            }

            let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
            loop {
                let current_max = self.max_active.load(Ordering::Acquire);
                if active <= current_max {
                    break;
                }
                if self
                    .max_active
                    .compare_exchange(current_max, active, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    break;
                }
            }

            if self.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            }

            let outcome = self
                .outcomes
                .lock()
                .pop_front()
                .unwrap_or(ProbeOutcome::Success);
            self.active.fetch_sub(1, Ordering::AcqRel);

            let result = probe_result(&node.id, assignment.worker_id, assignment.qnum, outcome);
            (result.clone(), vec![result])
        }
    }

    fn probe_result(
        strategy_id: &str,
        worker_id: usize,
        qnum: u16,
        outcome: ProbeOutcome,
    ) -> ProbeResult {
        ProbeResult {
            strategy_id: strategy_id.to_string(),
            worker_id,
            qnum: Some(qnum),
            assigned_source_port: Some(40_000 + worker_id as u16),
            target_host: "example.com".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            target_port: 443,
            protocol: ProbeProtocol::Tls12Http11,
            path: "/".to_string(),
            method: HttpMethod::Get,
            read_mode: ReadMode::Body,
            setup_ms: Some(1),
            connect_ms: Some(1),
            tls_ms: Some(1),
            first_byte_ms: Some(1),
            total_ms: 1,
            outcome,
            http_status: Some(200),
            bytes_read: 1,
            header_bytes: 0,
            body_bytes: 1,
            total_bytes: 1,
            transfer_level: TransferLevel::Body,
            dpi_suspicious: false,
            failure_kind: None,
            error_class: None,
            error_message: None,
        }
    }

    fn test_node(id: &str) -> StrategyNode {
        StrategyNode {
            id: id.to_string(),
            family: "fake".to_string(),
            action_id: "fake_tls".to_string(),
            args: vec!["--lua-desync=fake".to_string()],
            components: vec![StrategyComponent {
                family: "fake".to_string(),
                action_id: "fake_tls".to_string(),
                args: vec!["--lua-desync=fake".to_string()],
            }],
            is_combined: false,
            cost: 1.0,
            risk: 1.0,
            prior: (1.0, 1.0),
        }
    }

    fn pool_config(workers: usize, stop_at_success: usize) -> WorkerPoolConfig {
        WorkerPoolConfig {
            workers: WorkersConfig {
                count: workers,
                spawn_grace_ms: 1,
                task_channel_size: 64,
                result_channel_size: 64,
                shutdown_timeout_ms: 1000,
            },
            isolation: IsolationConfig {
                mode: "source_port".to_string(),
                queue_base: 200,
                mark_base: "0x20000000".to_string(),
                desync_mark: "0x40000000".to_string(),
                use_nft_vmap: false,
            },
            stop_at_success,
        }
    }

    fn test_isolation(mode: &str) -> IsolationConfig {
        IsolationConfig {
            mode: mode.to_string(),
            queue_base: 200,
            mark_base: "0x20000000".to_string(),
            desync_mark: "0x40000000".to_string(),
            use_nft_vmap: mode == "fwmark",
        }
    }

    fn indexed_task(index: usize, id: &str) -> IndexedPoolTask {
        IndexedPoolTask {
            strategy_index: index,
            node: test_node(id),
            targets: vec![StrategyProbeTarget {
                original: "https://example.com/".to_string(),
                host: "example.com".to_string(),
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 443,
                protocol: ProbeProtocol::Tls12Http11,
                request: HttpRequestSpec {
                    method: HttpMethod::Get,
                    path_and_query: "/".to_string(),
                    user_agent: "test".to_string(),
                    read_mode: ReadMode::Body,
                    min_body_bytes: 1,
                    dpi_detection_bytes: 16384,
                    verify_transfer_bytes: 32768,
                    max_read_bytes: 1024,
                },
            }],
            timeouts: ProbeTimeouts {
                connect_ms: 100,
                tls_ms: 100,
                first_byte_ms: 100,
                total_ms: 100,
            },
        }
    }

    fn strategy_probe_target() -> StrategyProbeTarget {
        StrategyProbeTarget {
            original: "http://127.0.0.1:9/".to_string(),
            host: "127.0.0.1".to_string(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 9,
            protocol: ProbeProtocol::HttpPlain,
            request: HttpRequestSpec {
                method: HttpMethod::Get,
                path_and_query: "/".to_string(),
                user_agent: "test".to_string(),
                read_mode: ReadMode::Body,
                min_body_bytes: 1,
                dpi_detection_bytes: 16384,
                verify_transfer_bytes: 32768,
                max_read_bytes: 1024,
            },
        }
    }

    fn probe_timeouts() -> ProbeTimeouts {
        ProbeTimeouts {
            connect_ms: 50,
            tls_ms: 50,
            first_byte_ms: 50,
            total_ms: 100,
        }
    }

    #[test]
    fn assignment_generation_uses_queue_base_plus_worker_id() {
        let assignments = generate_assignments(3, &test_isolation("source_port"));
        assert_eq!(assignments.len(), 3);
        assert_eq!(assignments[0].qnum, 200);
        assert_eq!(assignments[1].qnum, 201);
        assert_eq!(assignments[2].qnum, 202);
        assert_eq!(assignments[0].worker_id, 0);
        assert_eq!(assignments[2].worker_id, 2);
    }

    #[test]
    fn fwmark_assignment_sets_mark_and_queue() {
        let assignments = generate_assignments(3, &test_isolation("fwmark"));
        assert_eq!(assignments[0].fwmark, Some(0x20000001));
        assert_eq!(assignments[2].fwmark, Some(0x20000003));
        assert!(assignments.iter().all(|item| item.source_port.is_none()));
    }

    #[tokio::test]
    async fn deterministic_task_indexing_preserved_in_results() {
        let backend = MockBackend::new(0, vec![ProbeOutcome::Success; 3]);
        let assignments = generate_assignments(2, &test_isolation("source_port"));
        let pool = WorkerPool::new(pool_config(2, 0), backend, assignments);
        let tasks = vec![
            indexed_task(0, "0"),
            indexed_task(1, "1"),
            indexed_task(2, "2"),
        ];
        let results = pool.run_tasks(tasks, CancellationToken::new()).await;
        assert_eq!(results.len(), 3);
        assert_eq!(
            results
                .iter()
                .map(|item| item.strategy_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[tokio::test]
    async fn out_of_order_results_are_sorted_by_strategy_index() {
        let backend = MockBackend::new(30, vec![ProbeOutcome::Success; 3]);
        let assignments = generate_assignments(3, &test_isolation("source_port"));
        let pool = WorkerPool::new(pool_config(3, 0), backend, assignments);
        let tasks = vec![
            indexed_task(2, "2"),
            indexed_task(0, "0"),
            indexed_task(1, "1"),
        ];
        let results = pool.run_tasks(tasks, CancellationToken::new()).await;
        assert_eq!(
            results
                .iter()
                .map(|item| item.strategy_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[tokio::test]
    async fn stop_at_success_stops_queueing_new_tasks() {
        let backend = MockBackend::new(20, vec![ProbeOutcome::Success; 8]);
        let assignments = generate_assignments(2, &test_isolation("source_port"));
        let monitor = backend.clone();
        let pool = WorkerPool::new(pool_config(2, 2), backend, assignments);
        let cancel = CancellationToken::new();
        let monitor_for_loop = monitor.clone();
        let results = pool
            .run(
                cancel,
                move |ctx| async move {
                    for index in 0..8usize {
                        if ctx.should_stop() {
                            break;
                        }
                        if !ctx.enqueue(indexed_task(index, &index.to_string())).await {
                            break;
                        }
                        while !ctx.should_stop()
                            && monitor_for_loop.started_indices().len() <= index
                        {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }
                },
                |_| {},
            )
            .await;

        assert!(
            monitor.started_indices().len() < 8,
            "started={:?}",
            monitor.started_indices()
        );
        assert!(
            results
                .iter()
                .filter(|item| item.result.outcome == ProbeOutcome::Success)
                .count()
                >= 2
        );
    }

    #[tokio::test]
    async fn stop_at_success_does_not_run_prefilled_queue_tail() {
        let backend = MockBackend::new(20, vec![ProbeOutcome::Success; 20]);
        let monitor = backend.clone();
        let assignments = generate_assignments(2, &test_isolation("source_port"));
        let pool = WorkerPool::new(pool_config(2, 2), backend, assignments);
        let tasks = (0..20)
            .map(|index| indexed_task(index, &index.to_string()))
            .collect::<Vec<_>>();

        let results = pool.run_tasks(tasks, CancellationToken::new()).await;

        assert!(
            monitor.started_indices().len() <= 4,
            "started={:?}",
            monitor.started_indices()
        );
        assert!(
            results.len() <= 4,
            "results={:?}",
            results
                .iter()
                .map(|item| item.strategy_index)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn active_workers_never_exceed_workers_count() {
        let backend = MockBackend::new(50, vec![ProbeOutcome::Success; 6]);
        let assignments = generate_assignments(2, &test_isolation("source_port"));
        let pool = WorkerPool::new(pool_config(2, 0), backend, assignments);
        let tasks = (0..6)
            .map(|index| indexed_task(index, &index.to_string()))
            .collect::<Vec<_>>();
        let backend_ref = &pool.backend;
        let _ = pool.run_tasks(tasks, CancellationToken::new()).await;
        assert!(backend_ref.max_active() <= 2);
    }

    #[tokio::test]
    async fn strategy_runs_all_targets_even_after_failure() {
        let runtime = WorkerRuntime {
            firewall: Arc::new(NoopFirewall),
            nfqws: Arc::new(SleepNfqws),
            native_probe: NativeTcpTlsHttpProbe::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                1024,
                "test".to_string(),
            ),
            nfqws_binary: PathBuf::from("sleep"),
            nfqws_library_paths: Vec::new(),
            nfqws_base_args: Vec::new(),
            nfqws_start_grace_ms: 0,
            nfqws_log_stdout: false,
            nfqws_log_stderr: false,
            firewall_hook: FirewallHook::Output,
            isolation_mode: crate::isolation::IsolationMode::SourcePort,
        };
        let targets = vec![
            strategy_probe_target(),
            strategy_probe_target(),
            strategy_probe_target(),
        ];

        let (result, attempts) = run_strategy_tests(
            &runtime,
            test_node("repeat-check"),
            WorkerAssignment {
                worker_id: 0,
                qnum: 200,
                fwmark: None,
                source_port: None,
            },
            targets,
            probe_timeouts(),
            CancellationToken::new(),
        )
        .await;

        assert_eq!(attempts.len(), 3);
        assert_ne!(result.outcome, ProbeOutcome::Success);
    }

    #[test]
    fn nfqws_args_order_is_base_qnum_strategy() {
        use crate::nfqws::{build_nfqws_args, NfqwsInstanceConfig};
        use std::path::PathBuf;

        let args = build_nfqws_args(&NfqwsInstanceConfig {
            qnum: 200,
            binary: PathBuf::from("/bin/nfqws2"),
            library_paths: Vec::new(),
            base_args: vec!["--user=daemon".to_string(), "--fwmark=0x1".to_string()],
            strategy_args: vec!["--lua-desync=fake".to_string()],
            worker_id: 0,
            strategy_id: "s0".to_string(),
            start_grace_ms: 100,
            log_stdout: false,
            log_stderr: false,
        });
        assert_eq!(
            args,
            vec![
                "--user=daemon".to_string(),
                "--fwmark=0x1".to_string(),
                "--qnum=200".to_string(),
                "--lua-desync=fake".to_string(),
            ]
        );
    }
}
