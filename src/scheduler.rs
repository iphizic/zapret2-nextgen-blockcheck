use crate::{
    bayes::BayesianState,
    config::{IsolationConfig, WorkersConfig},
    graph::{StrategyGraph, StrategyNode},
    isolation::generate_assignments,
    pruning::should_update_strategy_score,
    scoring::{adaptive_score, ScoreWeights},
    types::*,
    worker::WorkerRuntime,
    worker_pool::{IndexedPoolResult, IndexedPoolTask, WorkerPool, WorkerPoolConfig},
};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Scheduler {
    pub runtime: WorkerRuntime,
    pub workers_config: WorkersConfig,
    pub isolation: IsolationConfig,
    pub successful_strategy_limit: usize,
    pub score_weights: ScoreWeights,
    pub targets: Vec<StrategyProbeTarget>,
    pub live_log: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StrategyRunResult {
    pub node: StrategyNode,
    pub result: ProbeResult,
    pub attempts: Vec<ProbeResult>,
    pub adaptive_score: f64,
    pub worker_id: usize,
    pub qnum: u16,
}

impl Scheduler {
    pub async fn run_graph(
        &self,
        graph: StrategyGraph,
        timeouts: ProbeTimeouts,
        cancel: CancellationToken,
    ) -> Vec<StrategyRunResult> {
        let mut bayes = BayesianState::default();
        self.run_graph_with_bayes(graph, timeouts, cancel, &mut bayes)
            .await
    }

    pub async fn run_graph_with_bayes(
        &self,
        graph: StrategyGraph,
        timeouts: ProbeTimeouts,
        cancel: CancellationToken,
        bayes: &mut BayesianState,
    ) -> Vec<StrategyRunResult> {
        let ordered = self.order_nodes(&graph, bayes);
        let worker_count = self.workers_config.count.max(1);
        let assignments = generate_assignments(worker_count, &self.isolation);
        let mut runtime = self.runtime.clone();
        runtime.nfqws_start_grace_ms = self.workers_config.spawn_grace_ms;

        let pool = WorkerPool::new(
            WorkerPoolConfig {
                workers: self.workers_config.clone(),
                isolation: self.isolation.clone(),
                stop_at_success: self.successful_strategy_limit,
            },
            runtime,
            assignments,
        );

        let targets = self.targets.clone();
        let timeouts_for_pool = timeouts.clone();
        let mut strategy_index = 0usize;
        let mut ordered_nodes = ordered.into_iter();
        let live_log = self.live_log;
        let score_weights = self.score_weights;
        let mut live_index = 0usize;

        let pool_results = pool
            .run(
                cancel.clone(),
                move |ctx| {
                    let targets = targets.clone();
                    let timeouts = timeouts_for_pool.clone();
                    async move {
                        while let Some(node) = ordered_nodes.next() {
                            if ctx.should_stop() {
                                break;
                            }
                            let task = IndexedPoolTask {
                                strategy_index,
                                node,
                                targets: targets.clone(),
                                timeouts: timeouts.clone(),
                            };
                            strategy_index += 1;
                            if !ctx.enqueue(task).await {
                                break;
                            }
                        }
                    }
                },
                move |item| {
                    if live_log {
                        live_index += 1;
                        eprintln!(
                            "{}",
                            live_strategy_result_line(live_index, item, score_weights)
                        );
                    }
                },
            )
            .await;

        self.finalize_results(pool_results, bayes)
    }

    fn finalize_results(
        &self,
        pool_results: Vec<IndexedPoolResult>,
        bayes: &mut BayesianState,
    ) -> Vec<StrategyRunResult> {
        let mut out = Vec::with_capacity(pool_results.len());
        for item in pool_results {
            if should_update_strategy_score(&item.result) {
                bayes.update(&item.node.id, item.node.prior, &item.result);
            }
            let score = adaptive_score(
                &item.result,
                item.node.cost,
                item.node.risk,
                self.score_weights,
            );
            let run = StrategyRunResult {
                node: item.node,
                result: item.result,
                attempts: item.attempts,
                adaptive_score: score,
                worker_id: item.worker_id,
                qnum: item.qnum,
            };
            out.push(run);
        }
        out
    }

    #[allow(dead_code)]
    pub async fn run_plan(
        &self,
        host: String,
        ip: std::net::IpAddr,
        nodes: Vec<StrategyNode>,
        request: HttpRequestSpec,
        timeouts: ProbeTimeouts,
    ) -> Vec<ProbeResult> {
        let graph = StrategyGraph { nodes };
        let _ = (host, ip, request);
        self.run_graph(graph, timeouts, CancellationToken::new())
            .await
            .into_iter()
            .map(|r| r.result)
            .collect()
    }

    fn order_nodes(&self, graph: &StrategyGraph, bayes: &BayesianState) -> Vec<StrategyNode> {
        let _ = bayes;
        graph.ordered_seed()
    }
}

fn live_strategy_result_line(
    index: usize,
    item: &IndexedPoolResult,
    weights: ScoreWeights,
) -> String {
    let score = adaptive_score(&item.result, item.node.cost, item.node.risk, weights);
    format!(
        "info(checker): strategy #{index:<5} id={} family={} worker={} qnum={} attempts={}/{} domains={} outcome={:?} http={} body={}B bytes={} tls={}ms total={}ms score={:.1}",
        item.node.id,
        item.node.family,
        item.worker_id,
        item.qnum,
        item.attempts
            .iter()
            .filter(|attempt| attempt.outcome == ProbeOutcome::Success)
            .count(),
        item.attempts.len(),
        unique_attempt_targets(&item.attempts),
        item.result.outcome,
        item.result
            .http_status
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into()),
        item.result.body_bytes,
        item.result.bytes_read,
        item.result
            .tls_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into()),
        item.result.total_ms,
        score,
    )
}

fn unique_attempt_targets(attempts: &[ProbeResult]) -> usize {
    let mut seen = std::collections::BTreeSet::new();
    for attempt in attempts {
        seen.insert((
            attempt.target_host.clone(),
            attempt.target_port,
            attempt.path.clone(),
        ));
    }
    seen.len()
}
