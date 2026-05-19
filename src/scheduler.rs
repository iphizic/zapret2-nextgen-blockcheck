use crate::{
    bayes::BayesianState,
    graph::{StrategyGraph, StrategyNode},
    pruning::{should_update_strategy_score, PruningPolicy, PruningState},
    scoring::{adaptive_score, ScoreWeights},
    types::*,
    worker::WorkerRuntime,
};
use futures::{stream, StreamExt};
use serde::Serialize;
use std::{net::IpAddr, sync::Arc};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Scheduler {
    pub runtime: WorkerRuntime,
    pub workers_count: usize,
    pub successful_strategy_limit: usize,
    pub pruning_policy: PruningPolicy,
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
        let runtime = Arc::new(self.runtime.clone());
        let mut pruning = PruningState::default();
        let ordered = self.order_nodes(&graph, bayes);
        let mut next_worker_id = 0usize;
        let mut remaining = ordered.into_iter();
        let mut out = Vec::new();
        let mut successful_count = 0usize;

        loop {
            if cancel.is_cancelled() {
                break;
            }
            if self.successful_strategy_limit > 0
                && successful_count >= self.successful_strategy_limit
            {
                break;
            }
            let mut batch = Vec::new();
            while batch.len() < self.workers_count {
                let Some(node) = remaining.next() else { break };
                if pruning.is_pruned(&node.family) {
                    continue;
                }
                let worker_id = next_worker_id;
                next_worker_id += 1;
                batch.push((worker_id, node));
            }
            if batch.is_empty() {
                break;
            }

            let results = stream::iter(batch)
                .map(|(worker_id, node)| {
                    let runtime = runtime.clone();
                    let token = cancel.clone();
                    let targets = self.targets.clone();
                    let timeouts = timeouts.clone();
                    async move {
                        let (result, attempts) = run_strategy_tests(
                            runtime,
                            node.clone(),
                            worker_id,
                            targets,
                            timeouts,
                            token,
                        )
                        .await;
                        (node, result, attempts)
                    }
                })
                .buffer_unordered(self.workers_count)
                .collect::<Vec<_>>()
                .await;

            for (node, result, attempts) in results {
                if result.outcome == ProbeOutcome::Success {
                    successful_count += 1;
                }
                if should_update_strategy_score(&result) {
                    bayes.update(&node.id, node.prior, &result);
                }
                pruning.record(&node.family, &result, &self.pruning_policy);
                let score = adaptive_score(&result, node.cost, node.risk, self.score_weights);
                let item = StrategyRunResult {
                    node,
                    result,
                    attempts,
                    adaptive_score: score,
                };
                if self.live_log {
                    eprintln!("{}", live_strategy_line(out.len() + 1, &item));
                }
                out.push(item);
            }
        }

        out
    }

    #[allow(dead_code)]
    pub async fn run_plan(
        &self,
        host: String,
        ip: IpAddr,
        nodes: Vec<StrategyNode>,
        request: HttpRequestSpec,
        timeouts: ProbeTimeouts,
    ) -> Vec<ProbeResult> {
        let graph = StrategyGraph {
            nodes,
            transition_cost: Default::default(),
        };
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

async fn run_strategy_tests(
    runtime: Arc<WorkerRuntime>,
    node: StrategyNode,
    worker_id: usize,
    targets: Vec<StrategyProbeTarget>,
    timeouts: ProbeTimeouts,
    token: CancellationToken,
) -> (ProbeResult, Vec<ProbeResult>) {
    let mut attempts = Vec::new();
    let mut last_result = None;

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
            .run_strategy_task(task, worker_id, Some(token.clone()))
            .await;
        let success = result.outcome == ProbeOutcome::Success;
        last_result = Some(result.clone());
        attempts.push(result);
        if !success {
            return (attempts.last().expect("attempt exists").clone(), attempts);
        }
    }

    let result = last_result.expect("at least one strategy target is required");
    (result, attempts)
}

fn live_strategy_line(index: usize, item: &StrategyRunResult) -> String {
    format!(
        "live: strategy #{index} {} family={} tests={}/{} domains={} outcome={:?} http={} body={}B bytes={} tls={}ms total={}ms score={:.1}",
        item.node.id,
        item.node.family,
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
        item.adaptive_score,
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
