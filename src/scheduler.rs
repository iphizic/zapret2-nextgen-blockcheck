use crate::{
    bayes::BayesianState,
    graph::{StrategyGraph, StrategyNode},
    ordering::tsp_like_local_ordering,
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
    pub protocol: ProbeProtocol,
}

#[derive(Debug, Clone, Serialize)]
pub struct StrategyRunResult {
    pub node: StrategyNode,
    pub result: ProbeResult,
    pub adaptive_score: f64,
}

impl Scheduler {
    pub async fn run_graph(
        &self,
        host: String,
        ip: IpAddr,
        graph: StrategyGraph,
        path: String,
        timeouts: ProbeTimeouts,
        cancel: CancellationToken,
    ) -> Vec<StrategyRunResult> {
        let mut bayes = BayesianState::default();
        self.run_graph_with_bayes(host, ip, graph, path, timeouts, cancel, &mut bayes)
            .await
    }

    pub async fn run_graph_with_bayes(
        &self,
        host: String,
        ip: IpAddr,
        graph: StrategyGraph,
        path: String,
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
                    let task = StrategyTask {
                        strategy_id: node.id.clone(),
                        strategy_args: node.args.clone(),
                        target_host: host.clone(),
                        target_ip: ip,
                        target_port: self.protocol.default_port(),
                        protocol: self.protocol,
                        path: path.clone(),
                        timeouts: timeouts.clone(),
                    };
                    async move {
                        let result = runtime
                            .run_strategy_task(task, worker_id, Some(token))
                            .await;
                        (node, result)
                    }
                })
                .buffer_unordered(self.workers_count)
                .collect::<Vec<_>>()
                .await;

            for (node, result) in results {
                if result.outcome == ProbeOutcome::Success {
                    successful_count += 1;
                }
                if should_update_strategy_score(&result) {
                    bayes.update(&node.id, node.prior, &result);
                }
                pruning.record(&node.family, &result, &self.pruning_policy);
                let score = adaptive_score(&result, node.cost, node.risk, self.score_weights);
                out.push(StrategyRunResult {
                    node,
                    result,
                    adaptive_score: score,
                });
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
        path: String,
        timeouts: ProbeTimeouts,
    ) -> Vec<ProbeResult> {
        let graph = StrategyGraph {
            nodes,
            transition_cost: Default::default(),
        };
        self.run_graph(host, ip, graph, path, timeouts, CancellationToken::new())
            .await
            .into_iter()
            .map(|r| r.result)
            .collect()
    }

    fn order_nodes(&self, graph: &StrategyGraph, bayes: &BayesianState) -> Vec<StrategyNode> {
        let mut nodes = graph.ordered_seed();
        nodes.sort_by(|a, b| {
            let sa = bayes.thompson_like_score(&a.id, a.prior, a.cost, a.risk);
            let sb = bayes.thompson_like_score(&b.id, b.prior, b.cost, b.risk);
            sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
        });
        tsp_like_local_ordering(&nodes, &graph.transition_cost)
    }
}
