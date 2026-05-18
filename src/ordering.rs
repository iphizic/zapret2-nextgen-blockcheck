use crate::graph::StrategyNode;
use std::collections::HashMap;

pub fn tsp_like_local_ordering(
    nodes: &[StrategyNode],
    transition: &HashMap<(String, String), f64>,
) -> Vec<StrategyNode> {
    if nodes.is_empty() {
        return vec![];
    }
    let mut remaining = nodes.to_vec();
    remaining.sort_by(|a, b| {
        a.cost
            .total_cmp(&b.cost)
            .then_with(|| a.risk.total_cmp(&b.risk))
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut out = vec![remaining.remove(0)];
    while !remaining.is_empty() {
        let last = out.last().unwrap();
        let idx = remaining
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| {
                let ca = transition
                    .get(&(last.family.clone(), a.family.clone()))
                    .copied()
                    .unwrap_or(a.cost);
                let cb = transition
                    .get(&(last.family.clone(), b.family.clone()))
                    .copied()
                    .unwrap_or(b.cost);
                ca.total_cmp(&cb)
                    .then_with(|| a.cost.total_cmp(&b.cost))
                    .then_with(|| a.id.cmp(&b.id))
            })
            .map(|(i, _)| i)
            .unwrap();
        out.push(remaining.remove(idx));
    }
    out
}
