use crate::types::{FailureKind, ProbeOutcome, ProbeResult};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct PruningPolicy {
    pub soft_fail_family_limit: u32,
    pub combo_requires_signal: bool,
}

pub fn should_update_strategy_score(result: &ProbeResult) -> bool {
    !matches!(
        result.failure_kind,
        Some(FailureKind::InfrastructureFailure)
    )
}

#[derive(Debug, Default)]
pub struct PruningState {
    family_failures: HashMap<String, u32>,
    pruned_families: HashSet<String>,
}

impl PruningState {
    pub fn record(&mut self, family: &str, result: &ProbeResult, policy: &PruningPolicy) {
        if !matches!(result.failure_kind, Some(FailureKind::StrategyFailure)) {
            return;
        }
        if matches!(result.outcome, ProbeOutcome::Success) {
            return;
        }
        let failures = self.family_failures.entry(family.to_string()).or_default();
        let failure_weight = if policy.combo_requires_signal && family.contains('_') {
            2
        } else {
            1
        };
        *failures += failure_weight;
        if *failures >= policy.soft_fail_family_limit {
            self.pruned_families.insert(family.to_string());
        }
    }

    pub fn is_pruned(&self, family: &str) -> bool {
        self.pruned_families.contains(family)
    }
}
