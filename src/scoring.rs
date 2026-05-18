use crate::types::{FailureKind, ProbeOutcome, ProbeResult};

#[derive(Debug, Clone, Copy)]
pub struct ScoreWeights {
    pub success: f64,
    pub timeout_penalty: f64,
    pub cost_penalty: f64,
    pub risk_penalty: f64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            success: 100.0,
            timeout_penalty: 20.0,
            cost_penalty: 3.0,
            risk_penalty: 5.0,
        }
    }
}

pub fn adaptive_score(result: &ProbeResult, cost: f64, risk: f64, w: ScoreWeights) -> f64 {
    let mut s = match result.outcome {
        ProbeOutcome::Success => w.success,
        ProbeOutcome::Timeout => -w.timeout_penalty,
        ProbeOutcome::Cancelled => 0.0,
        _ => -5.0,
    };
    if matches!(
        result.failure_kind,
        Some(FailureKind::InfrastructureFailure)
    ) {
        return 0.0;
    }
    s -= cost * w.cost_penalty;
    s -= risk * w.risk_penalty;
    s
}
