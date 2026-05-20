use crate::types::{FailureKind, ProbeResult};

pub fn should_update_strategy_score(result: &ProbeResult) -> bool {
    !matches!(
        result.failure_kind,
        Some(FailureKind::InfrastructureFailure)
    )
}
