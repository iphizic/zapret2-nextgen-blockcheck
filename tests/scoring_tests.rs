use zapret_checker::{
    bayes::BayesianState,
    scoring::{adaptive_score, ScoreWeights},
    types::*,
};

fn result(kind: Option<FailureKind>, outcome: ProbeOutcome) -> ProbeResult {
    ProbeResult {
        strategy_id: "s1".into(),
        worker_id: 0,
        qnum: Some(200),
        assigned_source_port: Some(50000),
        target_host: "example.org".into(),
        target_ip: "127.0.0.1".parse().unwrap(),
        target_port: 443,
        protocol: ProbeProtocol::Tls12Http11,
        setup_ms: None,
        connect_ms: None,
        tls_ms: None,
        first_byte_ms: None,
        total_ms: 1,
        outcome,
        http_status: None,
        bytes_read: 0,
        failure_kind: kind,
        error_class: None,
        error_message: None,
    }
}

#[test]
fn infrastructure_failure_does_not_penalize_adaptive_score() {
    let score = adaptive_score(
        &result(
            Some(FailureKind::InfrastructureFailure),
            ProbeOutcome::InternalError,
        ),
        10.0,
        10.0,
        ScoreWeights::default(),
    );
    assert_eq!(score, 0.0);
}

#[test]
fn infrastructure_failure_does_not_update_bayesian_state() {
    let mut state = BayesianState::default();
    state.update(
        "s1",
        (4.0, 2.0),
        &result(
            Some(FailureKind::InfrastructureFailure),
            ProbeOutcome::InternalError,
        ),
    );
    assert!(state.posteriors.get("s1").is_none());
}

#[test]
fn strategy_failure_updates_bayesian_state() {
    let mut state = BayesianState::default();
    state.update(
        "s1",
        (4.0, 2.0),
        &result(Some(FailureKind::StrategyFailure), ProbeOutcome::Timeout),
    );
    let posterior = state.posteriors.get("s1").unwrap();
    assert_eq!(posterior.tests, 1);
    assert!(posterior.beta > 2.0);
}
