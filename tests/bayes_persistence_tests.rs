use zapret_checker::bayes::{BayesianState, Posterior};

#[test]
fn bayes_yaml_preserves_base_file_and_updates_runtime_posteriors() {
    let path = std::env::temp_dir().join("zapret_checker_bayes_state.yaml");
    std::fs::write(
        &path,
        r#"version: 1
kind: bayesian_priors
global:
  default_prior: [2.0, 2.0]
"#,
    )
    .unwrap();

    let mut state = BayesianState::default();
    state.posteriors.insert(
        "strategy_a".into(),
        Posterior {
            alpha: 5.0,
            beta: 2.0,
            tests: 3,
        },
    );
    state.save(&path).unwrap();

    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(saved.contains("kind: bayesian_priors"));
    assert!(saved.contains("runtime_posteriors"));

    let loaded = BayesianState::load(&path).unwrap();
    let posterior = loaded.posteriors.get("strategy_a").unwrap();
    assert_eq!(posterior.alpha, 5.0);
    assert_eq!(posterior.tests, 3);
}

#[test]
fn bayes_json_state_roundtrips() {
    let path = std::env::temp_dir().join("zapret_checker_bayes_state.json");
    let mut state = BayesianState::default();
    state.posteriors.insert(
        "strategy_b".into(),
        Posterior {
            alpha: 2.0,
            beta: 4.0,
            tests: 2,
        },
    );
    state.save(&path).unwrap();

    let loaded = BayesianState::load(&path).unwrap();
    let posterior = loaded.posteriors.get("strategy_b").unwrap();
    assert_eq!(posterior.beta, 4.0);
    assert_eq!(posterior.tests, 2);
}
