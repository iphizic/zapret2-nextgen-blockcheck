use std::{fs, path::PathBuf};
use zapret_checker::{config::AppConfig, graph::StrategyGraph};

#[test]
fn config_loads_checker_toml_and_validates_os_assigned_source_port() {
    let cfg = AppConfig::load(&PathBuf::from("config/checker.toml")).unwrap();
    assert_eq!(cfg.source_port.mode, "os_assigned");
    assert!(cfg.workers.count > 0);
    assert!(cfg.queue.qnum_count > 0);
    assert!(cfg.probe.protocols.tls12);
    assert!(!cfg.probe.protocols.tls13);
    assert_eq!(cfg.probe.protocols.preferred, "tls12");
    assert_eq!(cfg.strategies.successful_strategy_limit, 20);
}

#[test]
fn config_rejects_source_port_pool_mode() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace("mode = \"os_assigned\"", "mode = \"fixed_pool\"");
    let path = std::env::temp_dir().join("zapret_checker_bad_source_mode.toml");
    fs::write(&path, text).unwrap();
    let err = AppConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("source_port.mode must be os_assigned"));
}

#[test]
fn strategy_graph_loads_strategies_and_transition_costs() {
    let graph = StrategyGraph::load(
        &PathBuf::from("config/standart/strategies.yaml"),
        &PathBuf::from("config/standart/transition_matrix.yaml"),
    )
    .unwrap();
    assert!(!graph.nodes.is_empty());
    assert_eq!(
        graph
            .transition_cost
            .get(&("split".to_string(), "fake_split".to_string()))
            .copied(),
        Some(18.0)
    );
}

#[test]
fn custom_strategy_dir_schema_still_loads_simple_files() {
    let graph = StrategyGraph::load(
        &PathBuf::from("config/custom/strategies.yaml"),
        &PathBuf::from("config/custom/transition_matrix.yaml"),
    )
    .unwrap();
    assert_eq!(graph.nodes.len(), 3);
    assert_eq!(
        graph
            .transition_cost
            .get(&("split".to_string(), "fake_split".to_string()))
            .copied(),
        Some(1.0)
    );
}
