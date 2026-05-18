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
fn config_accepts_expand_search_mode() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace("search_mode = \"signal\"", "search_mode = \"expand\"");
    text = text.replace("max_candidates = 200", "max_candidates = 25");
    let path = std::env::temp_dir().join("zapret_checker_expand_mode.toml");
    fs::write(&path, text).unwrap();
    let cfg = AppConfig::load(&path).unwrap();
    assert_eq!(cfg.strategies.search_mode, "expand");
    assert_eq!(cfg.strategies.max_candidates, 25);
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
fn signal_tls12_generates_more_than_nine_candidates_without_placeholders() {
    let graph = StrategyGraph::load_for_protocol_mode(
        &PathBuf::from("config/standart/strategies.yaml"),
        &PathBuf::from("config/standart/transition_matrix.yaml"),
        "tls12",
        "signal",
        200,
    )
    .unwrap();
    assert!(graph.nodes.len() > 20, "got {}", graph.nodes.len());
    assert!(graph.nodes.iter().all(|n| n.id.starts_with("tls12_")));
    assert!(graph.nodes.iter().all(|n| {
        let args = n.args.join(" ");
        !args.contains("{{") && !args.contains("}}")
    }));
    assert!(graph
        .nodes
        .iter()
        .any(|n| n.args.iter().any(|a| a.contains("fake_default_tls"))));
}

#[test]
fn expand_mode_generates_candidates_and_max_candidates_caps_nodes() {
    let graph = StrategyGraph::load_for_protocol_mode(
        &PathBuf::from("config/standart/strategies.yaml"),
        &PathBuf::from("config/standart/transition_matrix.yaml"),
        "tls12",
        "expand",
        7,
    )
    .unwrap();
    assert_eq!(graph.nodes.len(), 7);
    assert!(graph.nodes.iter().all(|n| n.id.starts_with("tls12_")));
}

#[test]
fn signal_cartesian_product_expands_split_positions() {
    let graph = StrategyGraph::load_for_protocol_mode(
        &PathBuf::from("config/standart/strategies.yaml"),
        &PathBuf::from("config/standart/transition_matrix.yaml"),
        "tls12",
        "signal",
        200,
    )
    .unwrap();
    let split_count = graph
        .nodes
        .iter()
        .filter(|n| {
            n.family == "split" && n.args[0].contains("multisplit:payload=tls_client_hello")
        })
        .count();
    assert!(split_count >= 7, "got {split_count}");
}

#[test]
fn unresolved_placeholder_variant_is_skipped() {
    let strategies_path = std::env::temp_dir().join("zapret_checker_unresolved_strategies.yaml");
    let transition_path = std::env::temp_dir().join("zapret_checker_unresolved_transition.yaml");
    fs::write(
        &strategies_path,
        r#"
families:
  - id: split
    enabled: true
    protocols: [tls12]
    cost: 1
    risk: 1
    prior: [2, 2]
    actions:
      - id: good
        protocols: [tls12]
        params:
          pos:
            values: [a, b, c]
            default: a
        render:
          lua_desync: "multisplit:payload=tls_client_hello:pos={{pos}}"
      - id: bad
        protocols: [tls12]
        params: {}
        render:
          lua_desync: "fake:payload=tls_client_hello:blob={{blob}}"
candidate_generators:
  signal:
    tls12:
      - family: split
        actions: [good, bad]
        params:
          pos: [a, b, c]
"#,
    )
    .unwrap();
    fs::write(
        &transition_path,
        r#"
costs:
  split:
    split: 0
"#,
    )
    .unwrap();
    let graph = StrategyGraph::load_for_protocol_mode(
        &strategies_path,
        &transition_path,
        "tls12",
        "signal",
        20,
    )
    .unwrap();
    assert_eq!(graph.nodes.len(), 3);
    assert!(graph.nodes.iter().all(|n| !n.args[0].contains("{{")));
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
