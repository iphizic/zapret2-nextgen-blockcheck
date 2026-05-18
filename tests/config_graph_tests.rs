use std::{fs, path::PathBuf};
use zapret_checker::{
    config::AppConfig,
    graph::{select_diverse_nodes, StrategyGraph, StrategyNode},
};

#[test]
fn config_loads_checker_toml_and_validates_os_assigned_source_port() {
    let cfg = AppConfig::load(&PathBuf::from("config/checker.toml")).unwrap();
    assert_eq!(cfg.source_port.mode, "os_assigned");
    assert!(cfg.workers.count > 0);
    assert!(cfg.queue.qnum_count > 0);
    assert!(cfg.probe.protocols.tls12);
    assert!(!cfg.probe.protocols.tls13);
    assert!(cfg.probe.protocols.quic);
    assert_eq!(cfg.probe.protocols.preferred, "tls12");
    assert_eq!(cfg.strategies.successful_strategy_limit, 40);
    assert_eq!(cfg.strategies.search_mode, "expand");
    assert_eq!(cfg.strategies.max_candidates, 300);
    assert_eq!(cfg.strategies.max_per_family, 24);
    assert_eq!(cfg.strategies.max_per_action, 8);
    assert!(cfg.strategies.round_robin_families);
}

#[test]
fn config_accepts_expand_search_mode() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace("search_mode = \"expand\"", "search_mode = \"force\"");
    text = text.replace("max_candidates = 300", "max_candidates = 25");
    let path = std::env::temp_dir().join("zapret_checker_expand_mode.toml");
    fs::write(&path, text).unwrap();
    let cfg = AppConfig::load(&path).unwrap();
    assert_eq!(cfg.strategies.search_mode, "force");
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
        24,
        8,
        true,
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
        24,
        8,
        true,
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
        24,
        8,
        true,
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
        24,
        8,
        true,
    )
    .unwrap();
    assert_eq!(graph.nodes.len(), 3);
    assert!(graph.nodes.iter().all(|n| !n.args[0].contains("{{")));
}

fn node(family: &str, action_id: &str, idx: usize) -> StrategyNode {
    StrategyNode {
        id: format!("old_{family}_{action_id}_{idx}"),
        family: family.into(),
        action_id: action_id.into(),
        args: vec![format!("--lua-desync={family}:{action_id}:{idx}")],
        cost: match family {
            "split" => 2.0,
            "fake" => 3.0,
            "disorder" => 3.0,
            _ => 5.0,
        },
        risk: 1.0,
        prior: (4.0, 2.0),
    }
}

#[test]
fn diverse_selection_deduplicates_by_args() {
    let mut a = node("split", "multisplit_tls", 0);
    let mut b = node("split", "multisplit_tls", 1);
    b.args = a.args.clone();
    a.id = "a".into();
    b.id = "b".into();
    let selected = select_diverse_nodes(vec![a, b], "tls12", 10, 10, 10, true);
    assert_eq!(selected.len(), 1);
}

#[test]
fn diverse_selection_limits_per_action() {
    let nodes = (0..10)
        .map(|i| node("split", "multisplit_tls", i))
        .collect();
    let selected = select_diverse_nodes(nodes, "tls12", 20, 20, 3, true);
    assert_eq!(selected.len(), 3);
}

#[test]
fn diverse_selection_limits_per_family() {
    let nodes = (0..10)
        .map(|i| node("split", &format!("action{i}"), i))
        .collect();
    let selected = select_diverse_nodes(nodes, "tls12", 20, 4, 20, true);
    assert_eq!(selected.len(), 4);
}

#[test]
fn diverse_selection_round_robins_families_by_rank() {
    let mut nodes = Vec::new();
    for i in 0..3 {
        nodes.push(node("split", "a", i));
        nodes.push(node("fake", "a", i));
        nodes.push(node("disorder", "a", i));
    }
    let selected = select_diverse_nodes(nodes, "tls12", 9, 10, 10, true);
    let families = selected
        .iter()
        .map(|n| n.family.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        families,
        vec!["split", "fake", "disorder", "split", "fake", "disorder", "split", "fake", "disorder"]
    );
}

#[test]
fn diverse_selection_applies_max_candidates_and_reindexes_ids() {
    let mut nodes = Vec::new();
    for i in 0..100 {
        nodes.push(node("split", "a", i));
        nodes.push(node("fake", "b", i));
    }
    let selected = select_diverse_nodes(nodes, "tls12", 10, 100, 100, true);
    assert_eq!(selected.len(), 10);
    for (i, node) in selected.iter().enumerate() {
        assert_eq!(
            node.id,
            format!("tls12_{}_{}_{}", node.family, node.action_id, i)
        );
    }
}

#[test]
fn ordered_seed_preserves_graph_order() {
    let nodes = vec![node("fake", "a", 0), node("split", "a", 1)];
    let graph = StrategyGraph {
        nodes: nodes.clone(),
        transition_cost: Default::default(),
    };
    assert_eq!(
        graph
            .ordered_seed()
            .iter()
            .map(|n| n.id.as_str())
            .collect::<Vec<_>>(),
        nodes.iter().map(|n| n.id.as_str()).collect::<Vec<_>>()
    );
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
            .get(&("split".to_string(), "faked_split".to_string()))
            .copied(),
        Some(2.0)
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
