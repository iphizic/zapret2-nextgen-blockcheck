use std::{collections::BTreeMap, fs, path::PathBuf};
use zapret_checker::{
    config::{AllowedCombination, AppConfig, StrategyCombinationConfig, StrategyValuesConfig},
    graph::{
        generate_combined_nodes, select_diverse_nodes, GraphLoadOptions, StrategyComponent,
        StrategyGraph, StrategyNode,
    },
    payload_registry::PayloadAliases,
};

fn graph_options<'a>(
    protocol_key: &'a str,
    search_mode: &'a str,
    max_candidates: usize,
    max_per_family: usize,
    max_per_action: usize,
    payload_aliases: Option<&'a PayloadAliases>,
    strategy_values: Option<&'a StrategyValuesConfig>,
) -> GraphLoadOptions<'a> {
    GraphLoadOptions {
        protocol_key,
        search_mode,
        max_candidates,
        max_per_family,
        max_per_action,
        round_robin_families: true,
        payload_aliases,
        strategy_values,
        strategy_combinations: None,
    }
}

#[test]
fn config_loads_checker_toml_and_validates_os_assigned_source_port() {
    let cfg = AppConfig::load(&PathBuf::from("config/checker.toml")).unwrap();
    assert_eq!(cfg.source_port.mode, "os_assigned");
    assert!(cfg.workers.count > 0);
    assert!(cfg.isolation.queue_base > 0);
    assert!(cfg.probe.protocols.tls12);
    assert!(!cfg.probe.protocols.tls13);
    assert!(cfg.probe.protocols.quic);
    assert_eq!(cfg.probe.protocols.preferred, "tls12");
    assert_eq!(cfg.probe.dns.mode, "doh");
    assert_eq!(cfg.probe.dns.doh_addr, "1.1.1.1:443");
    assert_eq!(
        cfg.probe.dns.doh_addrs,
        [
            "1.1.1.1:443".to_string(),
            "104.16.248.249:443".to_string(),
            "104.16.249.249:443".to_string()
        ]
    );
    assert_eq!(cfg.probe.dns.doh_host, "cloudflare-dns.com");
    assert_eq!(cfg.probe.dns.doh_path, "/dns-query");
    assert_eq!(cfg.strategies.successful_strategy_limit, 10);
    assert_eq!(cfg.strategies.search_mode, "expand");
    assert!(cfg.strategies.round_robin_families);
    assert!(cfg.blobs.auto_load);
    assert_eq!(
        cfg.blobs.base_dir,
        Some(PathBuf::from("/opt/zapret/files/fake"))
    );
    assert_eq!(cfg.payloads.max_per_protocol, 16);
    assert_eq!(cfg.payloads.http.builtin, ["fake_default_http"]);
    assert!(cfg.payloads.http.aliases.contains_key("http_iana_org"));
    assert_eq!(cfg.payloads.tls.builtin, ["fake_default_tls"]);
    assert!(cfg.payloads.tls.aliases.contains_key("tls_www_google_com"));
    assert_eq!(cfg.payloads.quic.builtin, ["fake_default_quic"]);
    assert!(cfg
        .payloads
        .quic
        .aliases
        .contains_key("quic_www_google_com"));
    assert_eq!(cfg.strategy_values.mode, "extend");
    assert_eq!(
        cfg.strategy_values.values_for_param("tls12", "payload"),
        Some(&vec!["tls_client_hello".to_string()])
    );
    assert!(cfg.strategy_combinations.enabled);
    assert!(cfg.strategy_combinations.require_different_family);
    assert!(!cfg.strategy_combinations.allow_same_action);
    assert_eq!(cfg.strategy_combinations.mode, "pairwise");
}

#[test]
fn config_accepts_expand_search_mode() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace("search_mode = \"expand\"", "search_mode = \"force\"");
    let path = std::env::temp_dir().join("zapret_checker_expand_mode.toml");
    fs::write(&path, text).unwrap();
    let cfg = AppConfig::load(&path).unwrap();
    assert_eq!(cfg.strategies.search_mode, "force");
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
fn strategy_values_rejects_invalid_mode() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace("mode = \"extend\"", "mode = \"bad\"");
    let path = std::env::temp_dir().join("zapret_checker_bad_strategy_values_mode.toml");
    fs::write(&path, text).unwrap();
    let err = AppConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("strategy_values.mode must be extend or override"));
}

#[test]
fn strategy_combinations_default_is_disabled() {
    let config = zapret_checker::config::StrategyCombinationConfig::default();
    assert!(!config.enabled);
    assert!(!config.pair_allowed("tls12", "fake", "split"));
}

#[test]
fn strategy_combinations_rejects_invalid_protocol() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace(
        "protocols = [\"tls12\", \"tls13\"]",
        "protocols = [\"tls11\", \"tls13\"]",
    );
    let path = std::env::temp_dir().join("zapret_checker_bad_combination_protocol.toml");
    fs::write(&path, text).unwrap();
    let err = AppConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("unsupported protocol"));
}

#[test]
fn strategy_combinations_rejects_family_count_not_two() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace(
        "families = [\"fake\", \"split\"]",
        "families = [\"fake\", \"split\", \"wsize\"]",
    );
    let path = std::env::temp_dir().join("zapret_checker_bad_combination_family_count.toml");
    fs::write(&path, text).unwrap();
    let err = AppConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("must contain exactly 2 families"));
}

#[test]
fn strategy_combinations_pair_allowed_is_unordered() {
    let mut cfg = AppConfig::load(&PathBuf::from("config/checker.toml")).unwrap();
    cfg.strategy_combinations.enabled = true;

    assert!(cfg
        .strategy_combinations
        .pair_allowed("tls12", "split", "fake"));
    assert!(cfg
        .strategy_combinations
        .pair_allowed("tls13", "fake", "split"));
    assert!(!cfg
        .strategy_combinations
        .pair_allowed("tls12", "fake", "udp_len"));
}

#[test]
fn strategy_combinations_disabled_pair_allowed_is_false() {
    let mut cfg = AppConfig::load(&PathBuf::from("config/checker.toml")).unwrap();
    cfg.strategy_combinations.enabled = false;
    assert!(!cfg
        .strategy_combinations
        .pair_allowed("tls12", "fake", "split"));
}

#[test]
fn strategy_combinations_force_mode_allows_pair() {
    let mut cfg = AppConfig::load(&PathBuf::from("config/checker.toml")).unwrap();
    cfg.strategy_combinations.enabled = true;
    cfg.strategy_combinations.mode = "force".to_string();

    assert!(cfg
        .strategy_combinations
        .pair_allowed("tls12", "fake", "udp_len"));
    assert!(!cfg
        .strategy_combinations
        .pair_allowed("tls12", "fake", "fake"));
}

#[test]
fn payload_config_defaults_load_from_checker_toml() {
    let cfg = AppConfig::load(&PathBuf::from("config/checker.toml")).unwrap();
    assert!(cfg.blobs.auto_load);
    assert_eq!(
        cfg.blobs.base_dir,
        Some(PathBuf::from("/opt/zapret/files/fake"))
    );
    assert_eq!(cfg.payloads.max_per_protocol, 16);
    assert_eq!(cfg.payloads.http.builtin, ["fake_default_http"]);
    assert!(cfg.payloads.http.files.is_empty());
    assert_eq!(
        cfg.payloads.http.aliases.get("http_iana_org"),
        Some(&PathBuf::from("http_iana_org.bin"))
    );
    assert_eq!(cfg.payloads.tls.builtin, ["fake_default_tls"]);
    assert!(cfg.payloads.tls.files.is_empty());
    assert_eq!(cfg.payloads.tls.aliases.len(), 7);
    assert_eq!(cfg.payloads.quic.builtin, ["fake_default_quic"]);
    assert!(cfg.payloads.quic.files.is_empty());
    assert_eq!(cfg.payloads.quic.aliases.len(), 11);
}

#[test]
fn payload_config_auto_load_false_allows_missing_base_dir() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace("auto_load = true", "auto_load = false");
    text = text.replace(
        "base_dir = \"/opt/zapret/files/fake\"",
        "base_dir = \"/tmp/zapret_checker_missing_payload_blobs\"",
    );
    let path = std::env::temp_dir().join("zapret_checker_missing_base_dir.toml");
    fs::write(&path, text).unwrap();
    let cfg = AppConfig::load(&path).unwrap();
    assert!(!cfg.blobs.auto_load);
}

#[test]
fn payload_config_auto_load_true_requires_base_dir() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace("base_dir = \"/opt/zapret/files/fake\"\n", "");
    let path = std::env::temp_dir().join("zapret_checker_auto_load_without_base_dir.toml");
    fs::write(&path, text).unwrap();
    let err = AppConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("blobs.base_dir is required"));
}

#[test]
fn payload_config_rejects_duplicate_alias_between_protocols() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace(
        "[payloads.http.aliases]\n",
        "[payloads.http.aliases]\nshared = \"http.bin\"\n",
    );
    text = text.replace(
        "[payloads.tls.aliases]\n",
        "[payloads.tls.aliases]\nshared = \"tls.bin\"\n",
    );
    let path = std::env::temp_dir().join("zapret_checker_duplicate_payload_alias.toml");
    fs::write(&path, text).unwrap();
    let err = AppConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("duplicated between http and tls"));
}

#[test]
fn payload_config_rejects_alias_with_hyphen() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace(
        "[payloads.tls.aliases]\n",
        "[payloads.tls.aliases]\ntls-google = \"tls.bin\"\n",
    );
    let path = std::env::temp_dir().join("zapret_checker_bad_payload_alias.toml");
    fs::write(&path, text).unwrap();
    let err = AppConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("must contain only ASCII letters, digits or underscore"));
}

#[test]
fn payload_config_rejects_zero_max_per_protocol() {
    let mut text = fs::read_to_string("config/checker.toml").unwrap();
    text = text.replace("max_per_protocol = 16", "max_per_protocol = 0");
    let path = std::env::temp_dir().join("zapret_checker_zero_payload_max.toml");
    fs::write(&path, text).unwrap();
    let err = AppConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("payloads.max_per_protocol must be greater than zero"));
}

#[test]
fn signal_tls12_generates_more_than_nine_candidates_without_placeholders() {
    let graph = StrategyGraph::load_for_protocol_mode(
        &PathBuf::from("config/standart/strategies.yaml"),
        graph_options("tls12", "signal", 200, 24, 8, None, None),
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
        graph_options("tls12", "expand", 7, 24, 8, None, None),
    )
    .unwrap();
    assert_eq!(graph.nodes.len(), 7);
    assert!(graph.nodes.iter().all(|n| n.id.starts_with("tls12_")));
}

#[test]
fn signal_cartesian_product_expands_split_positions() {
    let graph = StrategyGraph::load_for_protocol_mode(
        &PathBuf::from("config/standart/strategies.yaml"),
        graph_options("tls12", "signal", 200, 24, 8, None, None),
    )
    .unwrap();
    let split_count = graph
        .nodes
        .iter()
        .filter(|n| {
            n.family == "split"
                && n.args
                    .iter()
                    .any(|arg| arg.contains("multisplit:payload=tls_client_hello"))
        })
        .count();
    assert!(split_count >= 7, "got {split_count}");
}

#[test]
fn catalog_strategy_adds_payload_filter_before_lua_desync() {
    let graph = StrategyGraph::load_for_protocol_mode(
        &PathBuf::from("config/standart/strategies.yaml"),
        graph_options("tls12", "signal", 200, 24, 8, None, None),
    )
    .unwrap();
    let node = graph
        .nodes
        .iter()
        .find(|n| {
            n.args
                .iter()
                .any(|arg| arg.contains("multisplit:payload=tls_client_hello"))
        })
        .unwrap();
    assert_eq!(node.args[0], "--payload=tls_client_hello");
    assert!(node.args[1].starts_with("--lua-desync="));
}

#[test]
fn catalog_strategy_infers_payload_option_when_lua_function_uses_standard_payload() {
    let graph = StrategyGraph::load_for_protocol_mode(
        &PathBuf::from("config/standart/strategies.yaml"),
        graph_options("tls12", "signal", 400, 24, 8, None, None),
    )
    .unwrap();
    let node = graph
        .nodes
        .iter()
        .find(|n| n.args.iter().any(|arg| arg.contains("tcpseg:pos=")))
        .unwrap();
    assert_eq!(node.args[0], "--payload=tls_client_hello");
    assert!(node.args[1].starts_with("--lua-desync=tcpseg:"));
}

#[test]
fn fake_dir_blob_generates_separate_blob_option() {
    let base =
        std::env::temp_dir().join(format!("zapret_checker_fake_blobs_{}", std::process::id()));
    let fake_dir = base.join("fake");
    fs::create_dir_all(&fake_dir).unwrap();
    let fake_file = fake_dir.join("tls_fake.bin");
    fs::write(&fake_file, [0x16, 0x03, 0x01]).unwrap();

    let strategies_path = base.join("strategies.yaml");
    fs::write(
        &strategies_path,
        format!(
            r#"
families:
  - id: fake
    enabled: true
    protocols: [tls12]
    cost: 1
    risk: 1
    prior: [2, 2]
    actions:
      - id: tls_blob_file
        protocols: [tls12]
        params:
          blob:
            values: ["fake_dir_tls:{}"]
        render:
          lua_desync: "fake:payload=tls_client_hello:blob={{{{blob}}}}"
candidate_generators:
  signal:
    tls12:
      - family: fake
        actions: [tls_blob_file]
"#,
            fake_dir.display()
        ),
    )
    .unwrap();

    let graph = StrategyGraph::load_for_protocol_mode(
        &strategies_path,
        graph_options("tls12", "signal", 20, 24, 8, None, None),
    )
    .unwrap();
    let node = graph.nodes.first().unwrap();
    assert_eq!(
        node.args[0],
        format!("--blob=fake_tls_tls_fake_bin:@{}", fake_file.display())
    );
    assert_eq!(node.args[1], "--payload=tls_client_hello");
    assert_eq!(
        node.args[2],
        "--lua-desync=fake:payload=tls_client_hello:blob=fake_tls_tls_fake_bin"
    );
}

#[test]
fn unresolved_placeholder_variant_is_skipped() {
    let strategies_path = std::env::temp_dir().join("zapret_checker_unresolved_strategies.yaml");
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
    let graph = StrategyGraph::load_for_protocol_mode(
        &strategies_path,
        graph_options("tls12", "signal", 20, 24, 8, None, None),
    )
    .unwrap();
    assert_eq!(graph.nodes.len(), 3);
    assert!(graph
        .nodes
        .iter()
        .all(|n| n.args.iter().all(|arg| !arg.contains("{{"))));
}

#[test]
fn runtime_tls_payload_aliases_extend_tls12_and_tls13_blob_values() {
    let aliases = PayloadAliases {
        tls: vec!["tls_google".to_string()],
        ..PayloadAliases::default()
    };

    let tls12 = graph_with_runtime_payload_aliases(
        "runtime_tls_aliases_tls12",
        "tls12",
        "blob",
        "fake:payload=tls_client_hello:blob={{blob}}",
        Some(&aliases),
    );
    let tls13 = graph_with_runtime_payload_aliases(
        "runtime_tls_aliases_tls13",
        "tls13",
        "blob",
        "fake:payload=tls_client_hello:blob={{blob}}",
        Some(&aliases),
    );

    assert!(graph_args_contain(&tls12, "blob=tls_google"));
    assert!(graph_args_contain(&tls13, "blob=tls_google"));
}

#[test]
fn checker_toml_payload_aliases_extend_tls_blob_values() {
    let cfg = AppConfig::load(&PathBuf::from("config/checker.toml")).unwrap();
    let aliases = PayloadAliases {
        http: cfg.payloads.http.aliases.keys().cloned().collect(),
        tls: cfg.payloads.tls.aliases.keys().cloned().collect(),
        quic: cfg.payloads.quic.aliases.keys().cloned().collect(),
    };
    let graph = graph_with_runtime_payload_aliases(
        "checker_toml_payload_aliases_tls",
        "tls12",
        "blob",
        "fake:payload=tls_client_hello:blob={{blob}}",
        Some(&aliases),
    );

    assert!(graph_args_contain(&graph, "blob=tls_www_google_com"));
}

#[test]
fn runtime_http_payload_aliases_extend_only_http_blob_values() {
    let aliases = PayloadAliases {
        http: vec!["http_custom".to_string()],
        tls: vec!["tls_custom".to_string()],
        quic: vec!["quic_custom".to_string()],
    };

    let graph = graph_with_runtime_payload_aliases(
        "runtime_http_aliases",
        "http",
        "blob",
        "fake:payload=http_req:blob={{blob}}",
        Some(&aliases),
    );

    assert!(graph_args_contain(&graph, "blob=http_custom"));
    assert!(!graph_args_contain(&graph, "blob=tls_custom"));
    assert!(!graph_args_contain(&graph, "blob=quic_custom"));
}

#[test]
fn runtime_quic_payload_aliases_extend_only_quic_blob_values() {
    let aliases = PayloadAliases {
        http: vec!["http_custom".to_string()],
        tls: vec!["tls_custom".to_string()],
        quic: vec!["quic_custom".to_string()],
    };

    let graph = graph_with_runtime_payload_aliases(
        "runtime_quic_aliases",
        "quic",
        "blob",
        "fake:payload=quic_initial:blob={{blob}}",
        Some(&aliases),
    );

    assert!(graph_args_contain(&graph, "blob=quic_custom"));
    assert!(!graph_args_contain(&graph, "blob=http_custom"));
    assert!(!graph_args_contain(&graph, "blob=tls_custom"));
}

#[test]
fn runtime_payload_aliases_are_deduped_after_yaml_values() {
    let aliases = PayloadAliases {
        tls: vec!["fake_default_tls".to_string(), "tls_google".to_string()],
        ..PayloadAliases::default()
    };

    let graph = graph_with_runtime_payload_aliases(
        "runtime_payload_alias_dedup",
        "tls12",
        "blob",
        "fake:payload=tls_client_hello:blob={{blob}}",
        Some(&aliases),
    );

    assert_eq!(graph.nodes.len(), 2);
    assert_eq!(graph_arg_match_count(&graph, "blob=fake_default_tls"), 1);
    assert_eq!(graph_arg_match_count(&graph, "blob=tls_google"), 1);
}

#[test]
fn runtime_payload_aliases_do_not_extend_non_blob_params() {
    let aliases = PayloadAliases {
        tls: vec!["tls_google".to_string()],
        ..PayloadAliases::default()
    };

    let graph = graph_with_runtime_payload_aliases(
        "runtime_payload_alias_non_blob_param",
        "tls12",
        "marker",
        "fake:payload=tls_client_hello:marker={{marker}}",
        Some(&aliases),
    );

    assert_eq!(graph.nodes.len(), 1);
    assert!(graph_args_contain(&graph, "marker=yaml_marker"));
    assert!(!graph_args_contain(&graph, "tls_google"));
}

#[test]
fn generated_args_include_runtime_blob_alias_for_fake_action() {
    let aliases = PayloadAliases {
        tls: vec!["tls_google".to_string()],
        ..PayloadAliases::default()
    };

    let graph = graph_with_runtime_payload_aliases(
        "runtime_payload_alias_fake_action_args",
        "tls12",
        "blob",
        "fake:payload=tls_client_hello:blob={{blob}}",
        Some(&aliases),
    );

    assert!(graph
        .nodes
        .iter()
        .flat_map(|node| node.args.iter())
        .any(|arg| arg == "--lua-desync=fake:payload=tls_client_hello:blob=tls_google"));
}

#[test]
fn strategy_values_extend_yaml_values() {
    let strategy_values = strategy_values("extend", "tls", "marker", ["b"]);

    let graph = graph_with_runtime_values(
        "strategy_values_extend",
        "tls12",
        "marker",
        "fake:payload=tls_client_hello:marker={{marker}}",
        None,
        Some(&strategy_values),
    );

    assert_eq!(graph.nodes.len(), 2);
    assert!(graph_args_contain(&graph, "marker=yaml_marker"));
    assert!(graph_args_contain(&graph, "marker=b"));
}

#[test]
fn strategy_values_override_yaml_values() {
    let strategy_values = strategy_values("override", "tls", "marker", ["b"]);

    let graph = graph_with_runtime_values(
        "strategy_values_override",
        "tls12",
        "marker",
        "fake:payload=tls_client_hello:marker={{marker}}",
        None,
        Some(&strategy_values),
    );

    assert_eq!(graph.nodes.len(), 1);
    assert!(!graph_args_contain(&graph, "marker=yaml_marker"));
    assert!(graph_args_contain(&graph, "marker=b"));
}

#[test]
fn strategy_values_extend_dedups_preserving_yaml_order() {
    let strategy_values = strategy_values("extend", "tls", "marker", ["yaml_marker", "b"]);

    let graph = graph_with_runtime_values(
        "strategy_values_dedup",
        "tls12",
        "marker",
        "fake:payload=tls_client_hello:marker={{marker}}",
        None,
        Some(&strategy_values),
    );

    assert_eq!(graph.nodes.len(), 2);
    assert_eq!(graph_arg_match_count(&graph, "marker=yaml_marker"), 1);
    assert_eq!(graph_arg_match_count(&graph, "marker=b"), 1);
}

#[test]
fn strategy_values_tls_map_applies_to_tls12_and_tls13() {
    let strategy_values = strategy_values("override", "tls", "marker", ["tls_marker"]);

    let tls12 = graph_with_runtime_values(
        "strategy_values_tls12",
        "tls12",
        "marker",
        "fake:payload=tls_client_hello:marker={{marker}}",
        None,
        Some(&strategy_values),
    );
    let tls13 = graph_with_runtime_values(
        "strategy_values_tls13",
        "tls13",
        "marker",
        "fake:payload=tls_client_hello:marker={{marker}}",
        None,
        Some(&strategy_values),
    );

    assert!(graph_args_contain(&tls12, "marker=tls_marker"));
    assert!(graph_args_contain(&tls13, "marker=tls_marker"));
}

#[test]
fn strategy_values_blob_keeps_payload_alias_injection() {
    let aliases = PayloadAliases {
        tls: vec!["tls_google".to_string()],
        ..PayloadAliases::default()
    };
    let strategy_values = strategy_values("override", "tls", "blob", ["tls_config_blob"]);

    let graph = graph_with_runtime_values(
        "strategy_values_blob_payload_alias",
        "tls12",
        "blob",
        "fake:payload=tls_client_hello:blob={{blob}}",
        Some(&aliases),
        Some(&strategy_values),
    );

    assert_eq!(graph.nodes.len(), 2);
    assert!(graph_args_contain(&graph, "blob=tls_config_blob"));
    assert!(graph_args_contain(&graph, "blob=tls_google"));
}

#[test]
fn strategy_values_payload_param_generates_config_payload_value() {
    let strategy_values = strategy_values("override", "tls", "payload", ["tls_client_hello"]);

    let graph = graph_with_runtime_values(
        "strategy_values_payload_param",
        "tls12",
        "payload",
        "fake:payload={{payload}}",
        None,
        Some(&strategy_values),
    );

    assert!(graph
        .nodes
        .iter()
        .flat_map(|node| node.args.iter())
        .any(|arg| arg == "--lua-desync=fake:payload=tls_client_hello"));
}

fn graph_with_runtime_payload_aliases(
    test_name: &str,
    protocol_key: &str,
    param_name: &str,
    lua_desync: &str,
    runtime_payload_aliases: Option<&PayloadAliases>,
) -> StrategyGraph {
    graph_with_runtime_values(
        test_name,
        protocol_key,
        param_name,
        lua_desync,
        runtime_payload_aliases,
        None,
    )
}

fn graph_with_runtime_values(
    test_name: &str,
    protocol_key: &str,
    param_name: &str,
    lua_desync: &str,
    runtime_payload_aliases: Option<&PayloadAliases>,
    runtime_strategy_values: Option<&StrategyValuesConfig>,
) -> StrategyGraph {
    let base = std::env::temp_dir().join(format!(
        "zapret_checker_runtime_payload_aliases_{}_{}",
        test_name,
        std::process::id()
    ));
    fs::create_dir_all(&base).unwrap();
    let strategies_path = base.join("strategies.yaml");
    let yaml_value = if param_name == "blob" {
        match protocol_key {
            "http" => "fake_default_http",
            "quic" => "fake_default_quic",
            _ => "fake_default_tls",
        }
    } else if param_name == "payload" {
        "yaml_payload"
    } else {
        "yaml_marker"
    };

    fs::write(
        &strategies_path,
        format!(
            r#"
families:
  - id: fake
    enabled: true
    protocols: [{protocol_key}]
    cost: 1
    risk: 1
    prior: [2, 2]
    actions:
      - id: runtime_payload
        protocols: [{protocol_key}]
        params:
          {param_name}:
            values: [{yaml_value}]
            default: {yaml_value}
        render:
          lua_desync: "{lua_desync}"
candidate_generators:
  signal:
    {protocol_key}:
      - family: fake
        actions: [runtime_payload]
"#
        ),
    )
    .unwrap();

    StrategyGraph::load_for_protocol_mode(
        &strategies_path,
        graph_options(
            protocol_key,
            "signal",
            20,
            20,
            20,
            runtime_payload_aliases,
            runtime_strategy_values,
        ),
    )
    .unwrap()
}

fn strategy_values<const N: usize>(
    mode: &str,
    protocol: &str,
    param: &str,
    values: [&str; N],
) -> StrategyValuesConfig {
    let mut map = BTreeMap::new();
    map.insert(
        param.to_string(),
        values.iter().map(|value| value.to_string()).collect(),
    );
    let mut config = StrategyValuesConfig {
        mode: mode.to_string(),
        ..StrategyValuesConfig::default()
    };
    match protocol {
        "http" => config.http = map,
        "tls" => config.tls = map,
        "quic" => config.quic = map,
        _ => {}
    }
    config
}

fn graph_args_contain(graph: &StrategyGraph, needle: &str) -> bool {
    graph
        .nodes
        .iter()
        .flat_map(|node| node.args.iter())
        .any(|arg| arg.contains(needle))
}

fn graph_arg_match_count(graph: &StrategyGraph, needle: &str) -> usize {
    graph
        .nodes
        .iter()
        .flat_map(|node| node.args.iter())
        .filter(|arg| arg.contains(needle))
        .count()
}

fn node(family: &str, action_id: &str, idx: usize) -> StrategyNode {
    StrategyNode {
        id: format!("old_{family}_{action_id}_{idx}"),
        family: family.into(),
        action_id: action_id.into(),
        args: vec![format!("--lua-desync={family}:{action_id}:{idx}")],
        components: vec![StrategyComponent {
            family: family.into(),
            action_id: action_id.into(),
            args: vec![format!("--lua-desync={family}:{action_id}:{idx}")],
        }],
        is_combined: false,
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

fn combination_config() -> StrategyCombinationConfig {
    StrategyCombinationConfig {
        enabled: true,
        require_different_family: true,
        allow_same_action: false,
        mode: "pairwise".to_string(),
        allowed: vec![AllowedCombination {
            protocols: vec!["tls12".to_string()],
            families: vec!["fake".to_string(), "split".to_string()],
        }],
    }
}

#[test]
fn combined_fake_split_allowed_generates_node() {
    let nodes = vec![node("fake", "fake_a", 0), node("split", "split_a", 0)];
    let combined = generate_combined_nodes("tls12", &nodes, &combination_config());

    assert_eq!(combined.len(), 1);
    assert!(combined[0].is_combined);
    assert_eq!(combined[0].family, "combined_fake_split");
}

#[test]
fn combined_split_fake_does_not_generate_reverse_duplicate() {
    let nodes = vec![node("split", "split_a", 0), node("fake", "fake_a", 0)];
    let combined = generate_combined_nodes("tls12", &nodes, &combination_config());

    assert_eq!(combined.len(), 1);
    assert_eq!(combined[0].family, "combined_fake_split");
}

#[test]
fn combined_disallowed_pair_is_not_generated() {
    let nodes = vec![node("fake", "fake_a", 0), node("wsize", "wsize_a", 0)];
    let combined = generate_combined_nodes("tls12", &nodes, &combination_config());

    assert!(combined.is_empty());
}

#[test]
fn combined_legacy_action_is_not_used() {
    let nodes = vec![node("fake", "fake_legacy", 0), node("split", "split_a", 0)];
    let combined = generate_combined_nodes("tls12", &nodes, &combination_config());

    assert!(combined.is_empty());
}

#[test]
fn combined_same_family_blocked_when_required() {
    let mut cfg = combination_config();
    cfg.allowed = vec![AllowedCombination {
        protocols: vec!["tls12".to_string()],
        families: vec!["fake".to_string(), "fake".to_string()],
    }];
    let nodes = vec![node("fake", "fake_a", 0), node("fake", "fake_b", 1)];
    let combined = generate_combined_nodes("tls12", &nodes, &cfg);

    assert!(combined.is_empty());
}

#[test]
fn combined_same_action_blocked_when_not_allowed() {
    let nodes = vec![
        node("fake", "same_action", 0),
        node("split", "same_action", 0),
    ];
    let combined = generate_combined_nodes("tls12", &nodes, &combination_config());

    assert!(combined.is_empty());
}

#[test]
fn combined_args_are_concatenated_without_joining() {
    let fake = node("fake", "fake_a", 0);
    let split = node("split", "split_a", 0);
    let combined = generate_combined_nodes(
        "tls12",
        &[split.clone(), fake.clone()],
        &combination_config(),
    );

    assert_eq!(combined.len(), 1);
    assert_eq!(
        combined[0].args,
        [fake.args[0].clone(), split.args[0].clone()]
    );
}

#[test]
fn combined_components_len_is_two() {
    let nodes = vec![node("fake", "fake_a", 0), node("split", "split_a", 0)];
    let combined = generate_combined_nodes("tls12", &nodes, &combination_config());

    assert_eq!(combined[0].components.len(), 2);
}

#[test]
fn combined_output_is_deterministic() {
    let nodes = vec![
        node("split", "split_b", 1),
        node("fake", "fake_b", 1),
        node("split", "split_a", 0),
        node("fake", "fake_a", 0),
    ];
    let first = generate_combined_nodes("tls12", &nodes, &combination_config());
    let second = generate_combined_nodes("tls12", &nodes, &combination_config());

    assert_eq!(
        first.iter().map(|node| &node.args).collect::<Vec<_>>(),
        second.iter().map(|node| &node.args).collect::<Vec<_>>()
    );
    assert_eq!(
        first.iter().map(|node| &node.id).collect::<Vec<_>>(),
        second.iter().map(|node| &node.id).collect::<Vec<_>>()
    );
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
fn config_loads_without_transition_matrix() {
    let cfg = AppConfig::load(&PathBuf::from("config/checker.toml")).unwrap();
    assert!(cfg.strategies.transition_matrix.is_none());
}

#[test]
fn graph_loads_without_transition_path() {
    let graph = StrategyGraph::load(&PathBuf::from("config/standart/strategies.yaml")).unwrap();
    assert!(!graph.nodes.is_empty());
}

#[test]
fn legacy_actions_are_not_generated() {
    let strategies_path =
        std::env::temp_dir().join("zapret_checker_legacy_actions_strategies.yaml");
    fs::write(
        &strategies_path,
        r#"
families:
  - id: fake
    enabled: true
    protocols: [tls12]
    cost: 1
    risk: 1
    prior: [2, 2]
    actions:
      - id: good
        protocols: [tls12]
        params: {}
        render:
          lua_desync: "fake:payload=tls_client_hello"
      - id: fake_legacy
        protocols: [tls12]
        params: {}
        render:
          lua_desync: "fake:payload=tls_client_hello:pattern=random"
candidate_generators:
  signal:
    tls12:
      - family: fake
        actions: [good, fake_legacy]
"#,
    )
    .unwrap();
    let graph = StrategyGraph::load_for_protocol_mode(
        &strategies_path,
        graph_options("tls12", "signal", 20, 24, 8, None, None),
    )
    .unwrap();
    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(graph.nodes[0].action_id, "good");
}

#[test]
fn diverse_selection_is_deterministic() {
    let nodes = vec![
        node("disorder", "z", 2),
        node("split", "a", 0),
        node("fake", "b", 1),
        node("split", "a", 1),
    ];
    let first = select_diverse_nodes(nodes.clone(), "tls12", 10, 10, 10, false);
    let second = select_diverse_nodes(nodes, "tls12", 10, 10, 10, false);
    assert_eq!(
        first.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(),
        second.iter().map(|n| n.id.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn ordered_seed_preserves_graph_order() {
    let nodes = vec![node("fake", "a", 0), node("split", "a", 1)];
    let graph = StrategyGraph {
        nodes: nodes.clone(),
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
fn strategy_graph_loads_standart_catalog_without_transition_matrix() {
    let graph = StrategyGraph::load(&PathBuf::from("config/standart/strategies.yaml")).unwrap();
    assert!(!graph.nodes.is_empty());
    assert!(graph.nodes.iter().all(|n| n.id.starts_with("tls13_")));
}

#[test]
fn custom_strategy_dir_schema_still_loads_simple_files() {
    let graph = StrategyGraph::load(&PathBuf::from("config/custom/strategies.yaml")).unwrap();
    assert_eq!(graph.nodes.len(), 3);
}
