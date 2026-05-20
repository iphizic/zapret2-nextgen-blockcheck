use crate::{
    config::{StrategyCombinationConfig, StrategyValuesConfig},
    payload_registry::PayloadAliases,
};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
};

const DEFAULT_FAKE_BLOB_DIR: &str = "/opt/zapret2/files/fake";
const BLOB_FILE_SENTINEL: &str = "__zapret_checker_blob_file__";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyNode {
    pub id: String,
    pub family: String,
    #[serde(default = "default_action_id")]
    pub action_id: String,
    pub args: Vec<String>,
    #[serde(default, rename = "strategy_components")]
    pub components: Vec<StrategyComponent>,
    #[serde(default)]
    pub is_combined: bool,
    pub cost: f64,
    pub risk: f64,
    pub prior: (f64, f64),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StrategyComponent {
    pub family: String,
    pub action_id: String,
    pub args: Vec<String>,
}

fn default_action_id() -> String {
    "manual".into()
}

#[derive(Debug, Clone, Default)]
pub struct StrategyGraph {
    pub nodes: Vec<StrategyNode>,
}

#[derive(Debug, Clone, Copy)]
pub struct GraphLoadOptions<'a> {
    pub protocol_key: &'a str,
    pub search_mode: &'a str,
    pub max_candidates: usize,
    pub max_per_family: usize,
    pub max_per_action: usize,
    pub round_robin_families: bool,
    pub payload_aliases: Option<&'a PayloadAliases>,
    pub strategy_values: Option<&'a StrategyValuesConfig>,
    pub strategy_combinations: Option<&'a StrategyCombinationConfig>,
}

impl StrategyGraph {
    pub fn ordered_seed(&self) -> Vec<StrategyNode> {
        self.nodes.clone()
    }

    #[allow(dead_code)]
    pub fn load_for_protocol(strategies_path: &Path, protocol_key: &str) -> anyhow::Result<Self> {
        Self::load_for_protocol_mode(
            strategies_path,
            GraphLoadOptions {
                protocol_key,
                search_mode: "signal",
                max_candidates: no_strategy_limit(),
                max_per_family: no_strategy_limit(),
                max_per_action: no_strategy_limit(),
                round_robin_families: default_round_robin_families(),
                payload_aliases: None,
                strategy_values: None,
                strategy_combinations: None,
            },
        )
    }

    pub fn load_for_protocol_mode(
        strategies_path: &Path,
        options: GraphLoadOptions<'_>,
    ) -> anyhow::Result<Self> {
        let strategies_text = std::fs::read_to_string(strategies_path)?;
        let strategies_yaml: Value = serde_yaml::from_str(&strategies_text)?;

        let mut nodes = if let Some(strategies) = value_seq(&strategies_yaml, "strategies") {
            select_diverse_nodes(
                parse_simple_strategies(strategies)?,
                options.protocol_key,
                options.max_candidates,
                options.max_per_family,
                options.max_per_action,
                options.round_robin_families,
            )
        } else {
            parse_catalog_strategies(
                &strategies_yaml,
                options.protocol_key,
                options.search_mode,
                options.max_candidates,
                options.max_per_family,
                options.max_per_action,
                options.round_robin_families,
                options.payload_aliases,
                options.strategy_values,
            )?
        };
        if let Some(strategy_combinations) = options.strategy_combinations {
            let remaining = options.max_candidates.saturating_sub(nodes.len());
            if remaining > 0 {
                let mut combined =
                    generate_combined_nodes(options.protocol_key, &nodes, strategy_combinations);
                combined.truncate(remaining);
                nodes.extend(combined);
            }
        }

        Ok(Self { nodes })
    }

    #[allow(dead_code)]
    pub fn load(strategies_path: &Path) -> anyhow::Result<Self> {
        Self::load_for_protocol_mode(
            strategies_path,
            GraphLoadOptions {
                protocol_key: "tls13",
                search_mode: "signal",
                max_candidates: no_strategy_limit(),
                max_per_family: no_strategy_limit(),
                max_per_action: no_strategy_limit(),
                round_robin_families: default_round_robin_families(),
                payload_aliases: None,
                strategy_values: None,
                strategy_combinations: None,
            },
        )
    }
}

pub fn no_strategy_limit() -> usize {
    usize::MAX
}

fn default_round_robin_families() -> bool {
    true
}

fn parse_simple_strategies(strategies: &[Value]) -> anyhow::Result<Vec<StrategyNode>> {
    let mut nodes: Vec<StrategyNode> = strategies
        .iter()
        .cloned()
        .map(serde_yaml::from_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?;
    for node in &mut nodes {
        if node.action_id.is_empty() || node.action_id == "manual" {
            node.action_id = node.family.clone();
        }
        normalize_single_node(node);
    }
    Ok(nodes)
}

fn parse_catalog_strategies(
    root: &Value,
    protocol_key: &str,
    search_mode: &str,
    max_candidates: usize,
    max_per_family: usize,
    max_per_action: usize,
    round_robin_families: bool,
    runtime_payload_aliases: Option<&PayloadAliases>,
    runtime_strategy_values: Option<&StrategyValuesConfig>,
) -> anyhow::Result<Vec<StrategyNode>> {
    let families = value_seq(root, "families")
        .ok_or_else(|| anyhow::anyhow!("strategy catalog missing strategies/families"))?;
    let catalog = catalog_families(families);
    let catalog_order = families
        .iter()
        .filter_map(|family| family.get("id").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let mut nodes = Vec::new();
    let mut seen = HashSet::new();

    match search_mode {
        "signal" => {
            let candidates = root
                .get("candidate_generators")
                .and_then(|v| v.get("signal"))
                .and_then(|v| v.get(protocol_key))
                .and_then(Value::as_sequence)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "strategy catalog missing candidate_generators.signal.{protocol_key}"
                    )
                })?;
            for candidate in candidates {
                let Some(family_id) = candidate.get("family").and_then(Value::as_str) else {
                    continue;
                };
                append_family_actions(
                    root,
                    &catalog,
                    protocol_key,
                    family_id,
                    Some(candidate),
                    false,
                    runtime_payload_aliases,
                    runtime_strategy_values,
                    &mut nodes,
                    &mut seen,
                );
            }
        }
        "expand" => {
            let family_order = root
                .get("candidate_generators")
                .and_then(|v| v.get("expand"))
                .and_then(|v| v.get(protocol_key))
                .and_then(|v| v.get("family_order"))
                .and_then(Value::as_sequence)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "strategy catalog missing candidate_generators.expand.{protocol_key}.family_order"
                    )
                })?;
            for family_id in family_order.iter().filter_map(Value::as_str) {
                append_family_actions(
                    root,
                    &catalog,
                    protocol_key,
                    family_id,
                    None,
                    true,
                    runtime_payload_aliases,
                    runtime_strategy_values,
                    &mut nodes,
                    &mut seen,
                );
            }
        }
        "force" => {
            for family_id in catalog_order {
                append_family_actions(
                    root,
                    &catalog,
                    protocol_key,
                    family_id,
                    None,
                    true,
                    runtime_payload_aliases,
                    runtime_strategy_values,
                    &mut nodes,
                    &mut seen,
                );
            }
        }
        _ => anyhow::bail!("unsupported search mode: {search_mode}"),
    }

    if nodes.is_empty() {
        anyhow::bail!(
            "strategy catalog produced no concrete {protocol_key} candidates for mode {search_mode}"
        );
    }

    Ok(select_diverse_nodes(
        nodes,
        protocol_key,
        max_candidates,
        max_per_family,
        max_per_action,
        round_robin_families,
    ))
}

#[derive(Debug, Clone)]
struct CatalogFamily {
    id: String,
    enabled: bool,
    protocols: Vec<String>,
    cost: f64,
    risk: f64,
    prior: (f64, f64),
    actions: Vec<CatalogAction>,
}

#[derive(Debug, Clone)]
struct CatalogAction {
    id: String,
    protocols: Vec<String>,
    template: String,
    params: Option<Value>,
}

fn catalog_families(families: &[Value]) -> HashMap<String, CatalogFamily> {
    let mut out = HashMap::new();
    for family in families {
        let Some(id) = family.get("id").and_then(Value::as_str) else {
            continue;
        };
        let actions = family
            .get("actions")
            .and_then(Value::as_sequence)
            .map(|actions| {
                actions
                    .iter()
                    .filter_map(|action| {
                        let id = action.get("id").and_then(Value::as_str)?;
                        let template = action
                            .get("render")
                            .and_then(|v| v.get("lua_desync"))
                            .and_then(Value::as_str)?;
                        Some(CatalogAction {
                            id: id.to_string(),
                            protocols: string_list(action.get("protocols")),
                            template: template.to_string(),
                            params: action.get("params").cloned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.insert(
            id.to_string(),
            CatalogFamily {
                id: id.to_string(),
                enabled: family
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
                protocols: string_list(family.get("protocols")),
                cost: family.get("cost").and_then(Value::as_f64).unwrap_or(5.0),
                risk: family.get("risk").and_then(Value::as_f64).unwrap_or(3.0),
                prior: family
                    .get("prior")
                    .and_then(Value::as_sequence)
                    .and_then(|v| Some((v.first()?.as_f64()?, v.get(1)?.as_f64()?)))
                    .unwrap_or((2.0, 2.0)),
                actions,
            },
        );
    }
    out
}

fn append_family_actions(
    root: &Value,
    catalog: &HashMap<String, CatalogFamily>,
    protocol_key: &str,
    family_id: &str,
    candidate: Option<&Value>,
    use_action_values: bool,
    runtime_payload_aliases: Option<&PayloadAliases>,
    runtime_strategy_values: Option<&StrategyValuesConfig>,
    nodes: &mut Vec<StrategyNode>,
    seen: &mut HashSet<String>,
) {
    let Some(family) = catalog.get(family_id) else {
        return;
    };
    if !family.enabled || !protocol_matches(&family.protocols, protocol_key, "") {
        return;
    }

    let action_filter = candidate
        .and_then(|v| v.get("actions"))
        .and_then(Value::as_sequence)
        .map(|seq| seq.iter().filter_map(Value::as_str).collect::<HashSet<_>>());
    let overrides = candidate.and_then(|v| v.get("params"));

    for action in &family.actions {
        if action.id.contains("_legacy") {
            continue;
        }
        if action_filter
            .as_ref()
            .is_some_and(|ids| !ids.contains(action.id.as_str()))
        {
            continue;
        }
        if !protocol_matches(&action.protocols, protocol_key, &action.template) {
            continue;
        }
        for lua in render_lua_desync_variants(
            root,
            protocol_key,
            action,
            overrides,
            use_action_values,
            runtime_payload_aliases,
            runtime_strategy_values,
        ) {
            let mut args = vec![format!("--lua-desync={lua}")];
            apply_blob_file_options(&mut args);
            ensure_payload_option(&mut args, Some(protocol_key));
            let args_key = args.join("\0");
            if !seen.insert(args_key.clone()) {
                continue;
            }
            nodes.push(StrategyNode {
                id: format!("{protocol_key}_{}_{}_{}", family.id, action.id, nodes.len()),
                family: family.id.clone(),
                action_id: action.id.clone(),
                components: vec![StrategyComponent {
                    family: family.id.clone(),
                    action_id: action.id.clone(),
                    args: args.clone(),
                }],
                is_combined: false,
                args,
                cost: family.cost,
                risk: family.risk,
                prior: family.prior,
            });
        }
    }
}

pub fn select_diverse_nodes(
    nodes: Vec<StrategyNode>,
    protocol_key: &str,
    max_candidates: usize,
    max_per_family: usize,
    max_per_action: usize,
    round_robin_families: bool,
) -> Vec<StrategyNode> {
    let mut nodes = nodes;
    nodes.sort_by(compare_node_quality);
    let mut seen_args = HashSet::new();
    let mut per_family = HashMap::<String, usize>::new();
    let mut per_action = HashMap::<(String, String), usize>::new();
    let mut filtered = Vec::new();

    for node in nodes {
        let args_key = node.args.join("\0");
        if !seen_args.insert(args_key) {
            continue;
        }
        let family_count = per_family.entry(node.family.clone()).or_default();
        if *family_count >= max_per_family {
            continue;
        }
        let action_key = (node.family.clone(), node.action_id.clone());
        let action_count = per_action.entry(action_key).or_default();
        if *action_count >= max_per_action {
            continue;
        }
        *family_count += 1;
        *action_count += 1;
        filtered.push(node);
    }

    let selected = if round_robin_families {
        round_robin_by_family(filtered, max_candidates)
    } else {
        let mut nodes = filtered;
        nodes.sort_by(compare_node_quality);
        nodes.truncate(max_candidates);
        nodes
    };

    reindex_nodes(protocol_key, selected)
}

pub fn generate_combined_nodes(
    protocol_key: &str,
    base_nodes: &[StrategyNode],
    cfg: &StrategyCombinationConfig,
) -> Vec<StrategyNode> {
    if !cfg.enabled {
        return Vec::new();
    }

    let mut singles = base_nodes
        .iter()
        .filter(|node| !node.is_combined)
        .filter(|node| !node.action_id.contains("_legacy"))
        .cloned()
        .collect::<Vec<_>>();
    for node in &mut singles {
        normalize_single_node(node);
    }
    singles.sort_by(compare_combination_input);

    let mut out = Vec::new();
    let mut seen_args = HashSet::new();

    for i in 0..singles.len() {
        for j in (i + 1)..singles.len() {
            let (first, second) = ordered_components(&singles[i], &singles[j]);
            if first.id == second.id {
                continue;
            }
            if cfg.require_different_family && first.family == second.family {
                continue;
            }
            if !cfg.allow_same_action && first.action_id == second.action_id {
                continue;
            }
            if args_intersect(&first.args, &second.args) {
                continue;
            }
            if cfg.mode != "force" && !cfg.pair_allowed(protocol_key, &first.family, &second.family)
            {
                continue;
            }

            let mut args = first.args.clone();
            args.extend(second.args.clone());
            if !seen_args.insert(args.join("\0")) {
                continue;
            }

            let family = format!("combined_{}_{}", first.family, second.family);
            let action_id = format!("{}+{}", first.action_id, second.action_id);
            out.push(StrategyNode {
                id: format!(
                    "{protocol_key}_combined_{}_{}_{}",
                    first.family,
                    second.family,
                    out.len()
                ),
                family,
                action_id,
                components: vec![
                    StrategyComponent {
                        family: first.family.clone(),
                        action_id: first.action_id.clone(),
                        args: first.args.clone(),
                    },
                    StrategyComponent {
                        family: second.family.clone(),
                        action_id: second.action_id.clone(),
                        args: second.args.clone(),
                    },
                ],
                is_combined: true,
                args,
                cost: first.cost + second.cost + 3.0,
                risk: first.risk.max(second.risk) + 0.1 * first.risk.min(second.risk),
                prior: (1.0, 1.0),
            });
        }
    }

    out
}

fn round_robin_by_family(nodes: Vec<StrategyNode>, max_candidates: usize) -> Vec<StrategyNode> {
    let mut family_order = Vec::<String>::new();
    let mut groups = BTreeMap::<String, Vec<StrategyNode>>::new();

    for node in nodes {
        if !groups.contains_key(&node.family) {
            family_order.push(node.family.clone());
        }
        groups.entry(node.family.clone()).or_default().push(node);
    }

    family_order.sort_by(|a, b| {
        family_diversity_rank(a)
            .cmp(&family_diversity_rank(b))
            .then_with(|| a.cmp(b))
    });

    for group in groups.values_mut() {
        group.sort_by(compare_node_quality);
    }

    let mut selected = Vec::new();
    loop {
        let mut made_progress = false;
        for family in &family_order {
            if selected.len() >= max_candidates {
                return selected;
            }
            let Some(group) = groups.get_mut(family) else {
                continue;
            };
            if group.is_empty() {
                continue;
            }
            selected.push(group.remove(0));
            made_progress = true;
        }
        if !made_progress {
            break;
        }
    }
    selected
}

pub fn prior_success_ratio(node: &StrategyNode) -> f64 {
    let (a, b) = node.prior;
    if a + b <= 0.0 {
        0.5
    } else {
        a / (a + b)
    }
}

pub fn compare_node_quality(a: &StrategyNode, b: &StrategyNode) -> Ordering {
    family_diversity_rank(&a.family)
        .cmp(&family_diversity_rank(&b.family))
        .then_with(|| a.family.cmp(&b.family))
        .then_with(|| a.action_id.cmp(&b.action_id))
        .then_with(|| a.id.cmp(&b.id))
}

pub fn family_diversity_rank(family: &str) -> usize {
    match family {
        "split" => 0,
        "fake" => 1,
        "disorder" => 2,
        "wsize" => 3,
        "faked_split" => 4,
        "seqovl" => 5,
        "syndata" => 6,
        "ipfrag" => 7,
        "oob" => 8,
        "udp_len" => 9,
        "http_trick" => 10,
        "hostfake" => 11,
        "ipv6_ext" => 12,
        _ => 99,
    }
}

fn reindex_nodes(protocol_key: &str, nodes: Vec<StrategyNode>) -> Vec<StrategyNode> {
    nodes
        .into_iter()
        .enumerate()
        .map(|(i, mut node)| {
            node.id = format!("{}_{}_{}_{}", protocol_key, node.family, node.action_id, i);
            if node.is_combined {
                node.id = format!("{}_{}_{}", protocol_key, node.family, i);
            } else {
                normalize_single_node(&mut node);
            }
            node
        })
        .collect()
}

fn normalize_single_node(node: &mut StrategyNode) {
    if node.is_combined || !node.components.is_empty() {
        return;
    }
    node.components = vec![StrategyComponent {
        family: node.family.clone(),
        action_id: node.action_id.clone(),
        args: node.args.clone(),
    }];
}

fn compare_combination_input(a: &StrategyNode, b: &StrategyNode) -> Ordering {
    combination_family_rank(&a.family)
        .cmp(&combination_family_rank(&b.family))
        .then_with(|| a.family.cmp(&b.family))
        .then_with(|| a.action_id.cmp(&b.action_id))
        .then_with(|| a.id.cmp(&b.id))
}

fn ordered_components<'a>(
    a: &'a StrategyNode,
    b: &'a StrategyNode,
) -> (&'a StrategyNode, &'a StrategyNode) {
    if compare_combination_input(a, b).is_gt() {
        (b, a)
    } else {
        (a, b)
    }
}

fn combination_family_rank(family: &str) -> usize {
    match family {
        "fake" => 0,
        "syndata" => 1,
        "ipfrag" => 2,
        "udp_len" => 3,
        "oob" => 4,
        "split" => 10,
        "disorder" => 11,
        "faked_split" => 12,
        "seqovl" => 13,
        "wsize" => 14,
        _ => 50,
    }
}

fn args_intersect(a: &[String], b: &[String]) -> bool {
    let args = a.iter().collect::<HashSet<_>>();
    b.iter().any(|arg| args.contains(arg))
}

fn protocol_matches(protocols: &[String], protocol_key: &str, template: &str) -> bool {
    if protocols.iter().any(|p| p == protocol_key) {
        return true;
    }
    if !protocols.is_empty() {
        return false;
    }
    let t = template.to_ascii_lowercase();
    match protocol_key {
        "http" => t.contains("http") || t.contains("http_host") || t.contains("http_request"),
        "tls12" | "tls13" => {
            t.contains("tls") || t.contains("sni") || t.contains("sniext") || t.contains("host")
        }
        "quic" => t.contains("quic") || t.contains("udp") || t.contains("http3"),
        _ => false,
    }
}

fn render_lua_desync_variants(
    root: &Value,
    protocol_key: &str,
    action: &CatalogAction,
    overrides: Option<&Value>,
    use_action_values: bool,
    runtime_payload_aliases: Option<&PayloadAliases>,
    runtime_strategy_values: Option<&StrategyValuesConfig>,
) -> Vec<String> {
    let combinations = param_combinations(
        root,
        protocol_key,
        action.params.as_ref(),
        overrides,
        use_action_values,
        runtime_payload_aliases,
        runtime_strategy_values,
    );
    let mut out = Vec::new();

    for combo in combinations {
        let mut rendered = action.template.clone();
        for (name, value) in &combo {
            rendered = rendered.replace(&format!("{{{{{name}}}}}"), value);
        }
        rendered = apply_suffixes(rendered, &combo);
        if rendered.contains("{{") || rendered.contains("}}") {
            continue;
        }
        out.push(rendered);
    }

    out
}

fn apply_suffixes(mut rendered: String, combo: &[(String, String)]) -> String {
    let get = |name: &str| -> Option<&str> {
        combo
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    let fooling_suffix = match get("fooling").unwrap_or("none") {
        "none" => "",
        "badsum" => ":badsum",
        "autottl" => ":autottl",
        "badsum_autottl" => ":badsum:autottl",
        "md5sig" => ":md5sig",
        "md5sig_autottl" => ":md5sig:autottl",
        "timestamp" => ":timestamp",
        "badseq" => ":badseq",
        "badack" => ":badack",
        _ => "",
    };

    let tls_mod_suffix = match get("tls_mod").unwrap_or("none") {
        "none" => "",
        "random_sni" => ":tls_mod=random_sni",
        "random_session_id" => ":tls_mod=random_session_id",
        _ => "",
    };

    let pattern_suffix = match get("pattern").unwrap_or("zero") {
        "zero" => "",
        "random" => ":pattern=random",
        _ => "",
    };

    let seqovl_pattern_suffix = match get("seqovl_pattern").unwrap_or("zero") {
        "zero" => "",
        "random" => ":seqovl_pattern=random",
        _ => "",
    };

    let rstack_suffix = match get("rstack").unwrap_or("false") {
        "true" => ":rstack",
        _ => "",
    };

    let midhost_suffix = match get("midhost").unwrap_or("none") {
        "none" => "".to_string(),
        value => format!(":midhost={value}"),
    };

    let disorder_after_suffix = match get("disorder_after").unwrap_or("none") {
        "none" => "".to_string(),
        value => format!(":disorder_after={value}"),
    };

    rendered = rendered.replace("{{fooling_suffix}}", fooling_suffix);
    rendered = rendered.replace("{{tls_mod_suffix}}", tls_mod_suffix);
    rendered = rendered.replace("{{pattern_suffix}}", pattern_suffix);
    rendered = rendered.replace("{{seqovl_pattern_suffix}}", seqovl_pattern_suffix);
    rendered = rendered.replace("{{rstack_suffix}}", rstack_suffix);
    rendered = rendered.replace("{{midhost_suffix}}", &midhost_suffix);
    rendered = rendered.replace("{{disorder_after_suffix}}", &disorder_after_suffix);
    rendered = rendered.replace("{{ipfrag_suffix}}", "");

    rendered
}

fn explicit_lua_payload(lua: &str) -> Option<&str> {
    lua.split(':')
        .find_map(|part| part.strip_prefix("payload="))
        .filter(|payload| !payload.is_empty())
}

fn ensure_payload_option(args: &mut Vec<String>, protocol_key: Option<&str>) {
    if args
        .iter()
        .any(|arg| arg == "--payload" || arg.starts_with("--payload="))
    {
        return;
    }
    let payloads = lua_desync_payloads(args, protocol_key);
    if payloads.is_empty() {
        return;
    }
    let insert_at = args
        .iter()
        .position(|arg| arg == "--lua-desync" || arg.starts_with("--lua-desync="))
        .unwrap_or(args.len());
    args.insert(insert_at, format!("--payload={}", payloads.join(",")));
}

fn apply_blob_file_options(args: &mut Vec<String>) {
    let mut blob_args = Vec::new();
    for arg in args.iter_mut() {
        let Some(lua) = arg.strip_prefix("--lua-desync=") else {
            continue;
        };
        let (updated_lua, discovered) = replace_blob_file_sentinels(lua);
        if !discovered.is_empty() {
            *arg = format!("--lua-desync={updated_lua}");
            blob_args.extend(discovered);
        }
    }
    if blob_args.is_empty() {
        return;
    }
    let insert_at = args
        .iter()
        .position(|arg| arg == "--lua-desync" || arg.starts_with("--lua-desync="))
        .unwrap_or(args.len());
    for (offset, blob_arg) in dedup_preserve_order(blob_args).into_iter().enumerate() {
        args.insert(insert_at + offset, blob_arg);
    }
}

fn replace_blob_file_sentinels(lua: &str) -> (String, Vec<String>) {
    let mut parts = Vec::new();
    let mut blob_args = Vec::new();
    for part in lua.split(':') {
        if let Some(value) = part.strip_prefix("blob=") {
            if let Some((name, path)) = parse_blob_file_sentinel(value) {
                parts.push(format!("blob={name}"));
                blob_args.push(format!("--blob={name}:@{path}"));
                continue;
            }
        }
        parts.push(part.to_string());
    }
    (parts.join(":"), blob_args)
}

fn parse_blob_file_sentinel(value: &str) -> Option<(String, String)> {
    let rest = value.strip_prefix(BLOB_FILE_SENTINEL)?;
    let (name, path) = rest.split_once('@')?;
    if name.is_empty() || path.is_empty() {
        return None;
    }
    Some((name.to_string(), path.to_string()))
}

fn lua_desync_payloads(args: &[String], protocol_key: Option<&str>) -> Vec<String> {
    let mut payloads = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let lua = if let Some(value) = arg.strip_prefix("--lua-desync=") {
            Some(value)
        } else if arg == "--lua-desync" {
            iter.next().map(|value| value.as_str())
        } else {
            None
        };
        let Some(lua) = lua else {
            continue;
        };
        let payload = explicit_lua_payload(lua).or_else(|| inferred_lua_payload(lua, protocol_key));
        if let Some(payload) = payload {
            for item in payload.split(',').filter(|item| !item.is_empty()) {
                if !payloads.iter().any(|seen| seen == item) {
                    payloads.push(item.to_string());
                }
            }
        }
    }
    payloads
}

fn inferred_lua_payload<'a>(lua: &str, protocol_key: Option<&'a str>) -> Option<&'a str> {
    if !lua_function_uses_standard_payload(lua_function_name(lua)) {
        return None;
    }
    match protocol_key {
        Some("http") => Some("http_req"),
        Some("tls12") | Some("tls13") => Some("tls_client_hello"),
        Some("quic") => Some("quic_initial"),
        _ => None,
    }
}

fn lua_function_name(lua: &str) -> &str {
    lua.split(':').next().unwrap_or(lua)
}

fn lua_function_uses_standard_payload(function: &str) -> bool {
    matches!(
        function,
        "drop"
            | "fake"
            | "rst"
            | "multisplit"
            | "multidisorder"
            | "fakedsplit"
            | "fakeddisorder"
            | "tcpseg"
            | "udplen"
    )
}

fn param_combinations(
    root: &Value,
    protocol_key: &str,
    action_params: Option<&Value>,
    overrides: Option<&Value>,
    use_action_values: bool,
    runtime_payload_aliases: Option<&PayloadAliases>,
    runtime_strategy_values: Option<&StrategyValuesConfig>,
) -> Vec<Vec<(String, String)>> {
    let keys_values = merged_param_values(
        root,
        protocol_key,
        action_params,
        overrides,
        use_action_values,
        runtime_payload_aliases,
        runtime_strategy_values,
    );
    if keys_values.is_empty() {
        return vec![Vec::new()];
    }

    let mut out: Vec<Vec<(String, String)>> = vec![Vec::new()];
    for (key, values) in keys_values {
        let mut next = Vec::new();
        for existing in &out {
            for value in &values {
                let mut candidate = existing.clone();
                candidate.push((key.clone(), value.clone()));
                next.push(candidate);
            }
        }
        out = next;
    }
    out
}

fn merged_param_values(
    root: &Value,
    protocol_key: &str,
    action_params: Option<&Value>,
    overrides: Option<&Value>,
    use_action_values: bool,
    runtime_payload_aliases: Option<&PayloadAliases>,
    runtime_strategy_values: Option<&StrategyValuesConfig>,
) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let override_map = overrides.and_then(Value::as_mapping);

    if let Some(action_map) = action_params.and_then(Value::as_mapping) {
        for (name, def) in action_map {
            let Some(name) = name.as_str() else {
                continue;
            };
            let values = override_map
                .and_then(|m| m.get(Value::String(name.to_string())))
                .map(values_from_yaml)
                .unwrap_or_else(|| param_values_from_action(root, def, use_action_values));
            let mut values = expand_dynamic_param_values(name, values);
            maybe_extend_payload_values(protocol_key, name, &mut values, runtime_payload_aliases);
            apply_strategy_values(
                protocol_key,
                name,
                &mut values,
                runtime_payload_aliases,
                runtime_strategy_values,
            );
            if !values.is_empty() {
                seen.insert(name.to_string());
                out.push((name.to_string(), values));
            }
        }
    }

    if let Some(override_map) = override_map {
        for (name, value) in override_map {
            let Some(name) = name.as_str() else {
                continue;
            };
            if seen.contains(name) {
                continue;
            }
            let values = values_from_yaml(value);
            let mut values = expand_dynamic_param_values(name, values);
            maybe_extend_payload_values(protocol_key, name, &mut values, runtime_payload_aliases);
            apply_strategy_values(
                protocol_key,
                name,
                &mut values,
                runtime_payload_aliases,
                runtime_strategy_values,
            );
            if !values.is_empty() {
                out.push((name.to_string(), values));
            }
        }
    }

    out
}

fn expand_dynamic_param_values(name: &str, values: Vec<String>) -> Vec<String> {
    if name != "blob" {
        return values;
    }

    let mut out = Vec::new();
    for value in values {
        if let Some((kind, dir)) = parse_fake_dir_marker(&value) {
            out.extend(fake_blob_files(kind, &dir));
        } else {
            out.push(value);
        }
    }
    dedup_preserve_order(out)
}

fn maybe_extend_payload_values(
    protocol_key: &str,
    param_name: &str,
    values: &mut Vec<String>,
    runtime_payload_aliases: Option<&PayloadAliases>,
) {
    if param_name != "blob" {
        return;
    }

    let Some(aliases) = runtime_payload_aliases else {
        return;
    };

    for alias in aliases.for_protocol_key(protocol_key) {
        if !values.iter().any(|value| value == alias) {
            values.push(alias.clone());
        }
    }
}

fn apply_strategy_values(
    protocol_key: &str,
    param_name: &str,
    values: &mut Vec<String>,
    runtime_payload_aliases: Option<&PayloadAliases>,
    runtime_strategy_values: Option<&StrategyValuesConfig>,
) {
    let Some(strategy_values) = runtime_strategy_values else {
        return;
    };
    let Some(config_values) = strategy_values.values_for_param(protocol_key, param_name) else {
        return;
    };

    match strategy_values.mode.as_str() {
        "override" => {
            values.clear();
            values.extend(config_values.iter().cloned());
            if param_name == "blob" {
                maybe_extend_payload_values(
                    protocol_key,
                    param_name,
                    values,
                    runtime_payload_aliases,
                );
            }
            *values = dedup_preserve_order(std::mem::take(values));
        }
        _ => {
            for value in config_values {
                if !values.iter().any(|seen| seen == value) {
                    values.push(value.clone());
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum FakeBlobKind {
    Http,
    Tls,
    Quic,
    All,
}

fn parse_fake_dir_marker(value: &str) -> Option<(FakeBlobKind, PathBuf)> {
    let (marker, dir) = value
        .split_once(':')
        .map(|(marker, dir)| (marker, PathBuf::from(dir)))
        .unwrap_or((value, PathBuf::from(DEFAULT_FAKE_BLOB_DIR)));
    let kind = match marker {
        "fake_dir_http" => FakeBlobKind::Http,
        "fake_dir_tls" => FakeBlobKind::Tls,
        "fake_dir_quic" => FakeBlobKind::Quic,
        "fake_dir_all" => FakeBlobKind::All,
        _ => return None,
    };
    Some((kind, dir))
}

fn fake_blob_files(kind: FakeBlobKind, dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_file() || !fake_blob_kind_matches(&path, kind) {
                return None;
            }
            Some(blob_file_sentinel(kind, &path))
        })
        .collect::<Vec<_>>();
    out.sort();
    out
}

fn blob_file_sentinel(kind: FakeBlobKind, path: &Path) -> String {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("blob");
    let kind = match kind {
        FakeBlobKind::Http => "http",
        FakeBlobKind::Tls => "tls",
        FakeBlobKind::Quic => "quic",
        FakeBlobKind::All => "fake",
    };
    let name = sanitize_blob_name(&format!("fake_{kind}_{filename}"));
    format!("{BLOB_FILE_SENTINEL}{name}@{}", path.to_string_lossy())
}

fn sanitize_blob_name(value: &str) -> String {
    let mut out = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    if out
        .chars()
        .next()
        .is_none_or(|c| !(c.is_ascii_alphabetic() || c == '_'))
    {
        out.insert(0, '_');
    }
    out
}

fn fake_blob_kind_matches(path: &std::path::Path, kind: FakeBlobKind) -> bool {
    if matches!(kind, FakeBlobKind::All) {
        return true;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match kind {
        FakeBlobKind::Http => name.contains("http"),
        FakeBlobKind::Tls => name.contains("tls") || name.contains("ssl"),
        FakeBlobKind::Quic => name.contains("quic"),
        FakeBlobKind::All => true,
    }
}

fn dedup_preserve_order(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

fn param_values_from_action(
    root: &Value,
    param_def: &Value,
    use_action_values: bool,
) -> Vec<String> {
    if use_action_values {
        if let Some(values) = param_def.get("values").and_then(Value::as_sequence) {
            return values.iter().filter_map(value_to_string).collect();
        }
        if let Some(values_ref) = param_def.get("values_ref").and_then(Value::as_str) {
            let values: Vec<String> = resolve_ref(root, values_ref)
                .and_then(Value::as_sequence)
                .map(|seq| seq.iter().filter_map(value_to_string).collect())
                .unwrap_or_default();
            if !values.is_empty() {
                return values;
            }
        }
    }

    if let Some(default) = param_def.get("default").and_then(value_to_string) {
        return vec![default];
    }
    if let Some(values) = param_def.get("values").and_then(Value::as_sequence) {
        return values.iter().take(1).filter_map(value_to_string).collect();
    }
    if let Some(values_ref) = param_def.get("values_ref").and_then(Value::as_str) {
        return resolve_ref(root, values_ref)
            .and_then(Value::as_sequence)
            .and_then(|seq| seq.first())
            .and_then(value_to_string)
            .into_iter()
            .collect();
    }

    values_from_yaml(param_def)
}

fn resolve_ref<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn values_from_yaml(value: &Value) -> Vec<String> {
    if let Some(seq) = value.as_sequence() {
        seq.iter().filter_map(value_to_string).collect()
    } else {
        value_to_string(value).into_iter().collect()
    }
}

fn value_to_string(value: &Value) -> Option<String> {
    if let Some(s) = value.as_str() {
        Some(s.to_string())
    } else if let Some(i) = value.as_i64() {
        Some(i.to_string())
    } else if let Some(f) = value.as_f64() {
        Some(f.to_string())
    } else {
        value.as_bool().map(|b| b.to_string())
    }
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_sequence)
        .map(|seq| {
            seq.iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn value_seq<'a>(value: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
    value.get(key).and_then(Value::as_sequence)
}
