use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyNode {
    pub id: String,
    pub family: String,
    pub args: Vec<String>,
    pub cost: f64,
    pub risk: f64,
    pub prior: (f64, f64),
}

#[derive(Debug, Clone, Default)]
pub struct StrategyGraph {
    pub nodes: Vec<StrategyNode>,
    pub transition_cost: HashMap<(String, String), f64>,
}

impl StrategyGraph {
    pub fn ordered_seed(&self) -> Vec<StrategyNode> {
        let mut n = self.nodes.clone();
        n.sort_by(|a, b| {
            a.cost
                .total_cmp(&b.cost)
                .then_with(|| a.risk.total_cmp(&b.risk))
                .then_with(|| a.id.cmp(&b.id))
        });
        n
    }

    #[allow(dead_code)]
    pub fn load_for_protocol(
        strategies_path: &Path,
        transition_path: &Path,
        protocol_key: &str,
    ) -> anyhow::Result<Self> {
        Self::load_for_protocol_mode(
            strategies_path,
            transition_path,
            protocol_key,
            "signal",
            default_max_candidates(),
        )
    }

    pub fn load_for_protocol_mode(
        strategies_path: &Path,
        transition_path: &Path,
        protocol_key: &str,
        search_mode: &str,
        max_candidates: usize,
    ) -> anyhow::Result<Self> {
        let strategies_text = std::fs::read_to_string(strategies_path)?;
        let strategies_yaml: Value = serde_yaml::from_str(&strategies_text)?;

        let nodes = if let Some(strategies) = value_seq(&strategies_yaml, "strategies") {
            let mut nodes = parse_simple_strategies(strategies)?;
            nodes.truncate(max_candidates);
            nodes
        } else {
            parse_catalog_strategies(&strategies_yaml, protocol_key, search_mode, max_candidates)?
        };

        let transition_text = std::fs::read_to_string(transition_path)?;
        let transition_cost = parse_transition_costs(&transition_text)?;

        Ok(Self {
            nodes,
            transition_cost,
        })
    }

    #[allow(dead_code)]
    pub fn load(strategies_path: &Path, transition_path: &Path) -> anyhow::Result<Self> {
        Self::load_for_protocol_mode(
            strategies_path,
            transition_path,
            "tls13",
            "signal",
            default_max_candidates(),
        )
    }
}

fn default_max_candidates() -> usize {
    200
}

fn parse_simple_strategies(strategies: &[Value]) -> anyhow::Result<Vec<StrategyNode>> {
    strategies
        .iter()
        .cloned()
        .map(serde_yaml::from_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn parse_transition_costs(text: &str) -> anyhow::Result<HashMap<(String, String), f64>> {
    let value: Value = serde_yaml::from_str(text)?;
    let rows = value_mapping(&value, "costs")
        .or_else(|| value_mapping(&value, "families"))
        .ok_or_else(|| anyhow::anyhow!("transition matrix missing costs/families mapping"))?;
    let mut out = HashMap::new();
    for (from, row) in rows {
        let Some(from) = from.as_str() else {
            continue;
        };
        let Some(row) = row.as_mapping() else {
            continue;
        };
        for (to, cost) in row {
            let (Some(to), Some(cost)) = (to.as_str(), cost.as_f64()) else {
                continue;
            };
            out.insert((from.to_string(), to.to_string()), cost);
        }
    }
    Ok(out)
}

fn parse_catalog_strategies(
    root: &Value,
    protocol_key: &str,
    search_mode: &str,
    max_candidates: usize,
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

    nodes.truncate(max_candidates);
    Ok(nodes)
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
        if action_filter
            .as_ref()
            .is_some_and(|ids| !ids.contains(action.id.as_str()))
        {
            continue;
        }
        if !protocol_matches(&action.protocols, protocol_key, &action.template) {
            continue;
        }
        for lua in render_lua_desync_variants(root, action, overrides, use_action_values) {
            let args_key = format!("--lua-desync={lua}");
            if !seen.insert(args_key.clone()) {
                continue;
            }
            nodes.push(StrategyNode {
                id: format!("{protocol_key}_{}_{}_{}", family.id, action.id, nodes.len()),
                family: family.id.clone(),
                args: vec![args_key],
                cost: family.cost,
                risk: family.risk,
                prior: family.prior,
            });
        }
    }
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
    action: &CatalogAction,
    overrides: Option<&Value>,
    use_action_values: bool,
) -> Vec<String> {
    let combinations =
        param_combinations(root, action.params.as_ref(), overrides, use_action_values);
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

    rendered = rendered.replace("{{fooling_suffix}}", fooling_suffix);
    rendered = rendered.replace("{{tls_mod_suffix}}", tls_mod_suffix);
    rendered = rendered.replace("{{pattern_suffix}}", pattern_suffix);
    rendered = rendered.replace("{{seqovl_pattern_suffix}}", seqovl_pattern_suffix);
    rendered = rendered.replace("{{ipfrag_suffix}}", "");

    rendered
}

fn param_combinations(
    root: &Value,
    action_params: Option<&Value>,
    overrides: Option<&Value>,
    use_action_values: bool,
) -> Vec<Vec<(String, String)>> {
    let keys_values = merged_param_values(root, action_params, overrides, use_action_values);
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
    action_params: Option<&Value>,
    overrides: Option<&Value>,
    use_action_values: bool,
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
            if !values.is_empty() {
                out.push((name.to_string(), values));
            }
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

fn value_mapping<'a>(value: &'a Value, key: &str) -> Option<&'a Mapping> {
    value.get(key).and_then(Value::as_mapping)
}
