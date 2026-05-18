use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::{collections::HashMap, path::Path};

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
        n.sort_by(|a, b| a.cost.partial_cmp(&b.cost).unwrap());
        n
    }

    pub fn load_for_protocol(
        strategies_path: &Path,
        transition_path: &Path,
        protocol_key: &str,
    ) -> anyhow::Result<Self> {
        let strategies_text = std::fs::read_to_string(strategies_path)?;
        let strategies_yaml: Value = serde_yaml::from_str(&strategies_text)?;

        let nodes = if let Some(strategies) = value_seq(&strategies_yaml, "strategies") {
            parse_simple_strategies(strategies)?
        } else {
            parse_catalog_strategies(&strategies_yaml, protocol_key)?
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
        Self::load_for_protocol(strategies_path, transition_path, "tls13")
    }
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
        let Some(from) = from.as_str() else { continue };
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

fn parse_catalog_strategies(root: &Value, protocol_key: &str) -> anyhow::Result<Vec<StrategyNode>> {
    let families = value_seq(root, "families")
        .ok_or_else(|| anyhow::anyhow!("strategy catalog missing strategies/families"))?;

    let actions = catalog_actions(families);
    let family_meta = catalog_family_meta(families);

    let candidates = root
        .get("candidate_generators")
        .and_then(|v| v.get("signal"))
        .and_then(|v| v.get(protocol_key))
        .and_then(Value::as_sequence)
        .ok_or_else(|| {
            anyhow::anyhow!("strategy catalog missing candidate_generators.signal.{protocol_key}")
        })?;

    let mut nodes = Vec::new();

    for candidate in candidates {
        let Some(family) = candidate.get("family").and_then(Value::as_str) else {
            continue;
        };

        let Some(action_ids) = candidate.get("actions").and_then(Value::as_sequence) else {
            continue;
        };

        for action_id in action_ids.iter().filter_map(Value::as_str) {
            let Some(lua_template) = actions.get(action_id) else {
                continue;
            };

            let params = candidate.get("params");
            let (cost, risk, prior) =
                family_meta
                    .get(family)
                    .cloned()
                    .unwrap_or((5.0, 3.0, (2.0, 2.0)));

            for lua in render_lua_desync_variants(lua_template, params) {
                nodes.push(StrategyNode {
                    id: format!("{protocol_key}_{family}_{action_id}_{}", nodes.len()),
                    family: family.to_string(),
                    args: vec![format!("--lua-desync={lua}")],
                    cost,
                    risk,
                    prior,
                });
            }
        }
    }

    if nodes.is_empty() {
        anyhow::bail!("strategy catalog produced no concrete {protocol_key} candidates");
    }

    Ok(nodes)
}

fn catalog_actions(families: &[Value]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for family in families {
        let Some(actions) = family.get("actions").and_then(Value::as_sequence) else {
            continue;
        };
        for action in actions {
            let (Some(id), Some(lua)) = (
                action.get("id").and_then(Value::as_str),
                action
                    .get("render")
                    .and_then(|v| v.get("lua_desync"))
                    .and_then(Value::as_str),
            ) else {
                continue;
            };
            out.insert(id.to_string(), lua.to_string());
        }
    }
    out
}

fn catalog_family_meta(families: &[Value]) -> HashMap<String, (f64, f64, (f64, f64))> {
    let mut out = HashMap::new();
    for family in families {
        let Some(id) = family.get("id").and_then(Value::as_str) else {
            continue;
        };
        let cost = family.get("cost").and_then(Value::as_f64).unwrap_or(5.0);
        let risk = family.get("risk").and_then(Value::as_f64).unwrap_or(3.0);
        let prior = family
            .get("prior")
            .and_then(Value::as_sequence)
            .and_then(|v| Some((v.get(0)?.as_f64()?, v.get(1)?.as_f64()?)))
            .unwrap_or((2.0, 2.0));
        out.insert(id.to_string(), (cost, risk, prior));
    }
    out
}

fn value_to_string(value: &Value) -> Option<String> {
    if let Some(s) = value.as_str() {
        Some(s.to_string())
    } else if let Some(i) = value.as_i64() {
        Some(i.to_string())
    } else if let Some(f) = value.as_f64() {
        Some(f.to_string())
    } else {
        None
    }
}

fn value_seq<'a>(value: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
    value.get(key).and_then(Value::as_sequence)
}

fn value_mapping<'a>(value: &'a Value, key: &str) -> Option<&'a Mapping> {
    value.get(key).and_then(Value::as_mapping)
}

fn render_lua_desync_variants(template: &str, params: Option<&Value>) -> Vec<String> {
    let combinations = param_combinations(params);

    let mut out = Vec::new();

    for combo in combinations {
        let mut rendered = template.to_string();

        for (name, value) in &combo {
            rendered = rendered.replace(&format!("{{{{{name}}}}}"), value);
        }

        rendered = apply_suffixes(rendered, &combo);

        // Не запускать битые шаблоны.
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
        "timestamp" => ":timestamp",
        "badseq" => ":badseq",
        "badack" => ":badack",
        "md5sig_autottl" => ":md5sig:autottl",
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

fn param_combinations(params: Option<&Value>) -> Vec<Vec<(String, String)>> {
    let Some(mapping) = params.and_then(Value::as_mapping) else {
        return vec![Vec::new()];
    };

    let mut keys_values: Vec<(String, Vec<String>)> = Vec::new();

    for (name, values) in mapping {
        let Some(name) = name.as_str() else {
            continue;
        };

        let values: Vec<String> = if let Some(seq) = values.as_sequence() {
            seq.iter().filter_map(value_to_string).collect()
        } else {
            value_to_string(values).into_iter().collect()
        };

        if values.is_empty() {
            continue;
        }

        keys_values.push((name.to_string(), values));
    }

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
