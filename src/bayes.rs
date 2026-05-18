use crate::types::{FailureKind, ProbeOutcome, ProbeResult};
use rand::distributions::{Distribution, Uniform};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::{collections::HashMap, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Posterior {
    pub alpha: f64,
    pub beta: f64,
    pub tests: u64,
}

impl Posterior {
    #[allow(dead_code)]
    pub fn mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BayesianState {
    pub posteriors: HashMap<String, Posterior>,
}

impl BayesianState {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            return Ok(serde_json::from_str(&text)?);
        }

        let value: Value = serde_yaml::from_str(&text)?;
        if let Some(posteriors) = value
            .get("runtime_posteriors")
            .or_else(|| value.get("posteriors"))
        {
            return Ok(Self {
                posteriors: serde_yaml::from_value(posteriors.clone())?,
            });
        }
        Ok(Self::default())
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            std::fs::write(path, serde_json::to_string_pretty(self)?)?;
            return Ok(());
        }

        let mut root = if path.exists() {
            let text = std::fs::read_to_string(path)?;
            serde_yaml::from_str::<Value>(&text).unwrap_or(Value::Mapping(Mapping::new()))
        } else {
            Value::Mapping(Mapping::new())
        };
        if !root.is_mapping() {
            root = Value::Mapping(Mapping::new());
        }
        let mapping = root.as_mapping_mut().expect("mapping checked above");
        mapping.insert(
            Value::String("runtime_posteriors".into()),
            serde_yaml::to_value(&self.posteriors)?,
        );
        std::fs::write(path, serde_yaml::to_string(&root)?)?;
        Ok(())
    }

    pub fn get_or_insert(&mut self, key: &str, prior: (f64, f64)) -> &mut Posterior {
        self.posteriors.entry(key.to_string()).or_insert(Posterior {
            alpha: prior.0,
            beta: prior.1,
            tests: 0,
        })
    }

    pub fn update(&mut self, key: &str, prior: (f64, f64), result: &ProbeResult) {
        if matches!(
            result.failure_kind,
            Some(FailureKind::InfrastructureFailure)
        ) {
            return;
        }
        let p = self.get_or_insert(key, prior);
        match result.outcome {
            ProbeOutcome::Success => p.alpha += 1.0,
            ProbeOutcome::Cancelled => return,
            ProbeOutcome::Timeout => p.beta += 0.7,
            _ => p.beta += 1.0,
        }
        p.tests += 1;
    }

    #[allow(dead_code)]
    pub fn thompson_like_score(&self, key: &str, prior: (f64, f64), cost: f64, risk: f64) -> f64 {
        let p = self.posteriors.get(key).cloned().unwrap_or(Posterior {
            alpha: prior.0,
            beta: prior.1,
            tests: 0,
        });
        // Lightweight placeholder: random jitter around mean. Replace with real Beta sampling if needed.
        let jitter = Uniform::from(-0.05..0.05).sample(&mut rand::thread_rng());
        p.mean() + jitter - 0.03 * cost - 0.04 * risk
    }
}
