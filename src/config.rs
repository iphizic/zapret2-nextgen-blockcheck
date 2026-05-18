use serde::Deserialize;
use std::{net::IpAddr, path::PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub workers: WorkersConfig,
    pub queue: QueueConfig,
    pub source_port: SourcePortConfig,
    pub probe: ProbeConfig,
    pub nfqws: NfqwsConfig,
    pub firewall: FirewallConfig,
    pub debug: DebugConfig,
    #[serde(default)]
    pub strategies: StrategiesConfig,
    #[serde(default)]
    pub bayes: BayesConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkersConfig {
    pub count: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QueueConfig {
    pub base_qnum: u16,
    pub qnum_count: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourcePortConfig {
    pub mode: String,
    pub bind_ipv4: IpAddr,
    pub bind_ipv6: IpAddr,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProbeConfig {
    pub backend: String,
    pub connect_timeout_ms: u64,
    pub tls_timeout_ms: u64,
    pub first_byte_timeout_ms: u64,
    pub total_timeout_ms: u64,
    pub max_read_bytes: usize,
    pub user_agent: String,
    pub path: String,

    #[serde(default)]
    pub protocols: ProtocolProbeConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolProbeConfig {
    #[serde(default = "default_true")]
    pub http: bool,

    #[serde(default = "default_true")]
    pub tls12: bool,

    #[serde(default = "default_true")]
    pub tls13: bool,

    #[serde(default)]
    pub quic: bool,

    #[serde(default = "default_preferred_protocol")]
    pub preferred: String,
}

fn default_true() -> bool {
    true
}

fn default_preferred_protocol() -> String {
    "tls13".to_string()
}

impl Default for ProtocolProbeConfig {
    fn default() -> Self {
        Self {
            http: true,
            tls12: true,
            tls13: false,
            quic: false,
            preferred: "tls13".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NfqwsConfig {
    pub binary: PathBuf,
    #[serde(default)]
    pub library_paths: Vec<PathBuf>,
    #[serde(default)]
    pub base_args: Vec<String>,
    pub start_grace_ms: u64,
    pub stop_timeout_ms: u64,
    pub log_stderr: bool,
    pub log_stdout: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirewallConfig {
    pub backend: String,
    pub table: String,
    pub hook: String,
    pub priority: String,
    pub cleanup_on_start: bool,
    pub cleanup_on_exit: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DebugConfig {
    pub enable_curl_fallback: bool,
    pub keep_rules_on_failure: bool,
    pub verbose_nfqws: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StrategiesConfig {
    pub file: PathBuf,
    pub transition_matrix: PathBuf,
    pub soft_fail_family_limit: usize,

    #[serde(default = "default_search_mode")]
    pub search_mode: String,

    #[serde(default = "default_max_candidates")]
    pub max_candidates: usize,
}

fn default_search_mode() -> String {
    "signal".into()
}

fn default_max_candidates() -> usize {
    200
}

#[derive(Debug, Clone, Deserialize)]
pub struct BayesConfig {
    pub state_file: PathBuf,
}

impl Default for BayesConfig {
    fn default() -> Self {
        Self {
            state_file: PathBuf::from("config/standart/bayesian_priors.yaml"),
        }
    }
}

impl Default for StrategiesConfig {
    fn default() -> Self {
        Self {
            file: PathBuf::from("config/standart/strategies.yaml"),
            transition_matrix: PathBuf::from("config/standart/transition_costs.yaml"),
            soft_fail_family_limit: 2,
            search_mode: default_search_mode(),
            max_candidates: default_max_candidates(),
        }
    }
}

impl AppConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Self = match path.extension().and_then(|ext| ext.to_str()) {
            Some("yaml") | Some("yml") => serde_yaml::from_str(&text)?,
            _ => toml::from_str(&text)?,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !matches!(
            self.probe.protocols.preferred.as_str(),
            "http" | "tls12" | "tls13" | "quic"
        ) {
            anyhow::bail!("probe.protocols.preferred must be http, tls12, tls13 or quic");
        }

        if !self.probe.protocols.http
            && !self.probe.protocols.tls12
            && !self.probe.protocols.tls13
            && !self.probe.protocols.quic
        {
            anyhow::bail!("at least one protocol probe must be enabled");
        }
        if self.workers.count == 0 {
            anyhow::bail!("workers.count must be greater than zero");
        }
        if self.queue.qnum_count == 0 {
            anyhow::bail!("queue.qnum_count must be greater than zero");
        }
        if self.source_port.mode != "os_assigned" {
            anyhow::bail!("source_port.mode must be os_assigned");
        }
        if !matches!(self.probe.backend.as_str(), "native" | "curl") {
            anyhow::bail!("probe.backend must be native or curl");
        }
        if !matches!(self.firewall.backend.as_str(), "nftables" | "iptables") {
            anyhow::bail!("firewall.backend must be nftables or iptables");
        }
        if !matches!(self.firewall.hook.as_str(), "output" | "postrouting") {
            anyhow::bail!("firewall.hook must be output or postrouting");
        }
        if self.debug.keep_rules_on_failure && self.firewall.cleanup_on_exit {
            anyhow::bail!(
                "debug.keep_rules_on_failure conflicts with firewall.cleanup_on_exit safety"
            );
        }
        Ok(())
    }
}
