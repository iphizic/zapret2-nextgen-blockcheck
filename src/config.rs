use serde::Deserialize;
use std::{collections::BTreeMap, net::IpAddr, path::PathBuf, sync::OnceLock};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub workers: WorkersConfig,
    pub source_port: SourcePortConfig,
    pub probe: ProbeConfig,
    pub nfqws: NfqwsConfig,
    pub firewall: FirewallConfig,
    pub debug: DebugConfig,
    #[serde(default)]
    pub isolation: IsolationConfig,
    #[serde(default)]
    pub strategies: StrategiesConfig,
    #[serde(default)]
    pub bayes: BayesConfig,
    #[serde(default)]
    pub blobs: BlobConfig,
    #[serde(default)]
    pub payloads: PayloadConfig,
    #[serde(default)]
    pub strategy_values: StrategyValuesConfig,
    #[serde(default)]
    pub strategy_combinations: StrategyCombinationConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct WorkersConfig {
    pub count: usize,
    #[serde(default = "default_spawn_grace_ms")]
    pub spawn_grace_ms: u64,
    #[serde(default = "default_task_channel_size")]
    pub task_channel_size: usize,
    #[serde(default = "default_result_channel_size")]
    pub result_channel_size: usize,
    #[serde(default = "default_shutdown_timeout_ms")]
    pub shutdown_timeout_ms: u64,
}

fn default_spawn_grace_ms() -> u64 {
    100
}

fn default_task_channel_size() -> usize {
    1024
}

fn default_result_channel_size() -> usize {
    1024
}

fn default_shutdown_timeout_ms() -> u64 {
    3000
}

#[derive(Debug, Clone, Deserialize)]
pub struct IsolationConfig {
    #[serde(default = "default_isolation_mode")]
    pub mode: String,
    #[serde(default = "default_isolation_queue_base")]
    pub queue_base: u16,
    #[serde(default = "default_mark_base")]
    pub mark_base: String,
    #[serde(default = "default_desync_mark")]
    pub desync_mark: String,
    #[serde(default = "default_use_nft_vmap")]
    pub use_nft_vmap: bool,
}

fn default_isolation_mode() -> String {
    "source_port".to_string()
}

fn default_isolation_queue_base() -> u16 {
    10
}

fn default_mark_base() -> String {
    "0x20000000".to_string()
}

fn default_desync_mark() -> String {
    "0x40000000".to_string()
}

fn default_use_nft_vmap() -> bool {
    false
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            mode: default_isolation_mode(),
            queue_base: default_isolation_queue_base(),
            mark_base: default_mark_base(),
            desync_mark: default_desync_mark(),
            use_nft_vmap: default_use_nft_vmap(),
        }
    }
}

impl IsolationConfig {
    pub fn mode(&self) -> anyhow::Result<crate::isolation::IsolationMode> {
        crate::isolation::IsolationMode::parse(&self.mode)
    }

    pub fn mark_base_value(&self) -> anyhow::Result<u32> {
        crate::isolation::parse_hex_mark(&self.mark_base)
    }

    pub fn desync_mark_value(&self) -> anyhow::Result<u32> {
        crate::isolation::parse_hex_mark(&self.desync_mark)
    }
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
    #[serde(default = "default_max_read_bytes")]
    pub max_read_bytes: usize,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_http_method")]
    pub method: String,
    #[serde(default = "default_read_mode")]
    pub read_mode: String,
    #[serde(default = "default_min_body_bytes")]
    pub min_body_bytes: usize,
    #[serde(default = "default_dpi_detection_bytes")]
    pub dpi_detection_bytes: usize,
    #[serde(default = "default_verify_transfer_bytes")]
    pub verify_transfer_bytes: usize,
    #[serde(default)]
    pub base_domains: Vec<String>,
    #[serde(default = "default_test_count")]
    pub test_count: usize,

    #[serde(default)]
    pub protocols: ProtocolProbeConfig,

    #[serde(default)]
    pub dns: DnsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_dns_mode")]
    pub mode: String,

    #[serde(default = "default_doh_addr")]
    pub doh_addr: String,

    #[serde(default)]
    pub doh_addrs: Vec<String>,

    #[serde(default = "default_doh_host")]
    pub doh_host: String,

    #[serde(default = "default_doh_path")]
    pub doh_path: String,
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

fn default_user_agent() -> String {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0".to_string()
}

fn default_http_method() -> String {
    "GET".to_string()
}

fn default_read_mode() -> String {
    "body".to_string()
}

fn default_min_body_bytes() -> usize {
    1
}

fn default_dpi_detection_bytes() -> usize {
    16384
}

fn default_verify_transfer_bytes() -> usize {
    32768
}

fn default_max_read_bytes() -> usize {
    65536
}

fn default_test_count() -> usize {
    1
}

fn default_preferred_protocol() -> String {
    "tls12".to_string()
}

fn default_dns_mode() -> String {
    "doh".to_string()
}

fn default_doh_addr() -> String {
    "1.1.1.1:443".to_string()
}

fn default_doh_host() -> String {
    "cloudflare-dns.com".to_string()
}

fn default_doh_path() -> String {
    "/dns-query".to_string()
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            mode: default_dns_mode(),
            doh_addr: default_doh_addr(),
            doh_addrs: Vec::new(),
            doh_host: default_doh_host(),
            doh_path: default_doh_path(),
        }
    }
}

impl DnsConfig {
    pub fn effective_doh_addrs(&self) -> Vec<&str> {
        if self.doh_addrs.is_empty() {
            vec![self.doh_addr.as_str()]
        } else {
            self.doh_addrs.iter().map(String::as_str).collect()
        }
    }
}

impl Default for ProtocolProbeConfig {
    fn default() -> Self {
        Self {
            http: true,
            tls12: true,
            tls13: false,
            quic: false,
            preferred: "tls12".to_string(),
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
pub struct BlobConfig {
    #[serde(default)]
    pub auto_load: bool,
    #[serde(default)]
    pub base_dir: Option<PathBuf>,
}

impl Default for BlobConfig {
    fn default() -> Self {
        Self {
            auto_load: false,
            base_dir: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayloadConfig {
    #[serde(default = "default_payload_max_per_protocol")]
    pub max_per_protocol: usize,
    #[serde(default = "default_http_payload_protocol_config")]
    pub http: PayloadProtocolConfig,
    #[serde(default = "default_tls_payload_protocol_config")]
    pub tls: PayloadProtocolConfig,
    #[serde(default = "default_quic_payload_protocol_config")]
    pub quic: PayloadProtocolConfig,
}

impl Default for PayloadConfig {
    fn default() -> Self {
        Self {
            max_per_protocol: default_payload_max_per_protocol(),
            http: default_http_payload_protocol_config(),
            tls: default_tls_payload_protocol_config(),
            quic: default_quic_payload_protocol_config(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PayloadProtocolConfig {
    #[serde(default)]
    pub builtin: Vec<String>,
    #[serde(default)]
    pub files: Vec<PathBuf>,
    #[serde(default)]
    pub aliases: BTreeMap<String, PathBuf>,
}

fn default_payload_max_per_protocol() -> usize {
    8
}

fn default_http_payload_protocol_config() -> PayloadProtocolConfig {
    PayloadProtocolConfig {
        builtin: vec!["fake_default_http".to_string()],
        files: Vec::new(),
        aliases: BTreeMap::new(),
    }
}

fn default_tls_payload_protocol_config() -> PayloadProtocolConfig {
    PayloadProtocolConfig {
        builtin: vec!["fake_default_tls".to_string()],
        files: Vec::new(),
        aliases: BTreeMap::new(),
    }
}

fn default_quic_payload_protocol_config() -> PayloadProtocolConfig {
    PayloadProtocolConfig {
        builtin: vec!["fake_default_quic".to_string()],
        files: Vec::new(),
        aliases: BTreeMap::new(),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StrategyValuesConfig {
    #[serde(default = "default_strategy_values_mode")]
    pub mode: String,
    #[serde(default)]
    pub http: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub tls: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub quic: BTreeMap<String, Vec<String>>,
}

impl Default for StrategyValuesConfig {
    fn default() -> Self {
        Self {
            mode: default_strategy_values_mode(),
            http: BTreeMap::new(),
            tls: BTreeMap::new(),
            quic: BTreeMap::new(),
        }
    }
}

impl StrategyValuesConfig {
    pub fn values_for_protocol_key(&self, protocol_key: &str) -> &BTreeMap<String, Vec<String>> {
        match protocol_key {
            "http" => &self.http,
            "tls12" | "tls13" | "tls" => &self.tls,
            "quic" => &self.quic,
            _ => empty_strategy_values_map(),
        }
    }

    pub fn values_for_param(&self, protocol_key: &str, param: &str) -> Option<&Vec<String>> {
        self.values_for_protocol_key(protocol_key).get(param)
    }

    pub fn param_names_for_protocol_key(&self, protocol_key: &str) -> Vec<String> {
        self.values_for_protocol_key(protocol_key)
            .keys()
            .cloned()
            .collect()
    }
}

fn default_strategy_values_mode() -> String {
    "extend".to_string()
}

fn empty_strategy_values_map() -> &'static BTreeMap<String, Vec<String>> {
    static EMPTY: OnceLock<BTreeMap<String, Vec<String>>> = OnceLock::new();
    EMPTY.get_or_init(BTreeMap::new)
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct StrategyCombinationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub require_different_family: bool,
    #[serde(default)]
    pub allow_same_action: bool,
    #[serde(default = "default_strategy_combination_mode")]
    pub mode: String,
    #[serde(default)]
    pub allowed: Vec<AllowedCombination>,
}

impl Default for StrategyCombinationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_different_family: true,
            allow_same_action: false,
            mode: default_strategy_combination_mode(),
            allowed: Vec::new(),
        }
    }
}

#[allow(dead_code)]
impl StrategyCombinationConfig {
    pub fn pair_allowed(&self, protocol_key: &str, family_a: &str, family_b: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if self.mode == "force" {
            return !self.require_different_family || family_a != family_b;
        }
        self.allowed.iter().any(|allowed| {
            allowed
                .protocols
                .iter()
                .any(|protocol| protocol == protocol_key)
                && allowed.families.len() == 2
                && ((allowed.families[0] == family_a && allowed.families[1] == family_b)
                    || (allowed.families[0] == family_b && allowed.families[1] == family_a))
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllowedCombination {
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub families: Vec<String>,
}

fn default_strategy_combination_mode() -> String {
    "pairwise".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct StrategiesConfig {
    pub file: PathBuf,
    #[serde(default)]
    pub transition_matrix: Option<PathBuf>,
    #[serde(default = "default_successful_strategy_limit")]
    pub successful_strategy_limit: usize,

    #[serde(default = "default_search_mode")]
    pub search_mode: String,

    #[serde(default = "default_round_robin_families")]
    pub round_robin_families: bool,
}

fn default_search_mode() -> String {
    "signal".into()
}

fn default_round_robin_families() -> bool {
    true
}

fn default_successful_strategy_limit() -> usize {
    10
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
            transition_matrix: None,
            successful_strategy_limit: default_successful_strategy_limit(),
            search_mode: default_search_mode(),
            round_robin_families: default_round_robin_families(),
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
        let preferred_enabled = match self.probe.protocols.preferred.as_str() {
            "http" => self.probe.protocols.http,
            "tls12" => self.probe.protocols.tls12,
            "tls13" => self.probe.protocols.tls13,
            "quic" => self.probe.protocols.quic,
            _ => false,
        };
        if !preferred_enabled {
            anyhow::bail!("probe.protocols.preferred is disabled in probe.protocols");
        }
        if self.workers.count == 0 {
            anyhow::bail!("workers.count must be greater than zero");
        }
        if self.workers.task_channel_size == 0 {
            anyhow::bail!("workers.task_channel_size must be greater than zero");
        }
        if self.workers.result_channel_size == 0 {
            anyhow::bail!("workers.result_channel_size must be greater than zero");
        }
        let max_worker_id = self.workers.count.saturating_sub(1) as u32;
        if u32::from(self.isolation.queue_base) + max_worker_id > u16::MAX as u32 {
            anyhow::bail!(
                "isolation.queue_base ({}) + workers.count - 1 overflows u16 qnum space",
                self.isolation.queue_base
            );
        }
        self.validate_isolation()?;
        if self.source_port.mode != "os_assigned" {
            anyhow::bail!("source_port.mode must be os_assigned");
        }
        if !matches!(self.probe.backend.as_str(), "native" | "curl") {
            anyhow::bail!("probe.backend must be native or curl");
        }
        crate::types::HttpMethod::parse_config(&self.probe.method)?;
        crate::types::ReadMode::parse_config(&self.probe.read_mode)?;
        if self.probe.min_body_bytes > self.probe.max_read_bytes {
            anyhow::bail!(
                "probe.min_body_bytes must be less than or equal to probe.max_read_bytes"
            );
        }
        if self.probe.test_count == 0 {
            anyhow::bail!("probe.test_count must be greater than zero");
        }
        if self.probe.dns.mode != "doh" {
            anyhow::bail!("probe.dns.mode must be doh");
        }
        let doh_addrs = self.probe.dns.effective_doh_addrs();
        if doh_addrs.is_empty() {
            anyhow::bail!("probe.dns.doh_addr or probe.dns.doh_addrs must not be empty");
        }
        for doh_addr in doh_addrs {
            let parsed = doh_addr.parse::<std::net::SocketAddr>().map_err(|_| {
                anyhow::anyhow!(
                    "probe.dns.doh_addr/doh_addrs must be IP socket addresses like 1.1.1.1:443"
                )
            })?;
            if parsed.port() != 443 {
                anyhow::bail!("probe.dns.doh_addr/doh_addrs must use port 443");
            }
        }
        if self.probe.dns.doh_host.is_empty()
            || self.probe.dns.doh_host.contains(':')
            || self.probe.dns.doh_host.contains('/')
        {
            anyhow::bail!("probe.dns.doh_host must be a DNS host name without port or path");
        }
        if !self.probe.dns.doh_path.starts_with('/') {
            anyhow::bail!("probe.dns.doh_path must start with /");
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
        if !matches!(
            self.strategies.search_mode.as_str(),
            "signal" | "expand" | "force"
        ) {
            anyhow::bail!("strategies.search_mode must be signal, expand or force");
        }
        self.validate_payloads()?;
        self.validate_strategy_values()?;
        self.validate_strategy_combinations()?;
        Ok(())
    }

    fn validate_isolation(&self) -> anyhow::Result<()> {
        let mode = self.isolation.mode()?;
        self.isolation.mark_base_value()?;
        self.isolation.desync_mark_value()?;
        if self.isolation.mark_base == self.isolation.desync_mark {
            anyhow::bail!("isolation.mark_base must differ from isolation.desync_mark");
        }
        if mode == crate::isolation::IsolationMode::Fwmark {
            if !self.isolation.use_nft_vmap {
                anyhow::bail!("isolation.use_nft_vmap must be true when isolation.mode=fwmark");
            }
            if self.firewall.backend != "nftables" {
                anyhow::bail!("isolation.mode=fwmark requires firewall.backend=nftables");
            }
            let max_worker_id = self.workers.count.saturating_sub(1) as u32;
            let mark_base = self.isolation.mark_base_value()?;
            if mark_base.saturating_add(max_worker_id + 1) == self.isolation.desync_mark_value()? {
                anyhow::bail!("worker fwmark range overlaps isolation.desync_mark");
            }
        }
        Ok(())
    }

    fn validate_strategy_combinations(&self) -> anyhow::Result<()> {
        let config = &self.strategy_combinations;
        if !matches!(
            config.mode.as_str(),
            "pairwise" | "best_with_variants" | "force"
        ) {
            anyhow::bail!(
                "strategy_combinations.mode must be pairwise, best_with_variants or force"
            );
        }

        for (index, allowed) in config.allowed.iter().enumerate() {
            if allowed.protocols.is_empty() {
                anyhow::bail!("strategy_combinations.allowed[{index}].protocols must not be empty");
            }
            for protocol in &allowed.protocols {
                if !matches!(protocol.as_str(), "http" | "tls12" | "tls13" | "quic") {
                    anyhow::bail!(
                        "strategy_combinations.allowed[{index}].protocols contains unsupported protocol {protocol:?}"
                    );
                }
            }
            if allowed.families.len() != 2 {
                anyhow::bail!(
                    "strategy_combinations.allowed[{index}].families must contain exactly 2 families"
                );
            }
            if allowed.families.iter().any(|family| family.is_empty()) {
                anyhow::bail!(
                    "strategy_combinations.allowed[{index}].families must not contain empty family names"
                );
            }
            if config.require_different_family && allowed.families[0] == allowed.families[1] {
                anyhow::bail!(
                    "strategy_combinations.allowed[{index}].families must be different when require_different_family=true"
                );
            }
        }

        Ok(())
    }

    fn validate_strategy_values(&self) -> anyhow::Result<()> {
        if !matches!(self.strategy_values.mode.as_str(), "extend" | "override") {
            anyhow::bail!("strategy_values.mode must be extend or override");
        }

        validate_strategy_value_map("http", &self.strategy_values.http)?;
        validate_strategy_value_map("tls", &self.strategy_values.tls)?;
        validate_strategy_value_map("quic", &self.strategy_values.quic)?;

        Ok(())
    }

    fn validate_payloads(&self) -> anyhow::Result<()> {
        if self.payloads.max_per_protocol == 0 {
            anyhow::bail!("payloads.max_per_protocol must be greater than zero");
        }

        if self.blobs.auto_load {
            let base_dir = self.blobs.base_dir.as_ref().ok_or_else(|| {
                anyhow::anyhow!("blobs.base_dir is required when blobs.auto_load=true")
            })?;
            let _ = base_dir;
        }

        let mut aliases = BTreeMap::<String, &'static str>::new();
        self.validate_payload_protocol_aliases("http", &self.payloads.http, &mut aliases)?;
        self.validate_payload_protocol_aliases("tls", &self.payloads.tls, &mut aliases)?;
        self.validate_payload_protocol_aliases("quic", &self.payloads.quic, &mut aliases)?;
        self.validate_payload_protocol_file_limit("http", &self.payloads.http)?;
        self.validate_payload_protocol_file_limit("tls", &self.payloads.tls)?;
        self.validate_payload_protocol_file_limit("quic", &self.payloads.quic)?;

        Ok(())
    }

    fn validate_payload_protocol_aliases(
        &self,
        protocol: &'static str,
        config: &PayloadProtocolConfig,
        aliases: &mut BTreeMap<String, &'static str>,
    ) -> anyhow::Result<()> {
        let _builtin_count = config.builtin.len();

        for alias in config.aliases.keys() {
            validate_payload_alias(alias)?;
            validate_payload_alias_reserved(alias)?;
            if let Some(existing_protocol) = aliases.insert(alias.clone(), protocol) {
                anyhow::bail!(
                    "payload alias {alias:?} is duplicated between {existing_protocol} and {protocol}"
                );
            }
        }

        for file in &config.files {
            let alias = payload_file_alias(file)?;
            validate_payload_alias(&alias)?;
            validate_payload_alias_reserved(&alias)?;
            if let Some(existing_protocol) = aliases.insert(alias.clone(), protocol) {
                anyhow::bail!(
                    "payload alias {alias:?} is duplicated between {existing_protocol} and {protocol}"
                );
            }
        }

        Ok(())
    }

    fn validate_payload_protocol_file_limit(
        &self,
        protocol: &'static str,
        config: &PayloadProtocolConfig,
    ) -> anyhow::Result<()> {
        let file_payload_count = config.files.len() + config.aliases.len();
        if file_payload_count > self.payloads.max_per_protocol {
            anyhow::bail!(
                "payloads.{protocol} has {file_payload_count} file payloads, but payloads.max_per_protocol is {}",
                self.payloads.max_per_protocol
            );
        }
        Ok(())
    }
}

fn validate_payload_alias(alias: &str) -> anyhow::Result<()> {
    if alias.is_empty() {
        anyhow::bail!("payload alias must not be empty");
    }
    if !alias
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        anyhow::bail!(
            "payload alias {alias:?} must contain only ASCII letters, digits or underscore"
        );
    }
    Ok(())
}

fn validate_payload_alias_reserved(alias: &str) -> anyhow::Result<()> {
    if matches!(
        alias,
        "fake_default_http" | "fake_default_tls" | "fake_default_quic"
    ) {
        anyhow::bail!("payload alias {alias:?} conflicts with a builtin payload alias");
    }
    Ok(())
}

fn payload_file_alias(file: &std::path::Path) -> anyhow::Result<String> {
    let stem = file
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("payload file must have a valid UTF-8 file name"))?;
    Ok(stem.to_string())
}

fn validate_strategy_value_map(
    protocol: &str,
    values: &BTreeMap<String, Vec<String>>,
) -> anyhow::Result<()> {
    for (param, param_values) in values {
        if param.is_empty() {
            anyhow::bail!("strategy_values.{protocol} parameter name must not be empty");
        }
        if let Some(index) = param_values.iter().position(|value| value.is_empty()) {
            anyhow::bail!(
                "strategy_values.{protocol}.{param}[{index}] must not be an empty string"
            );
        }
    }
    Ok(())
}
