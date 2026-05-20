mod bayes;
mod config;
mod firewall;
mod graph;
mod isolation;
mod nfqws;
mod payload_registry;
mod probe;
mod pruning;
mod queue;
mod scheduler;
mod scoring;
mod socket_mark;
mod types;
mod worker;
mod worker_pool;

use bayes::BayesianState;
use clap::{Parser, Subcommand};
use config::{AppConfig, DnsConfig, StrategyCombinationConfig, StrategyValuesConfig};
use firewall::{
    FirewallHook, FirewallManager, IptablesFirewallManager, NftablesFirewallManager,
    NftablesVmapFirewallManager,
};
use graph::{GraphLoadOptions, StrategyGraph};
use isolation::{generate_assignments, validate_nfqws_desync_mark, IsolationMode};
use nfqws::ProcessNfqwsManager;
use payload_registry::{PayloadDef, PayloadProtocol};
use probe::{NativeTcpTlsHttpProbe, ProbeBackend};
use scoring::ScoreWeights;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use types::*;
use worker::WorkerRuntime;

#[derive(Parser, Debug)]
#[command(name = "zapret-checker", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Check {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long, value_enum)]
        method: Option<HttpMethod>,
        #[arg(long, value_enum)]
        read_mode: Option<ReadMode>,
        #[arg(long)]
        min_body_bytes: Option<usize>,
        #[arg(long)]
        max_read_bytes: Option<usize>,
        #[arg(long, value_name = "N")]
        test_count: Option<usize>,
        #[arg(long)]
        workers: Option<usize>,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long, visible_alias = "conf-dir", value_name = "DIR")]
        strategies_dir: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        bayes_state: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        nfqws_binary: Option<PathBuf>,
        #[arg(long, value_name = "DIR")]
        nfqws_lib_dir: Vec<PathBuf>,
        #[arg(long, value_name = "PROTO")]
        probe_protocol: Option<String>,
        #[arg(long, value_name = "N")]
        successful_strategy_limit: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    Baseline {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        host: String,
    },
    Cleanup {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Debug, Serialize)]
struct CheckOutput {
    target: String,
    target_scheme: TargetScheme,
    request: HttpRequestSpec,
    test_count: usize,
    test_targets: Vec<String>,
    baseline: ProbeResult,
    results: Vec<scheduler::StrategyRunResult>,
    successful_strategy_limit: usize,
    search_mode: String,
    round_robin_families: bool,
    generated_count: usize,
    workers_count: usize,
    isolation_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_summary: Option<PayloadSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    payload_blob_imports: Vec<BlobImport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    combination_summary: Option<CombinationSummary>,
}

#[derive(Debug, Clone, Serialize)]
struct PayloadSummary {
    http: PayloadProtocolSummary,
    tls: PayloadProtocolSummary,
    quic: PayloadProtocolSummary,
    base_dir: Option<String>,
    auto_load: bool,
}

#[derive(Debug, Clone, Serialize)]
struct BlobImport {
    alias: String,
    path: String,
    arg: String,
}

#[derive(Debug, Clone, Default, Serialize)]
struct PayloadProtocolSummary {
    builtin: usize,
    files: usize,
}

#[derive(Debug, Clone, Serialize)]
struct CombinationSummary {
    enabled: bool,
    allowed_pairs: usize,
    generated: usize,
}

#[derive(Default)]
struct FamilyCounters {
    tested: usize,
    success: usize,
    failed: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Cleanup { config } => {
            let cfg = AppConfig::load(&config)?;
            let fw = build_firewall(&cfg, &[]);
            fw.cleanup_all().await?;
        }
        Commands::Baseline { config, host } => {
            let cfg = AppConfig::load(&config)?;
            let protocol = ProbeProtocol::Tls12Http11;
            let ip = resolve_one(&host, 443, &cfg.probe.dns).await?;
            let request = request_from_config(&cfg, None, None, None, None)?;
            let probe = NativeTcpTlsHttpProbe::new(
                cfg.source_port.bind_ipv4,
                cfg.source_port.bind_ipv6,
                cfg.probe.max_read_bytes,
                cfg.probe.user_agent.clone(),
            );
            let task = ProbeTask {
                strategy_id: "baseline".into(),
                worker_id: 0,
                strategy_args: vec![],
                target_host: host,
                target_ip: ip,
                protocol: protocol,
                target_port: protocol.default_port(),
                path: request.path_and_query.clone(),
                request,
                timeouts: ProbeTimeouts {
                    connect_ms: cfg.probe.connect_timeout_ms,
                    tls_ms: cfg.probe.tls_timeout_ms,
                    first_byte_ms: cfg.probe.first_byte_timeout_ms,
                    total_ms: cfg.probe.total_timeout_ms,
                },
            };
            let ctx = ProbeContext {
                qnum: 0,
                cancellation: None,
                baseline: true,
            };
            let r = ProbeBackend::probe(&probe, task, ctx).await;
            println!("{}", serde_json::to_string_pretty(&r)?);
        }
        Commands::Check {
            config,
            host,
            url,
            method,
            read_mode,
            min_body_bytes,
            max_read_bytes,
            test_count,
            workers,
            backend,
            strategies_dir,
            bayes_state,
            nfqws_binary,
            nfqws_lib_dir,
            probe_protocol,
            successful_strategy_limit,
            json,
        } => {
            let cfg = AppConfig::load(&config)?;
            let backend = backend.unwrap_or_else(|| cfg.probe.backend.clone());
            let explicit_protocol_from_cli = probe_protocol.is_some();
            let selected_protocol = selected_protocol(&cfg, probe_protocol)?;
            let cli_target_requested = host.is_some() || url.is_some();
            let target = primary_target_request(
                &cfg,
                host,
                url,
                selected_protocol,
                explicit_protocol_from_cli,
            )?;
            if !protocol_enabled(&cfg, target.protocol) {
                anyhow::bail!(
                    "selected protocol {:?} is disabled in config",
                    target.protocol
                );
            }
            let ip = resolve_one(&target.host, target.port, &cfg.probe.dns).await?;
            let request =
                request_from_config(&cfg, method, read_mode, min_body_bytes, max_read_bytes)?;
            let request = HttpRequestSpec {
                path_and_query: target.path_and_query.clone(),
                ..request
            };
            let test_count = test_count.unwrap_or(cfg.probe.test_count);
            if test_count == 0 {
                anyhow::bail!("--test-count must be greater than zero");
            }
            let strategy_targets = if cli_target_requested {
                let repeated_target = StrategyProbeTarget {
                    original: target.original.clone(),
                    host: target.host.clone(),
                    ip,
                    port: target.port,
                    protocol: target.protocol,
                    request: request.clone(),
                };
                let mut repeated = Vec::with_capacity(test_count);
                for _ in 0..test_count {
                    repeated.push(repeated_target.clone());
                }
                // CLI target is authoritative: configured base_domains are ignored.
                repeated
            } else {
                build_strategy_targets(
                    &cfg,
                    &request,
                    selected_protocol,
                    explicit_protocol_from_cli,
                    test_count,
                )
                .await?
            };
            if backend == "curl" {
                if !cfg.debug.enable_curl_fallback {
                    anyhow::bail!(
                        "--backend curl requires debug.enable_curl_fallback = true in config"
                    );
                }
                let timeouts = ProbeTimeouts {
                    connect_ms: cfg.probe.connect_timeout_ms,
                    tls_ms: cfg.probe.tls_timeout_ms,
                    first_byte_ms: cfg.probe.first_byte_timeout_ms,
                    total_ms: cfg.probe.total_timeout_ms,
                };
                let task = ProbeTask {
                    strategy_id: "curl-reference".into(),
                    worker_id: 0,
                    strategy_args: vec![],
                    target_host: target.host,
                    target_ip: ip,
                    protocol: target.protocol,
                    target_port: target.port,
                    path: request.path_and_query.clone(),
                    request,
                    timeouts,
                };
                let ctx = ProbeContext {
                    qnum: 0,
                    cancellation: None,
                    baseline: true,
                };
                let r = ProbeBackend::probe(&probe::CurlProbeFallback, task, ctx).await;
                println!("{}", serde_json::to_string_pretty(&vec![r])?);
                return Ok(());
            }
            if backend != "native" {
                anyhow::bail!("unsupported backend: {backend}");
            }
            let cancellation = shutdown_token();
            let native_probe = NativeTcpTlsHttpProbe::new(
                cfg.source_port.bind_ipv4,
                cfg.source_port.bind_ipv6,
                cfg.probe.max_read_bytes,
                cfg.probe.user_agent.clone(),
            );
            let timeouts = ProbeTimeouts {
                connect_ms: cfg.probe.connect_timeout_ms,
                tls_ms: cfg.probe.tls_timeout_ms,
                first_byte_ms: cfg.probe.first_byte_timeout_ms,
                total_ms: cfg.probe.total_timeout_ms,
            };
            if !json {
                eprintln!(
                    "info(checker): target={} host={} ip={} port={} protocol={:?} method={} read_mode={:?}",
                    target.original,
                    target.host,
                    ip,
                    target.port,
                    target.protocol,
                    request.method.as_str(),
                    request.read_mode,
                );
                eprintln!("info(checker::probe): baseline start");
            }
            let baseline = run_baseline_probe(
                &native_probe,
                target.host.clone(),
                ip,
                target.port,
                request.clone(),
                timeouts.clone(),
                Some(cancellation.clone()),
                target.protocol,
            )
            .await;
            if !json {
                eprintln!(
                    "info(checker::probe): baseline {}",
                    live_probe_summary(&baseline)
                );
            }
            let successful_strategy_limit =
                successful_strategy_limit.unwrap_or(cfg.strategies.successful_strategy_limit);
            let effective_workers = workers.unwrap_or(cfg.workers.count).max(1);
            let isolation_mode = cfg.isolation.mode()?;
            let assignments = generate_assignments(effective_workers, &cfg.isolation);
            if isolation_mode == IsolationMode::Fwmark {
                validate_nfqws_desync_mark(&cfg.nfqws.base_args, &cfg.isolation.desync_mark)?;
            }
            if should_skip_strategies_after_baseline(&baseline) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&CheckOutput {
                        target: target.original,
                        target_scheme: target.scheme,
                        request,
                        test_count,
                        test_targets: strategy_targets.iter().map(target_display_key).collect(),
                        baseline,
                        results: Vec::new(),
                        successful_strategy_limit,
                        search_mode: cfg.strategies.search_mode.clone(),
                        round_robin_families: cfg.strategies.round_robin_families,
                        generated_count: 0,
                        workers_count: effective_workers,
                        isolation_mode: isolation_mode.as_str().to_string(),
                        payload_summary: None,
                        payload_blob_imports: Vec::new(),
                        combination_summary: None,
                    })?
                );
                return Ok(());
            }
            let mut workers_config = cfg.workers.clone();
            workers_config.count = effective_workers;
            let nfqws_binary = nfqws_binary.unwrap_or_else(|| cfg.nfqws.binary.clone());
            validate_nfqws_binary(&nfqws_binary)?;
            let nfqws_library_paths = nfqws_library_paths(&cfg, &nfqws_binary, nfqws_lib_dir);
            validate_nfqws_library_paths(&nfqws_library_paths)?;
            let payload_defs = payload_registry::build_payload_registry(&cfg.blobs, &cfg.payloads)?;
            let payload_summary = payload_summary(&cfg, &payload_defs);
            let payload_blob_imports = payload_blob_imports(&payload_defs);
            let payload_aliases = payload_registry::aliases_from_payloads(&payload_defs);
            tracing::debug!(
                http_payload_aliases = payload_aliases.for_protocol_key("http").len(),
                tls_payload_aliases = payload_aliases.for_protocol_key("tls").len(),
                quic_payload_aliases = payload_aliases.for_protocol_key("quic").len(),
                file_payloads = payload_defs
                    .iter()
                    .filter(|payload| !payload.builtin)
                    .count(),
                "payload registry built"
            );
            let mut nfqws_base_args = cfg.nfqws.base_args.clone();
            nfqws_base_args.extend(payload_registry::render_blob_args(&payload_defs));
            let fw = build_firewall(&cfg, &assignments);
            fw.setup().await?;
            let nfqws = Arc::new(ProcessNfqwsManager {
                stop_timeout_ms: cfg.nfqws.stop_timeout_ms,
            });
            let runtime = WorkerRuntime {
                firewall: fw.clone(),
                nfqws,
                native_probe,
                nfqws_binary,
                nfqws_library_paths,
                nfqws_base_args,
                nfqws_start_grace_ms: workers_config.spawn_grace_ms,
                nfqws_log_stdout: cfg.nfqws.log_stdout || cfg.debug.verbose_nfqws,
                nfqws_log_stderr: cfg.nfqws.log_stderr || cfg.debug.verbose_nfqws,
                firewall_hook: parse_hook(&cfg.firewall.hook),
                isolation_mode,
            };
            let strategies_file = strategies_file(&cfg, strategies_dir.as_deref());
            let graph = StrategyGraph::load_for_protocol_mode(
                &strategies_file,
                GraphLoadOptions {
                    protocol_key: target.protocol.catalog_key(),
                    search_mode: &cfg.strategies.search_mode,
                    max_candidates: graph::no_strategy_limit(),
                    max_per_family: graph::no_strategy_limit(),
                    max_per_action: graph::no_strategy_limit(),
                    round_robin_families: cfg.strategies.round_robin_families,
                    payload_aliases: Some(&payload_aliases),
                    strategy_values: Some(&cfg.strategy_values),
                    strategy_combinations: Some(&cfg.strategy_combinations),
                },
            )?;
            let generated_count = graph.nodes.len();
            let combination_summary = combination_summary(&cfg.strategy_combinations, &graph.nodes);
            if !json {
                eprintln!(
                    "info(checker::pool): start generated={} workers={} domains={} repeats={} total_tests={} stop_at_success={}",
                    generated_count,
                    effective_workers,
                    unique_strategy_targets(&strategy_targets),
                    test_count,
                    strategy_targets.len(),
                    if successful_strategy_limit == 0 {
                        "disabled".into()
                    } else {
                        successful_strategy_limit.to_string()
                    },
                );
            }
            let scheduler = scheduler::Scheduler {
                runtime,
                workers_config,
                isolation: cfg.isolation.clone(),
                successful_strategy_limit,
                score_weights: ScoreWeights::default(),
                targets: strategy_targets.clone(),
                live_log: !json,
            };
            let bayes_path = bayes_state.unwrap_or_else(|| cfg.bayes.state_file.clone());
            let mut bayes = BayesianState::load(&bayes_path)?;
            let results = scheduler
                .run_graph_with_bayes(graph, timeouts, cancellation, &mut bayes)
                .await;
            if !json {
                let success = results
                    .iter()
                    .filter(|r| r.result.outcome == ProbeOutcome::Success)
                    .count();
                eprintln!(
                    "info(checker::pool): done tested={} success={} failed={}",
                    results.len(),
                    success,
                    results.len().saturating_sub(success),
                );
            }
            bayes.save(&bayes_path)?;
            if cfg.firewall.cleanup_on_exit {
                fw.cleanup_all().await?;
            }
            let output = &CheckOutput {
                target: target.original,
                target_scheme: target.scheme,
                request,
                test_count,
                test_targets: strategy_targets.iter().map(target_display_key).collect(),
                baseline,
                results,
                successful_strategy_limit,
                search_mode: cfg.strategies.search_mode.clone(),
                round_robin_families: cfg.strategies.round_robin_families,
                generated_count,
                workers_count: effective_workers,
                isolation_mode: isolation_mode.as_str().to_string(),
                payload_summary: Some(payload_summary),
                payload_blob_imports,
                combination_summary: Some(combination_summary),
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                print_check_report(&output, &cfg.strategy_values);
            }
        }
    }
    Ok(())
}

async fn run_baseline_probe(
    probe: &NativeTcpTlsHttpProbe,
    host: String,
    ip: std::net::IpAddr,
    port: u16,
    request: HttpRequestSpec,
    timeouts: ProbeTimeouts,
    cancellation: Option<CancellationToken>,
    protocol: ProbeProtocol,
) -> ProbeResult {
    let task = ProbeTask {
        strategy_id: "baseline".into(),
        worker_id: 0,
        strategy_args: vec![],
        target_host: host,
        target_ip: ip,
        target_port: port,
        protocol,
        path: request.path_and_query.clone(),
        request,
        timeouts,
    };
    let ctx = ProbeContext {
        qnum: 0,
        cancellation,
        baseline: true,
    };
    ProbeBackend::probe(probe, task, ctx).await
}

fn request_from_config(
    cfg: &AppConfig,
    method: Option<HttpMethod>,
    read_mode: Option<ReadMode>,
    min_body_bytes: Option<usize>,
    max_read_bytes: Option<usize>,
) -> anyhow::Result<HttpRequestSpec> {
    let request = HttpRequestSpec {
        method: method.unwrap_or(HttpMethod::parse_config(&cfg.probe.method)?),
        path_and_query: "/".into(),
        user_agent: cfg.probe.user_agent.clone(),
        read_mode: read_mode.unwrap_or(ReadMode::parse_config(&cfg.probe.read_mode)?),
        min_body_bytes: min_body_bytes.unwrap_or(cfg.probe.min_body_bytes),
        dpi_detection_bytes: cfg.probe.dpi_detection_bytes,
        verify_transfer_bytes: cfg.probe.verify_transfer_bytes,
        max_read_bytes: max_read_bytes.unwrap_or(cfg.probe.max_read_bytes),
    };
    if request.min_body_bytes > request.max_read_bytes {
        anyhow::bail!("--min-body-bytes must be less than or equal to --max-read-bytes");
    }
    Ok(request)
}

fn primary_target_request(
    cfg: &AppConfig,
    host: Option<String>,
    url: Option<String>,
    selected_protocol: ProbeProtocol,
    explicit_protocol_from_cli: bool,
) -> anyhow::Result<TargetRequest> {
    if host.is_none() && url.is_none() {
        let Some(first) = cfg.probe.base_domains.first() else {
            anyhow::bail!("specify --host/--url or configure probe.base_domains");
        };
        return parse_probe_domain_target(first, selected_protocol, explicit_protocol_from_cli);
    }
    parse_target_request(host, url, selected_protocol, explicit_protocol_from_cli)
}

async fn build_strategy_targets(
    cfg: &AppConfig,
    primary_request: &HttpRequestSpec,
    selected_protocol: ProbeProtocol,
    explicit_protocol_from_cli: bool,
    test_count: usize,
) -> anyhow::Result<Vec<StrategyProbeTarget>> {
    let mut targets = Vec::new();

    if cfg.probe.base_domains.is_empty() {
        anyhow::bail!("probe.base_domains must not be empty when --host/--url is omitted");
    }

    for domain in &cfg.probe.base_domains {
        let parsed =
            parse_probe_domain_target(domain, selected_protocol, explicit_protocol_from_cli)?;
        append_repeated_strategy_target(cfg, &mut targets, parsed, primary_request, test_count)
            .await?;
    }

    Ok(targets)
}

async fn append_repeated_strategy_target(
    cfg: &AppConfig,
    targets: &mut Vec<StrategyProbeTarget>,
    parsed: TargetRequest,
    primary_request: &HttpRequestSpec,
    test_count: usize,
) -> anyhow::Result<()> {
    if !protocol_enabled(cfg, parsed.protocol) {
        anyhow::bail!(
            "base domain protocol {:?} is disabled in config for {}",
            parsed.protocol,
            parsed.original
        );
    }
    let request = HttpRequestSpec {
        path_and_query: parsed.path_and_query.clone(),
        ..primary_request.clone()
    };
    let ip = resolve_one(&parsed.host, parsed.port, &cfg.probe.dns).await?;
    for _ in 0..test_count {
        targets.push(StrategyProbeTarget {
            original: parsed.original.clone(),
            host: parsed.host.clone(),
            ip,
            port: parsed.port,
            protocol: parsed.protocol,
            request: request.clone(),
        });
    }
    Ok(())
}

fn parse_probe_domain_target(
    domain: &str,
    selected_protocol: ProbeProtocol,
    explicit_protocol_from_cli: bool,
) -> anyhow::Result<TargetRequest> {
    if domain.contains("://") {
        parse_target_request(
            None,
            Some(domain.to_string()),
            selected_protocol,
            explicit_protocol_from_cli,
        )
    } else {
        parse_target_request(
            Some(domain.to_string()),
            None,
            selected_protocol,
            explicit_protocol_from_cli,
        )
    }
}

fn should_skip_strategies_after_baseline(result: &ProbeResult) -> bool {
    matches!(
        result.failure_kind,
        Some(FailureKind::InfrastructureFailure) | Some(FailureKind::Cancelled)
    )
}

fn validate_nfqws_binary(path: &std::path::Path) -> anyhow::Result<()> {
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("nfqws2 binary not found at {}: {e}", path.display()))?;
    if !meta.is_file() {
        anyhow::bail!("nfqws2 binary path is not a file: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            anyhow::bail!("nfqws2 binary is not executable: {}", path.display());
        }
    }
    Ok(())
}

fn parse_probe_protocol(s: &str) -> anyhow::Result<ProbeProtocol> {
    match s {
        "http" => Ok(ProbeProtocol::HttpPlain),
        "tls12" => Ok(ProbeProtocol::Tls12Http11),
        "tls13" => Ok(ProbeProtocol::Tls13Http11),
        "quic" => Ok(ProbeProtocol::QuicHttp3Future),
        _ => anyhow::bail!("unsupported probe protocol: {s}"),
    }
}

fn protocol_enabled(cfg: &AppConfig, p: ProbeProtocol) -> bool {
    match p {
        ProbeProtocol::HttpPlain => cfg.probe.protocols.http,
        ProbeProtocol::Tls12Http11 => cfg.probe.protocols.tls12,
        ProbeProtocol::Tls13Http11 => cfg.probe.protocols.tls13,
        ProbeProtocol::QuicHttp3Future => cfg.probe.protocols.quic,
    }
}

fn selected_protocol(cfg: &AppConfig, cli: Option<String>) -> anyhow::Result<ProbeProtocol> {
    let p = parse_probe_protocol(
        cli.as_deref()
            .unwrap_or(cfg.probe.protocols.preferred.as_str()),
    )?;

    if !protocol_enabled(cfg, p) {
        anyhow::bail!("selected protocol {:?} is disabled in config", p);
    }

    Ok(p)
}

fn nfqws_library_paths(
    cfg: &AppConfig,
    nfqws_binary: &std::path::Path,
    cli_paths: Vec<PathBuf>,
) -> Vec<PathBuf> {
    if !cli_paths.is_empty() {
        return cli_paths;
    }
    if !cfg.nfqws.library_paths.is_empty() {
        return cfg.nfqws.library_paths.clone();
    }
    nfqws_binary
        .parent()
        .map(|p| vec![p.to_path_buf()])
        .unwrap_or_default()
}

fn validate_nfqws_library_paths(paths: &[PathBuf]) -> anyhow::Result<()> {
    for path in paths {
        let meta = std::fs::metadata(path).map_err(|e| {
            anyhow::anyhow!("nfqws2 library path not found at {}: {e}", path.display())
        })?;
        if !meta.is_dir() {
            anyhow::bail!("nfqws2 library path is not a directory: {}", path.display());
        }
    }
    Ok(())
}

fn build_firewall(
    cfg: &AppConfig,
    assignments: &[worker::WorkerAssignment],
) -> Arc<dyn FirewallManager> {
    if cfg.isolation.mode().ok() == Some(IsolationMode::Fwmark) && cfg.isolation.use_nft_vmap {
        return Arc::new(NftablesVmapFirewallManager {
            table: cfg.firewall.table.clone(),
            hook: parse_hook(&cfg.firewall.hook),
            priority: cfg.firewall.priority.clone(),
            cleanup_on_start: cfg.firewall.cleanup_on_start,
            desync_mark: cfg
                .isolation
                .desync_mark_value()
                .expect("validated isolation.desync_mark"),
            assignments: assignments.to_vec(),
        });
    }
    match cfg.firewall.backend.as_str() {
        "iptables" => Arc::new(IptablesFirewallManager),
        _ => Arc::new(NftablesFirewallManager {
            table: cfg.firewall.table.clone(),
            hook: parse_hook(&cfg.firewall.hook),
            priority: cfg.firewall.priority.clone(),
            cleanup_on_start: cfg.firewall.cleanup_on_start,
        }),
    }
}

fn parse_hook(s: &str) -> FirewallHook {
    match s {
        "postrouting" => FirewallHook::Postrouting,
        _ => FirewallHook::Output,
    }
}

async fn resolve_one(host: &str, _port: u16, dns: &DnsConfig) -> anyhow::Result<IpAddr> {
    if dns.mode != "doh" {
        anyhow::bail!("unsupported DNS mode: {}", dns.mode);
    }
    let host = normalize_dns_host(host)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    let mut errors = Vec::new();
    for doh_addr in dns.effective_doh_addrs() {
        match resolve_one_doh_json(&host, doh_addr, dns).await {
            Ok(Some(ip)) => return Ok(ip),
            Ok(None) => errors.push(format!("{doh_addr}: no A/AAAA answer")),
            Err(e) => errors.push(format!("{doh_addr}: {e}")),
        }
    }

    anyhow::bail!(
        "DoH lookup for {host} via {} failed: {}",
        dns.effective_doh_addrs().join(", "),
        errors.join("; ")
    )
}

fn normalize_dns_host(host: &str) -> anyhow::Result<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        anyhow::bail!("host must not be empty");
    }

    if let Some(rest) = host.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            anyhow::bail!("invalid bracketed IPv6 host");
        };
        let tail = &rest[end + 1..];
        if !tail.is_empty() && !tail.starts_with(':') {
            anyhow::bail!("invalid bracketed IPv6 host");
        }
        return Ok(rest[..end].to_string());
    }

    if let Some((name, port)) = host.rsplit_once(':') {
        if !name.contains(':') && !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Ok(name.to_string());
        }
    }

    Ok(host.to_string())
}

#[derive(Debug, Deserialize)]
struct DohJsonResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohJsonAnswer>,
}

#[derive(Debug, Deserialize)]
struct DohJsonAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

async fn resolve_one_doh_json(
    host: &str,
    doh_addr: &str,
    dns: &DnsConfig,
) -> anyhow::Result<Option<IpAddr>> {
    let addr: SocketAddr = doh_addr.parse()?;
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .timeout(Duration::from_secs(8))
        .resolve(&dns.doh_host, addr)
        .build()?;
    for record_type in ["A", "AAAA"] {
        let url = format!(
            "https://{}{}?name={}&type={record_type}",
            dns.doh_host, dns.doh_path, host
        );
        let response = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/dns-json")
            .send()
            .await?
            .error_for_status()?
            .json::<DohJsonResponse>()
            .await?;
        if response.status != 0 {
            anyhow::bail!("DNS status {}", response.status);
        }
        let expected_type = match record_type {
            "A" => 1,
            "AAAA" => 28,
            _ => unreachable!("only A and AAAA are requested"),
        };
        if let Some(ip) = response
            .answer
            .into_iter()
            .filter(|answer| answer.record_type == expected_type)
            .find_map(|answer| answer.data.parse::<IpAddr>().ok())
        {
            return Ok(Some(ip));
        }
    }
    Ok(None)
}

fn strategies_file(cfg: &AppConfig, strategies_dir: Option<&std::path::Path>) -> PathBuf {
    match strategies_dir {
        Some(dir) => dir.join("strategies.yaml"),
        None => cfg.strategies.file.clone(),
    }
}

fn shutdown_token() -> CancellationToken {
    let token = CancellationToken::new();
    let ctrl_c = token.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        ctrl_c.cancel();
    });
    #[cfg(unix)]
    {
        let sigterm = token.clone();
        tokio::spawn(async move {
            if let Ok(mut signal) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                let _ = signal.recv().await;
                sigterm.cancel();
            }
        });
    }
    token
}

fn print_probe_result(prefix: &str, r: &ProbeResult) {
    println!("{}outcome:       {:?}", prefix, r.outcome);
    println!("{}failure_kind:  {:?}", prefix, r.failure_kind);
    println!("{}error_class:   {:?}", prefix, r.error_class);

    if let Some(msg) = &r.error_message {
        println!("{}error:         {}", prefix, msg);
    }

    println!(
        "{}timing:        connect={}ms tls={}ms first_byte={}ms total={}ms",
        prefix,
        fmt_ms(r.connect_ms),
        fmt_ms(r.tls_ms),
        fmt_ms(r.first_byte_ms),
        r.total_ms,
    );

    println!(
        "{}http_status:   {}",
        prefix,
        r.http_status
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into())
    );

    println!("{}bytes_read:    {}", prefix, r.bytes_read);
    println!("{}header_bytes:  {}", prefix, r.header_bytes);
    println!("{}body_bytes:    {}", prefix, r.body_bytes);
    println!("{}total_bytes:   {}", prefix, r.total_bytes);
    println!("{}transfer_level: {:?}", prefix, r.transfer_level);
    if r.dpi_suspicious {
        println!("{}dpi_suspicious: true", prefix);
    }
}

fn fmt_ms(v: Option<u64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".into())
}

fn live_probe_summary(r: &ProbeResult) -> String {
    format!(
        "outcome={:?} http={} body={}B bytes={} transfer={:?} dpi={} connect={}ms tls={}ms first_byte={}ms total={}ms failure={:?} error={:?}",
        r.outcome,
        r.http_status
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into()),
        r.body_bytes,
        r.bytes_read,
        r.transfer_level,
        r.dpi_suspicious,
        fmt_ms(r.connect_ms),
        fmt_ms(r.tls_ms),
        fmt_ms(r.first_byte_ms),
        r.total_ms,
        r.failure_kind,
        r.error_class,
    )
}

fn unique_strategy_targets(targets: &[StrategyProbeTarget]) -> usize {
    let mut seen = std::collections::BTreeSet::new();
    for target in targets {
        seen.insert((
            target.host.clone(),
            target.port,
            target.request.path_and_query.clone(),
        ));
    }
    seen.len()
}

fn target_display_key(target: &StrategyProbeTarget) -> String {
    format!(
        "{}:{}{}",
        target.host, target.port, target.request.path_and_query
    )
}

fn dedup_strings(items: &[String]) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item.clone());
        }
    }
    out
}

fn strategy_param_names(strategy_values: &StrategyValuesConfig, protocol_key: &str) -> String {
    let names = strategy_values.param_names_for_protocol_key(protocol_key);
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    }
}

fn payload_summary(cfg: &AppConfig, payloads: &[PayloadDef]) -> PayloadSummary {
    let mut summary = PayloadSummary {
        http: PayloadProtocolSummary::default(),
        tls: PayloadProtocolSummary::default(),
        quic: PayloadProtocolSummary::default(),
        base_dir: cfg
            .blobs
            .base_dir
            .as_ref()
            .map(|path| path.display().to_string()),
        auto_load: cfg.blobs.auto_load,
    };

    for payload in payloads {
        let target = match payload.protocol {
            PayloadProtocol::Http => &mut summary.http,
            PayloadProtocol::Tls => &mut summary.tls,
            PayloadProtocol::Quic => &mut summary.quic,
        };
        if payload.builtin {
            target.builtin += 1;
        } else {
            target.files += 1;
        }
    }

    summary
}

fn payload_blob_imports(payloads: &[PayloadDef]) -> Vec<BlobImport> {
    payloads
        .iter()
        .filter_map(|payload| {
            let path = payload.path.as_ref()?;
            Some(BlobImport {
                alias: payload.alias.clone(),
                path: path.display().to_string(),
                arg: format!("--blob={}:@{}", payload.alias, path.display()),
            })
        })
        .collect()
}

fn combination_summary(
    cfg: &StrategyCombinationConfig,
    nodes: &[graph::StrategyNode],
) -> CombinationSummary {
    CombinationSummary {
        enabled: cfg.enabled,
        allowed_pairs: cfg.allowed.len(),
        generated: nodes.iter().filter(|node| node.is_combined).count(),
    }
}

fn strategy_report_name(node: &graph::StrategyNode) -> String {
    if node.is_combined {
        format!("{} {}", node.family, node.action_id)
    } else {
        node.id.clone()
    }
}

fn strategy_command_args<'a>(args: &'a [String], blob_imports: &'a [BlobImport]) -> Vec<&'a str> {
    let aliases = blob_aliases_in_args(args);
    let mut out = Vec::new();
    for import in blob_imports {
        if aliases.contains(&import.alias) {
            out.push(import.arg.as_str());
        }
    }
    out.extend(args.iter().map(String::as_str));
    out
}

fn blob_aliases_in_args(args: &[String]) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    for arg in args {
        let mut rest = arg.as_str();
        while let Some(index) = rest.find("blob=") {
            let value_start = index + "blob=".len();
            let value = &rest[value_start..];
            let alias = value
                .chars()
                .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                .collect::<String>();
            let alias_len = alias.len();
            if !alias.is_empty() {
                aliases.insert(alias);
            }
            rest = &value[alias_len..];
        }
    }
    aliases
}

fn print_check_report(output: &CheckOutput, strategy_values: &StrategyValuesConfig) {
    println!("Target");
    println!("  url:        {}", output.target);
    println!("  scheme:     {:?}", output.target_scheme);
    println!("  host:       {}", output.baseline.target_host);
    println!("  ip:         {}", output.baseline.target_ip);
    println!("  port:       {}", output.baseline.target_port);
    println!("  protocol:   {:?}", output.baseline.protocol);
    println!("  method:     {}", output.request.method.as_str());
    println!("  path:       {}", output.baseline.path);
    println!("  read_mode:  {:?}", output.baseline.read_mode);
    println!("  user-agent: {}", output.request.user_agent);
    println!("  tests:      {}", output.test_count);
    println!();

    println!("Baseline");
    print_probe_result("  ", &output.baseline);
    println!();

    let total = output.results.len();
    let success = output
        .results
        .iter()
        .filter(|r| r.result.outcome == ProbeOutcome::Success)
        .count();

    let failed = total.saturating_sub(success);

    println!();

    println!("Parallelism");
    println!("  workers: {}", output.workers_count);
    println!("  active_model: nfqws-per-task");
    println!("  isolation: {}", output.isolation_mode);
    println!();

    println!("Summary");
    println!("  generated: {}", output.generated_count);
    println!("  tested:   {}", total);
    println!("  success:  {}", success);
    println!("  failed:   {}", failed);
    println!("  search_mode: {}", output.search_mode);
    println!("  round_robin: {}", output.round_robin_families);
    println!(
        "  test_targets: {}",
        dedup_strings(&output.test_targets).join(", ")
    );
    println!(
        "  stop_at_success: {}",
        if output.successful_strategy_limit == 0 {
            "disabled".into()
        } else {
            output.successful_strategy_limit.to_string()
        }
    );
    println!();

    println!("Strategy values");
    println!("  mode: {}", strategy_values.mode);
    println!(
        "  http params: {}",
        strategy_param_names(strategy_values, "http")
    );
    println!(
        "  tls params: {}",
        strategy_param_names(strategy_values, "tls")
    );
    println!(
        "  quic params: {}",
        strategy_param_names(strategy_values, "quic")
    );
    println!();

    if let Some(payloads) = &output.payload_summary {
        println!("Payloads");
        println!(
            "  http: builtin={} files={}",
            payloads.http.builtin, payloads.http.files
        );
        println!(
            "  tls:  builtin={} files={}",
            payloads.tls.builtin, payloads.tls.files
        );
        println!(
            "  quic: builtin={} files={}",
            payloads.quic.builtin, payloads.quic.files
        );
        println!(
            "  base_dir: {}",
            payloads.base_dir.as_deref().unwrap_or("-")
        );
        println!("  auto_load: {}", payloads.auto_load);
        println!();
    }

    if let Some(combinations) = &output.combination_summary {
        println!("Combinations");
        println!("  enabled: {}", combinations.enabled);
        println!("  allowed_pairs: {}", combinations.allowed_pairs);
        println!("  generated: {}", combinations.generated);
        println!();
    }

    println!("Families");
    let mut families = std::collections::BTreeMap::<String, FamilyCounters>::new();
    for item in &output.results {
        let counters = families.entry(item.node.family.clone()).or_default();
        counters.tested += 1;
        if item.result.outcome == ProbeOutcome::Success {
            counters.success += 1;
        } else {
            counters.failed += 1;
        }
    }
    if families.is_empty() {
        println!("  none");
    } else {
        for (family, counters) in families {
            println!(
                "  {:<14} tested={} success={} failed={}",
                family, counters.tested, counters.success, counters.failed
            );
        }
    }

    println!();

    println!("Best strategies");

    let mut successful: Vec<_> = output
        .results
        .iter()
        .filter(|r| r.result.outcome == ProbeOutcome::Success)
        .collect();

    successful.sort_by(|a, b| {
        b.adaptive_score
            .total_cmp(&a.adaptive_score)
            .then_with(|| a.node.cost.total_cmp(&b.node.cost))
            .then_with(|| a.node.risk.total_cmp(&b.node.risk))
            .then_with(|| a.node.id.cmp(&b.node.id))
    });

    if successful.is_empty() {
        println!("  none");
    } else {
        for item in successful {
            let strategy_name = strategy_report_name(&item.node);
            println!(
                "  [{:>6.1}] {:<36} {:<12} http={} body={}B tls={}ms total={}ms",
                item.adaptive_score,
                strategy_name,
                item.node.family,
                item.result
                    .http_status
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                item.result.body_bytes,
                item.result
                    .tls_ms
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                item.result.total_ms,
            );

            for arg in strategy_command_args(&item.node.args, &output.payload_blob_imports) {
                println!("           {}", arg);
            }
            if item.node.is_combined {
                println!("           components:");
                for component in &item.node.components {
                    println!(
                        "             - {}/{}",
                        component.family, component.action_id
                    );
                }
            }
        }
    }

    println!();

    println!("Failed strategies");

    for item in output
        .results
        .iter()
        .filter(|r| r.result.outcome != ProbeOutcome::Success)
        .take(20)
    {
        let strategy_name = strategy_report_name(&item.node);
        println!(
            "  [{:>6.1}] {:<36} {:<12} {:?} / {:?}",
            item.adaptive_score,
            strategy_name,
            item.node.family,
            item.result.outcome,
            item.result.error_class,
        );

        if let Some(msg) = &item.result.error_message {
            println!("           {}", msg);
        }

        for arg in strategy_command_args(&item.node.args, &output.payload_blob_imports) {
            println!("           {}", arg);
        }
        if item.node.is_combined {
            println!("           components:");
            for component in &item.node.components {
                println!(
                    "             - {}/{}",
                    component.family, component.action_id
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{StrategyComponent, StrategyNode};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn report_does_not_panic_without_payloads() {
        let output = check_output(Vec::new(), None, None);
        print_check_report(&output, &StrategyValuesConfig::default());
    }

    #[test]
    fn report_combined_strategy_name_includes_family_and_actions() {
        let node = combined_node();
        assert_eq!(
            strategy_report_name(&node),
            "combined_fake_split fake_tls+multisplit_tls"
        );
    }

    #[test]
    fn report_payload_summary_counts_payloads() {
        let mut cfg = AppConfig::load(&PathBuf::from("config/checker.toml")).unwrap();
        cfg.blobs.auto_load = true;
        let payloads = vec![
            PayloadDef {
                protocol: PayloadProtocol::Tls,
                alias: "fake_default_tls".to_string(),
                path: None,
                builtin: true,
            },
            PayloadDef {
                protocol: PayloadProtocol::Tls,
                alias: "tls_google".to_string(),
                path: Some("tls.bin".into()),
                builtin: false,
            },
            PayloadDef {
                protocol: PayloadProtocol::Http,
                alias: "fake_default_http".to_string(),
                path: None,
                builtin: true,
            },
        ];

        let summary = payload_summary(&cfg, &payloads);

        assert_eq!(summary.http.builtin, 1);
        assert_eq!(summary.http.files, 0);
        assert_eq!(summary.tls.builtin, 1);
        assert_eq!(summary.tls.files, 1);
        assert!(summary.auto_load);
    }

    #[test]
    fn strategy_command_args_include_used_blob_import_before_strategy_args() {
        let args = vec!["--lua-desync=fake:blob=tls_google:fooling=badsum".to_string()];
        let imports = vec![
            BlobImport {
                alias: "http_other".to_string(),
                path: "/tmp/http.bin".to_string(),
                arg: "--blob=http_other:@/tmp/http.bin".to_string(),
            },
            BlobImport {
                alias: "tls_google".to_string(),
                path: "/tmp/tls.bin".to_string(),
                arg: "--blob=tls_google:@/tmp/tls.bin".to_string(),
            },
        ];

        assert_eq!(
            strategy_command_args(&args, &imports),
            vec![
                "--blob=tls_google:@/tmp/tls.bin",
                "--lua-desync=fake:blob=tls_google:fooling=badsum"
            ]
        );
    }

    #[test]
    fn blob_aliases_are_extracted_from_multiple_strategy_args() {
        let args = vec![
            "--lua-desync=fake:blob=tls_a".to_string(),
            "--lua-desync=syndata:blob=tls_b:fooling=autottl".to_string(),
        ];

        assert_eq!(
            blob_aliases_in_args(&args).into_iter().collect::<Vec<_>>(),
            vec!["tls_a".to_string(), "tls_b".to_string()]
        );
    }

    #[test]
    fn doh_normalizes_host_port_before_query() {
        assert_eq!(
            normalize_dns_host("example.com:8443").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn doh_normalizes_bracketed_ipv6_literal() {
        assert_eq!(
            normalize_dns_host("[2001:db8::1]:443").unwrap(),
            "2001:db8::1"
        );
    }

    #[test]
    fn report_non_combined_strategy_name_is_old_id() {
        let node = single_node("tls12_fake_0");
        assert_eq!(strategy_report_name(&node), "tls12_fake_0");
    }

    fn check_output(
        results: Vec<scheduler::StrategyRunResult>,
        payload_summary: Option<PayloadSummary>,
        combination_summary: Option<CombinationSummary>,
    ) -> CheckOutput {
        CheckOutput {
            target: "https://example.com/".to_string(),
            target_scheme: TargetScheme::Https,
            request: request(),
            test_count: 1,
            test_targets: vec!["example.com:443/".to_string()],
            baseline: probe_result("baseline", ProbeOutcome::Success),
            results,
            successful_strategy_limit: 10,
            search_mode: "signal".to_string(),
            round_robin_families: true,
            generated_count: 0,
            workers_count: 1,
            isolation_mode: "source_port".to_string(),
            payload_summary,
            payload_blob_imports: Vec::new(),
            combination_summary,
        }
    }

    fn request() -> HttpRequestSpec {
        HttpRequestSpec {
            method: HttpMethod::Get,
            path_and_query: "/".to_string(),
            user_agent: "test".to_string(),
            read_mode: ReadMode::Body,
            min_body_bytes: 1,
            dpi_detection_bytes: 16384,
            verify_transfer_bytes: 32768,
            max_read_bytes: 1024,
        }
    }

    fn probe_result(strategy_id: &str, outcome: ProbeOutcome) -> ProbeResult {
        ProbeResult {
            strategy_id: strategy_id.to_string(),
            worker_id: 0,
            qnum: None,
            assigned_source_port: None,
            target_host: "example.com".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            target_port: 443,
            protocol: ProbeProtocol::Tls12Http11,
            path: "/".to_string(),
            method: HttpMethod::Get,
            read_mode: ReadMode::Body,
            setup_ms: Some(0),
            connect_ms: Some(0),
            tls_ms: Some(0),
            first_byte_ms: Some(0),
            total_ms: 1,
            outcome,
            http_status: Some(200),
            bytes_read: 128,
            header_bytes: 64,
            body_bytes: 64,
            total_bytes: 128,
            transfer_level: TransferLevel::Body,
            dpi_suspicious: false,
            failure_kind: None,
            error_class: None,
            error_message: None,
        }
    }

    fn single_node(id: &str) -> StrategyNode {
        StrategyNode {
            id: id.to_string(),
            family: "fake".to_string(),
            action_id: "fake_tls".to_string(),
            args: vec!["--lua-desync=fake".to_string()],
            components: vec![StrategyComponent {
                family: "fake".to_string(),
                action_id: "fake_tls".to_string(),
                args: vec!["--lua-desync=fake".to_string()],
            }],
            is_combined: false,
            cost: 1.0,
            risk: 1.0,
            prior: (1.0, 1.0),
        }
    }

    fn combined_node() -> StrategyNode {
        StrategyNode {
            id: "tls12_combined_fake_split_0".to_string(),
            family: "combined_fake_split".to_string(),
            action_id: "fake_tls+multisplit_tls".to_string(),
            args: vec![
                "--lua-desync=fake".to_string(),
                "--lua-desync=multisplit".to_string(),
            ],
            components: vec![
                StrategyComponent {
                    family: "fake".to_string(),
                    action_id: "fake_tls".to_string(),
                    args: vec!["--lua-desync=fake".to_string()],
                },
                StrategyComponent {
                    family: "split".to_string(),
                    action_id: "multisplit_tls".to_string(),
                    args: vec!["--lua-desync=multisplit".to_string()],
                },
            ],
            is_combined: true,
            cost: 5.0,
            risk: 2.0,
            prior: (1.0, 1.0),
        }
    }
}
