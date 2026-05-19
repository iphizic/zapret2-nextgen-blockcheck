mod bayes;
mod config;
mod firewall;
mod graph;
mod nfqws;
mod probe;
mod pruning;
mod queue;
mod scheduler;
mod scoring;
mod types;
mod worker;

use bayes::BayesianState;
use clap::{Parser, Subcommand};
use config::AppConfig;
use firewall::{FirewallHook, FirewallManager, IptablesFirewallManager, NftablesFirewallManager};
use graph::StrategyGraph;
use nfqws::ProcessNfqwsManager;
use probe::{NativeTcpTlsHttpProbe, ProbeBackend};
use pruning::PruningPolicy;
use queue::QueueAllocator;
use scoring::ScoreWeights;
use serde::Serialize;
use std::{net::ToSocketAddrs, path::PathBuf, sync::Arc};
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
    max_candidates: usize,
    max_per_family: usize,
    max_per_action: usize,
    round_robin_families: bool,
    generated_count: usize,
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
            let fw = build_firewall(&cfg);
            fw.cleanup_all().await?;
        }
        Commands::Baseline { config, host } => {
            let cfg = AppConfig::load(&config)?;
            let protocol = ProbeProtocol::Tls12Http11;
            let ip = resolve_one(&host, 443)?;
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
            let ip = resolve_one(&target.host, target.port)?;
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
                )?
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
                    "live: target {} host={} ip={} port={} protocol={:?} method={} read_mode={:?}",
                    target.original,
                    target.host,
                    ip,
                    target.port,
                    target.protocol,
                    request.method.as_str(),
                    request.read_mode,
                );
                eprintln!("live: baseline start");
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
                eprintln!("live: baseline {}", live_probe_summary(&baseline));
            }
            let successful_strategy_limit =
                successful_strategy_limit.unwrap_or(cfg.strategies.successful_strategy_limit);
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
                        max_candidates: cfg.strategies.max_candidates,
                        max_per_family: cfg.strategies.max_per_family,
                        max_per_action: cfg.strategies.max_per_action,
                        round_robin_families: cfg.strategies.round_robin_families,
                        generated_count: 0,
                    })?
                );
                return Ok(());
            }
            let nfqws_binary = nfqws_binary.unwrap_or_else(|| cfg.nfqws.binary.clone());
            validate_nfqws_binary(&nfqws_binary)?;
            let nfqws_library_paths = nfqws_library_paths(&cfg, &nfqws_binary, nfqws_lib_dir);
            validate_nfqws_library_paths(&nfqws_library_paths)?;
            let fw = build_firewall(&cfg);
            fw.setup().await?;
            let qa = QueueAllocator::new(cfg.queue.base_qnum, cfg.queue.qnum_count)?;
            let nfqws = Arc::new(ProcessNfqwsManager {
                stop_timeout_ms: cfg.nfqws.stop_timeout_ms,
            });
            let runtime = WorkerRuntime {
                queue_allocator: qa,
                firewall: fw.clone(),
                nfqws,
                native_probe,
                nfqws_binary,
                nfqws_library_paths,
                nfqws_base_args: cfg.nfqws.base_args.clone(),
                nfqws_start_grace_ms: cfg.nfqws.start_grace_ms,
                nfqws_log_stdout: cfg.nfqws.log_stdout || cfg.debug.verbose_nfqws,
                nfqws_log_stderr: cfg.nfqws.log_stderr || cfg.debug.verbose_nfqws,
                firewall_hook: parse_hook(&cfg.firewall.hook),
            };
            let (strategies_file, transition_matrix_file) =
                strategy_paths(&cfg, strategies_dir.as_deref());
            let graph = StrategyGraph::load_for_protocol_mode(
                &strategies_file,
                &transition_matrix_file,
                target.protocol.catalog_key(),
                &cfg.strategies.search_mode,
                cfg.strategies.max_candidates,
                cfg.strategies.max_per_family,
                cfg.strategies.max_per_action,
                cfg.strategies.round_robin_families,
            )?;
            let generated_count = graph.nodes.len();
            if !json {
                eprintln!(
                    "live: strategies start generated={} workers={} domains={} repeats={} total_tests={} stop_at_success={}",
                    generated_count,
                    workers
                        .unwrap_or(cfg.workers.count)
                        .min(cfg.queue.qnum_count as usize)
                        .max(1),
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
                workers_count: workers
                    .unwrap_or(cfg.workers.count)
                    .min(cfg.queue.qnum_count as usize)
                    .max(1),
                successful_strategy_limit,
                pruning_policy: PruningPolicy {
                    soft_fail_family_limit: cfg.strategies.soft_fail_family_limit,
                    combo_requires_signal: true,
                },
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
                    "live: strategies done tested={} success={} failed={}",
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
                max_candidates: cfg.strategies.max_candidates,
                max_per_family: cfg.strategies.max_per_family,
                max_per_action: cfg.strategies.max_per_action,
                round_robin_families: cfg.strategies.round_robin_families,
                generated_count,
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                print_check_report(&output);
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

fn build_strategy_targets(
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
        append_repeated_strategy_target(cfg, &mut targets, parsed, primary_request, test_count)?;
    }

    Ok(targets)
}

fn append_repeated_strategy_target(
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
    let ip = resolve_one(&parsed.host, parsed.port)?;
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

fn build_firewall(cfg: &AppConfig) -> Arc<dyn FirewallManager> {
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

fn resolve_one(host: &str, port: u16) -> anyhow::Result<std::net::IpAddr> {
    Ok((host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address"))?
        .ip())
}

fn strategy_paths(cfg: &AppConfig, strategies_dir: Option<&std::path::Path>) -> (PathBuf, PathBuf) {
    match strategies_dir {
        Some(dir) => (
            dir.join("strategies.yaml"),
            dir.join("transition_matrix.yaml"),
        ),
        None => default_strategy_paths(cfg),
    }
}

fn default_strategy_paths(cfg: &AppConfig) -> (PathBuf, PathBuf) {
    if cfg.strategies.file.exists() && cfg.strategies.transition_matrix.exists() {
        (
            cfg.strategies.file.clone(),
            cfg.strategies.transition_matrix.clone(),
        )
    } else {
        (
            PathBuf::from("config/standart/strategies.yaml"),
            PathBuf::from("config/standart/transition_matrix.yaml"),
        )
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
}

fn fmt_ms(v: Option<u64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".into())
}

fn live_probe_summary(r: &ProbeResult) -> String {
    format!(
        "outcome={:?} http={} body={}B bytes={} connect={}ms tls={}ms first_byte={}ms total={}ms failure={:?} error={:?}",
        r.outcome,
        r.http_status
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into()),
        r.body_bytes,
        r.bytes_read,
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

fn print_check_report(output: &CheckOutput) {
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

    println!("Summary");
    println!("  generated: {}", output.generated_count);
    println!("  tested:   {}", total);
    println!("  success:  {}", success);
    println!("  failed:   {}", failed);
    println!("  search_mode: {}", output.search_mode);
    println!("  max_candidates: {}", output.max_candidates);
    println!("  max_per_family: {}", output.max_per_family);
    println!("  max_per_action: {}", output.max_per_action);
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
            println!(
                "  [{:>6.1}] {:<36} {:<12} http={} body={}B tls={}ms total={}ms",
                item.adaptive_score,
                item.node.id,
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

            for arg in &item.node.args {
                println!("           {}", arg);
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
        println!(
            "  [{:>6.1}] {:<36} {:<12} {:?} / {:?}",
            item.adaptive_score,
            item.node.id,
            item.node.family,
            item.result.outcome,
            item.result.error_class,
        );

        if let Some(msg) = &item.result.error_message {
            println!("           {}", msg);
        }

        for arg in &item.node.args {
            println!("           {}", arg);
        }
    }
}
