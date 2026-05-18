mod bayes;
mod config;
mod firewall;
mod graph;
mod nfqws;
mod ordering;
mod probe;
mod pruning;
mod queue;
mod scheduler;
mod scoring;
mod types;
mod worker;

use anyhow::Context;
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
#[command(name = "zapret-checker")]
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
        host: String,
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
    baseline: ProbeResult,
    results: Vec<scheduler::StrategyRunResult>,
    successful_strategy_limit: usize,
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
                path: cfg.probe.path,
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
            let protocol = selected_protocol(&cfg, probe_protocol)?;
            let port = protocol.default_port();
            let ip = resolve_one(&host, port)?;
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
                    target_host: host,
                    target_ip: ip,
                    protocol,
                    target_port: protocol.default_port(),
                    path: cfg.probe.path,
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
            let baseline = run_baseline_probe(
                &native_probe,
                host.clone(),
                ip,
                cfg.probe.path.clone(),
                timeouts.clone(),
                Some(cancellation.clone()),
                protocol,
            )
            .await;
            let successful_strategy_limit =
                successful_strategy_limit.unwrap_or(cfg.strategies.successful_strategy_limit);
            if should_skip_strategies_after_baseline(&baseline) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&CheckOutput {
                        baseline,
                        results: Vec::new(),
                        successful_strategy_limit,
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
            let mut graph = StrategyGraph::load_for_protocol(
                &strategies_file,
                &transition_matrix_file,
                protocol.catalog_key(),
            )?;
            if graph.nodes.len() > cfg.strategies.max_candidates {
                graph.nodes.truncate(cfg.strategies.max_candidates);
            }
            let scheduler = scheduler::Scheduler {
                runtime,
                workers_count: workers
                    .unwrap_or(cfg.workers.count)
                    .min(cfg.queue.qnum_count as usize)
                    .max(1),
                successful_strategy_limit,
                pruning_policy: PruningPolicy {
                    soft_fail_family_limit: cfg
                        .strategies
                        .soft_fail_family_limit
                        .try_into()
                        .context("strategies.soft_fail_family_limit does not fit into u32")?,
                    combo_requires_signal: true,
                },
                score_weights: ScoreWeights::default(),
                protocol,
            };
            let bayes_path = bayes_state.unwrap_or_else(|| cfg.bayes.state_file.clone());
            let mut bayes = BayesianState::load(&bayes_path)?;
            let results = scheduler
                .run_graph_with_bayes(
                    host,
                    ip,
                    graph,
                    cfg.probe.path,
                    timeouts,
                    cancellation,
                    &mut bayes,
                )
                .await;
            bayes.save(&bayes_path)?;
            if cfg.firewall.cleanup_on_exit {
                fw.cleanup_all().await?;
            }
            let output = &CheckOutput {
                baseline,
                results,
                successful_strategy_limit,
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
    path: String,
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
        target_port: 443,
        protocol,
        path,
        timeouts,
    };
    let ctx = ProbeContext {
        qnum: 0,
        cancellation,
        baseline: true,
    };
    ProbeBackend::probe(probe, task, ctx).await
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
}

fn fmt_ms(v: Option<u64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".into())
}

fn print_check_report(output: &CheckOutput) {
    println!("Target");
    println!("  host:     {}", output.baseline.target_host);
    println!("  ip:       {}", output.baseline.target_ip);
    println!("  port:     {}", output.baseline.target_port);
    println!("  protocol: {:?}", output.baseline.protocol);
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
    println!("  tested:   {}", total);
    println!("  success:  {}", success);
    println!("  failed:   {}", failed);
    println!(
        "  stop_at_success: {}",
        if output.successful_strategy_limit == 0 {
            "disabled".into()
        } else {
            output.successful_strategy_limit.to_string()
        }
    );
    println!();

    println!("Best strategies");

    let mut successful: Vec<_> = output
        .results
        .iter()
        .filter(|r| r.result.outcome == ProbeOutcome::Success)
        .collect();

    successful.sort_by(|a, b| {
        b.adaptive_score
            .partial_cmp(&a.adaptive_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if successful.is_empty() {
        println!("  none");
    } else {
        for item in successful {
            println!(
                "  [{:>6.1}] {:<36} {:<12} http={} tls={}ms total={}ms",
                item.adaptive_score,
                item.node.id,
                item.node.family,
                item.result
                    .http_status
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
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
