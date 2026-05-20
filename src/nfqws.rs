use async_trait::async_trait;
use std::{path::PathBuf, process::Stdio, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::{Child, Command},
    time::{sleep, timeout},
};
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum NfqwsError {
    #[error("start failed: {0}")]
    StartFailed(String),
    #[error("exited early: {0}")]
    ExitedEarly(String),
    #[error("stop failed: {0}")]
    StopFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct NfqwsInstanceConfig {
    pub qnum: u16,
    pub binary: PathBuf,
    pub library_paths: Vec<PathBuf>,
    pub base_args: Vec<String>,
    pub strategy_args: Vec<String>,
    pub worker_id: usize,
    pub strategy_id: String,
    pub start_grace_ms: u64,
    pub log_stdout: bool,
    pub log_stderr: bool,
}

pub struct NfqwsHandle {
    pub qnum: u16,
    pub worker_id: usize,
    pub strategy_id: String,
    pub child: Child,
}

#[async_trait]
pub trait NfqwsManager: Send + Sync {
    async fn start(&self, cfg: NfqwsInstanceConfig) -> Result<NfqwsHandle, NfqwsError>;
    async fn stop(&self, handle: NfqwsHandle) -> Result<(), NfqwsError>;
}

#[derive(Debug, Clone)]
pub struct ProcessNfqwsManager {
    pub stop_timeout_ms: u64,
}

#[async_trait]
impl NfqwsManager for ProcessNfqwsManager {
    async fn start(&self, cfg: NfqwsInstanceConfig) -> Result<NfqwsHandle, NfqwsError> {
        let mut cmd = Command::new(&cfg.binary);
        cmd.args(&cfg.base_args);
        cmd.arg(format!("--qnum={}", cfg.qnum));
        cmd.args(&cfg.strategy_args);
        if !cfg.library_paths.is_empty() {
            cmd.env("LD_LIBRARY_PATH", render_library_path(&cfg.library_paths));
        }
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| NfqwsError::StartFailed(e.to_string()))?;
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        sleep(Duration::from_millis(cfg.start_grace_ms)).await;
        if let Some(status) = child.try_wait()? {
            let mut out = String::new();
            let mut err = String::new();
            if let Some(mut stdout) = stdout.take() {
                let _ = stdout.read_to_string(&mut out).await;
            }
            if let Some(mut stderr) = stderr.take() {
                let _ = stderr.read_to_string(&mut err).await;
            }
            return Err(NfqwsError::ExitedEarly(format!(
                "status={status}, args={:?}, stdout={}, stderr={}",
                rendered_args(&cfg),
                out.trim(),
                err.trim()
            )));
        }
        if let Some(stdout) = stdout.take() {
            let worker_id = cfg.worker_id;
            let qnum = cfg.qnum;
            let strategy_id = cfg.strategy_id.clone();
            let log_stdout = cfg.log_stdout;
            tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if log_stdout {
                        debug!(worker_id, qnum, strategy_id = %strategy_id, stream = "stdout", line = %line, "nfqws2 output");
                    }
                }
            });
        }
        if let Some(stderr) = stderr.take() {
            let worker_id = cfg.worker_id;
            let qnum = cfg.qnum;
            let strategy_id = cfg.strategy_id.clone();
            let log_stderr = cfg.log_stderr;
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if log_stderr {
                        debug!(worker_id, qnum, strategy_id = %strategy_id, stream = "stderr", line = %line, "nfqws2 output");
                    }
                }
            });
        }
        debug!(worker_id = cfg.worker_id, qnum = cfg.qnum, strategy_id = %cfg.strategy_id, "nfqws2 started");
        Ok(NfqwsHandle {
            qnum: cfg.qnum,
            worker_id: cfg.worker_id,
            strategy_id: cfg.strategy_id,
            child,
        })
    }

    async fn stop(&self, mut handle: NfqwsHandle) -> Result<(), NfqwsError> {
        if let Some(_status) = handle.child.try_wait()? {
            return Ok(());
        }
        debug!(worker_id = handle.worker_id, qnum = handle.qnum, strategy_id = %handle.strategy_id, "stopping nfqws2");
        if let Some(pid) = handle.child.id() {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .stdin(Stdio::null())
                .status()
                .await;
        }
        match timeout(
            Duration::from_millis(self.stop_timeout_ms),
            handle.child.wait(),
        )
        .await
        {
            Ok(Ok(status)) => {
                debug!(worker_id = handle.worker_id, qnum = handle.qnum, strategy_id = %handle.strategy_id, status = %status, "nfqws2 stopped");
                Ok(())
            }
            Ok(Err(e)) => Err(NfqwsError::StopFailed(e.to_string())),
            Err(_) => {
                warn!(worker_id = handle.worker_id, qnum = handle.qnum, strategy_id = %handle.strategy_id, "nfqws2 graceful stop timeout, killing");
                handle
                    .child
                    .start_kill()
                    .map_err(|e| NfqwsError::StopFailed(e.to_string()))?;
                match timeout(
                    Duration::from_millis(self.stop_timeout_ms),
                    handle.child.wait(),
                )
                .await
                {
                    Ok(Ok(status)) => {
                        debug!(worker_id = handle.worker_id, qnum = handle.qnum, strategy_id = %handle.strategy_id, status = %status, "nfqws2 killed");
                        Ok(())
                    }
                    Ok(Err(e)) => Err(NfqwsError::StopFailed(e.to_string())),
                    Err(_) => Err(NfqwsError::StopFailed("kill timeout".into())),
                }
            }
        }
    }
}

fn rendered_args(cfg: &NfqwsInstanceConfig) -> Vec<String> {
    build_nfqws_args(cfg)
}

pub fn build_nfqws_args(cfg: &NfqwsInstanceConfig) -> Vec<String> {
    let mut args = cfg.base_args.clone();
    args.push(format!("--qnum={}", cfg.qnum));
    args.extend(cfg.strategy_args.clone());
    args
}

fn render_library_path(paths: &[PathBuf]) -> String {
    let mut parts: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    if let Ok(existing) = std::env::var("LD_LIBRARY_PATH") {
        if !existing.is_empty() {
            parts.push(existing);
        }
    }
    parts.join(":")
}
