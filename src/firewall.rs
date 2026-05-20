use crate::worker::WorkerAssignment;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, process::Stdio};
use thiserror::Error;
use tokio::process::Command;
use tracing::debug;

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("command failed: {0}")]
    CommandFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum L4Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FirewallHook {
    Output,
    Postrouting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerFirewallRule {
    pub worker_id: usize,
    pub qnum: u16,
    pub source_port: u16,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub protocol: L4Protocol,
    pub hook: FirewallHook,
}

#[async_trait]
pub trait FirewallManager: Send + Sync {
    async fn setup(&self) -> Result<(), FirewallError>;
    async fn install_worker_rule(&self, rule: WorkerFirewallRule) -> Result<(), FirewallError>;
    async fn remove_worker_rule(&self, rule: WorkerFirewallRule) -> Result<(), FirewallError>;
    async fn cleanup_all(&self) -> Result<(), FirewallError>;
}

#[derive(Debug, Clone)]
pub struct NftablesFirewallManager {
    pub table: String,
    pub hook: FirewallHook,
    pub priority: String,
    pub cleanup_on_start: bool,
}

impl NftablesFirewallManager {
    pub fn render_add_rule(&self, rule: &WorkerFirewallRule) -> Vec<String> {
        let chain = match rule.hook {
            FirewallHook::Output => "output",
            FirewallHook::Postrouting => "postrouting",
        };
        let proto = match rule.protocol {
            L4Protocol::Tcp => "tcp",
            L4Protocol::Udp => "udp",
        };
        let ipkw = if rule.target_ip.is_ipv4() {
            "ip"
        } else {
            "ip6"
        };
        vec![
            "add".into(),
            "rule".into(),
            "inet".into(),
            self.table.clone(),
            chain.into(),
            ipkw.into(),
            "daddr".into(),
            rule.target_ip.to_string(),
            proto.into(),
            "sport".into(),
            rule.source_port.to_string(),
            proto.into(),
            "dport".into(),
            rule.target_port.to_string(),
            "queue".into(),
            "num".into(),
            rule.qnum.to_string(),
            "bypass".into(),
        ]
    }

    pub fn render_delete_rule_by_handle(
        &self,
        rule: &WorkerFirewallRule,
        handle: u64,
    ) -> Vec<String> {
        let chain = match rule.hook {
            FirewallHook::Output => "output",
            FirewallHook::Postrouting => "postrouting",
        };
        vec![
            "delete".into(),
            "rule".into(),
            "inet".into(),
            self.table.clone(),
            chain.into(),
            "handle".into(),
            handle.to_string(),
        ]
    }

    pub fn render_list_chain(&self, hook: FirewallHook) -> Vec<String> {
        let chain = match hook {
            FirewallHook::Output => "output",
            FirewallHook::Postrouting => "postrouting",
        };
        vec![
            "-a".into(),
            "list".into(),
            "chain".into(),
            "inet".into(),
            self.table.clone(),
            chain.into(),
        ]
    }

    async fn nft(&self, args: &[String]) -> Result<(), FirewallError> {
        let status = Command::new("nft")
            .args(args)
            .stdin(Stdio::null())
            .status()
            .await?;
        if status.success() {
            Ok(())
        } else {
            Err(FirewallError::CommandFailed(format!(
                "nft {:?} -> {}",
                args, status
            )))
        }
    }

    async fn nft_output(&self, args: &[String]) -> Result<String, FirewallError> {
        let output = Command::new("nft")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(FirewallError::CommandFailed(format!(
                "nft {:?} -> {}, stderr={}",
                args,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    async fn find_rule_handle(
        &self,
        rule: &WorkerFirewallRule,
    ) -> Result<Option<u64>, FirewallError> {
        let output = self.nft_output(&self.render_list_chain(rule.hook)).await?;
        Ok(find_nft_rule_handle(&output, rule))
    }

    async fn nft_quiet(&self, args: &[String]) -> Result<(), FirewallError> {
        let status = Command::new("nft")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await?;
        if status.success() {
            Ok(())
        } else {
            Err(FirewallError::CommandFailed(format!(
                "nft {:?} -> {}",
                args, status
            )))
        }
    }
}

#[async_trait]
impl FirewallManager for NftablesFirewallManager {
    async fn setup(&self) -> Result<(), FirewallError> {
        if self.cleanup_on_start {
            let _ = self.cleanup_all().await;
        }
        let _ = self
            .nft(&[
                "add".into(),
                "table".into(),
                "inet".into(),
                self.table.clone(),
            ])
            .await;
        let (chain, hook) = match self.hook {
            FirewallHook::Output => ("output", "output"),
            FirewallHook::Postrouting => ("postrouting", "postrouting"),
        };
        let args = vec![
            "add".into(),
            "chain".into(),
            "inet".into(),
            self.table.clone(),
            chain.into(),
            "{".into(),
            "type".into(),
            "filter".into(),
            "hook".into(),
            hook.into(),
            "priority".into(),
            self.priority.clone(),
            ";".into(),
            "}".into(),
        ];
        let _ = self.nft(&args).await;
        Ok(())
    }

    async fn install_worker_rule(&self, rule: WorkerFirewallRule) -> Result<(), FirewallError> {
        debug!(
            worker_id = rule.worker_id,
            qnum = rule.qnum,
            assigned_source_port = rule.source_port,
            target_ip = %rule.target_ip,
            target_port = rule.target_port,
            firewall_hook = ?rule.hook,
            backend = "nftables",
            "install firewall rule"
        );
        self.nft(&self.render_add_rule(&rule)).await
    }

    async fn remove_worker_rule(&self, rule: WorkerFirewallRule) -> Result<(), FirewallError> {
        debug!(
            worker_id = rule.worker_id,
            qnum = rule.qnum,
            assigned_source_port = rule.source_port,
            target_ip = %rule.target_ip,
            target_port = rule.target_port,
            firewall_hook = ?rule.hook,
            backend = "nftables",
            "remove firewall rule"
        );
        let Some(handle) = self.find_rule_handle(&rule).await? else {
            return Ok(());
        };
        self.nft(&self.render_delete_rule_by_handle(&rule, handle))
            .await
    }

    async fn cleanup_all(&self) -> Result<(), FirewallError> {
        let args = vec![
            "delete".into(),
            "table".into(),
            "inet".into(),
            self.table.clone(),
        ];
        let _ = self.nft_quiet(&args).await;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NftablesVmapFirewallManager {
    pub table: String,
    pub hook: FirewallHook,
    pub priority: String,
    pub cleanup_on_start: bool,
    pub desync_mark: u32,
    pub assignments: Vec<WorkerAssignment>,
}

impl NftablesVmapFirewallManager {
    pub fn render_setup_script(&self) -> String {
        let chain = match self.hook {
            FirewallHook::Output => "output",
            FirewallHook::Postrouting => "postrouting",
        };
        let meta_elements = self
            .assignments
            .iter()
            .filter_map(|assignment| {
                assignment.fwmark.map(|mark| {
                    format!(
                        "            {mark:#x} : queue num {} bypass,",
                        assignment.qnum
                    )
                })
            })
            .collect::<Vec<_>>()
            .join("\n");
        let ct_elements = meta_elements.clone();

        format!(
            r#"table inet {table} {{
    map meta_mark_queue {{
        type mark : meta mark;
        elements = {{
{meta_elements}
        }};
    }}

    map ct_mark_queue {{
        type mark : meta mark;
        elements = {{
{ct_elements}
        }};
    }}

    chain {chain} {{
        type filter hook {chain} priority {priority}; policy accept;
        meta mark {desync_mark:#x} notrack counter accept comment "desync bypass";
        meta mark vmap @meta_mark_queue
        ct mark set meta mark
        ct mark vmap @ct_mark_queue
    }}

    chain input {{
        type filter hook input priority {priority}; policy accept;
        ct mark vmap @ct_mark_queue
    }}
}}"#,
            table = self.table,
            meta_elements = meta_elements,
            ct_elements = ct_elements,
            chain = chain,
            priority = self.priority,
            desync_mark = self.desync_mark,
        )
    }

    async fn nft_apply_script(&self, script: &str) -> Result<(), FirewallError> {
        use tokio::io::AsyncWriteExt;
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(script.as_bytes()).await?;
        }
        let output = child.wait_with_output().await?;
        if output.status.success() {
            Ok(())
        } else {
            Err(FirewallError::CommandFailed(format!(
                "nft script failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    async fn nft_quiet(&self, args: &[String]) -> Result<(), FirewallError> {
        let status = Command::new("nft")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await?;
        if status.success() {
            Ok(())
        } else {
            Err(FirewallError::CommandFailed(format!(
                "nft {:?} -> {}",
                args, status
            )))
        }
    }
}

#[async_trait]
impl FirewallManager for NftablesVmapFirewallManager {
    async fn setup(&self) -> Result<(), FirewallError> {
        if self.cleanup_on_start {
            let _ = self
                .nft_quiet(&[
                    "delete".into(),
                    "table".into(),
                    "inet".into(),
                    self.table.clone(),
                ])
                .await;
        }
        self.nft_apply_script(&self.render_setup_script()).await
    }

    async fn install_worker_rule(&self, _rule: WorkerFirewallRule) -> Result<(), FirewallError> {
        Ok(())
    }

    async fn remove_worker_rule(&self, _rule: WorkerFirewallRule) -> Result<(), FirewallError> {
        Ok(())
    }

    async fn cleanup_all(&self) -> Result<(), FirewallError> {
        let args = vec![
            "delete".into(),
            "table".into(),
            "inet".into(),
            self.table.clone(),
        ];
        let _ = self.nft_quiet(&args).await;
        Ok(())
    }
}

pub fn find_nft_rule_handle(output: &str, rule: &WorkerFirewallRule) -> Option<u64> {
    let ipkw = if rule.target_ip.is_ipv4() {
        "ip"
    } else {
        "ip6"
    };
    let proto = match rule.protocol {
        L4Protocol::Tcp => "tcp",
        L4Protocol::Udp => "udp",
    };
    output
        .lines()
        .find(|line| {
            line.contains(&format!("{ipkw} daddr {}", rule.target_ip))
                && line.contains(&format!("{proto} sport {}", rule.source_port))
                && line.contains(&format!("{proto} dport {}", rule.target_port))
                && line.contains("queue")
                && line.contains(&rule.qnum.to_string())
                && line.contains("# handle ")
        })
        .and_then(|line| {
            line.rsplit_once("# handle ")
                .and_then(|(_, handle)| handle.split_whitespace().next())
                .and_then(|handle| handle.parse::<u64>().ok())
        })
}

#[derive(Debug, Clone)]
pub struct IptablesFirewallManager;

impl IptablesFirewallManager {
    pub fn render_add_rule(&self, rule: &WorkerFirewallRule) -> Vec<String> {
        let chain = match rule.hook {
            FirewallHook::Output => "OUTPUT",
            FirewallHook::Postrouting => "POSTROUTING",
        };
        let proto = match rule.protocol {
            L4Protocol::Tcp => "tcp",
            L4Protocol::Udp => "udp",
        };
        vec![
            "-t".into(),
            "mangle".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            proto.into(),
            "-d".into(),
            rule.target_ip.to_string(),
            "--sport".into(),
            rule.source_port.to_string(),
            "--dport".into(),
            rule.target_port.to_string(),
            "-j".into(),
            "NFQUEUE".into(),
            "--queue-num".into(),
            rule.qnum.to_string(),
            "--queue-bypass".into(),
        ]
    }

    pub fn render_delete_rule(&self, rule: &WorkerFirewallRule) -> Vec<String> {
        let mut args = self.render_add_rule(rule);
        args[2] = "-D".into();
        args
    }

    async fn iptables(
        &self,
        rule: &WorkerFirewallRule,
        args: &[String],
    ) -> Result<(), FirewallError> {
        let binary = if rule.target_ip.is_ipv4() {
            "iptables"
        } else {
            "ip6tables"
        };
        let status = Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .status()
            .await?;
        if status.success() {
            Ok(())
        } else {
            Err(FirewallError::CommandFailed(format!(
                "{} {:?} -> {}",
                binary, args, status
            )))
        }
    }
}

#[async_trait]
impl FirewallManager for IptablesFirewallManager {
    async fn setup(&self) -> Result<(), FirewallError> {
        Ok(())
    }
    async fn install_worker_rule(&self, rule: WorkerFirewallRule) -> Result<(), FirewallError> {
        debug!(
            worker_id = rule.worker_id,
            qnum = rule.qnum,
            assigned_source_port = rule.source_port,
            target_ip = %rule.target_ip,
            target_port = rule.target_port,
            firewall_hook = ?rule.hook,
            backend = "iptables",
            "install firewall rule"
        );
        self.iptables(&rule, &self.render_add_rule(&rule)).await
    }
    async fn remove_worker_rule(&self, rule: WorkerFirewallRule) -> Result<(), FirewallError> {
        debug!(
            worker_id = rule.worker_id,
            qnum = rule.qnum,
            assigned_source_port = rule.source_port,
            target_ip = %rule.target_ip,
            target_port = rule.target_port,
            firewall_hook = ?rule.hook,
            backend = "iptables",
            "remove firewall rule"
        );
        self.iptables(&rule, &self.render_delete_rule(&rule)).await
    }
    async fn cleanup_all(&self) -> Result<(), FirewallError> {
        Ok(())
    }
}
