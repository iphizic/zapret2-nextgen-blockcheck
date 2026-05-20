use crate::{config::IsolationConfig, worker::WorkerAssignment};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationMode {
    SourcePort,
    Fwmark,
}

impl IsolationMode {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "source_port" => Ok(Self::SourcePort),
            "fwmark" => Ok(Self::Fwmark),
            other => anyhow::bail!("isolation.mode must be source_port or fwmark, got {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourcePort => "source_port",
            Self::Fwmark => "fwmark",
        }
    }
}

pub fn parse_hex_mark(value: &str) -> anyhow::Result<u32> {
    let trimmed = value.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u32::from_str_radix(hex, 16).map_err(|error| anyhow::anyhow!("invalid mark {value:?}: {error}"))
}

pub fn format_hex_mark(value: u32) -> String {
    format!("0x{value:08x}")
}

pub fn worker_fwmark(mark_base: u32, worker_id: usize) -> u32 {
    mark_base.saturating_add(worker_id as u32 + 1)
}

pub fn generate_assignments(
    workers_count: usize,
    isolation: &IsolationConfig,
) -> Vec<WorkerAssignment> {
    let mode = IsolationMode::parse(&isolation.mode).expect("validated isolation.mode");
    let mark_base = parse_hex_mark(&isolation.mark_base).expect("validated isolation.mark_base");
    (0..workers_count)
        .map(|worker_id| {
            let qnum = isolation.queue_base + worker_id as u16;
            match mode {
                IsolationMode::Fwmark => WorkerAssignment {
                    worker_id,
                    qnum,
                    fwmark: Some(worker_fwmark(mark_base, worker_id)),
                    source_port: None,
                },
                IsolationMode::SourcePort => WorkerAssignment {
                    worker_id,
                    qnum,
                    fwmark: None,
                    source_port: None,
                },
            }
        })
        .collect()
}

pub fn validate_nfqws_desync_mark(base_args: &[String], desync_mark: &str) -> anyhow::Result<()> {
    let expected = parse_hex_mark(desync_mark)?;
    let mut found = false;
    for arg in base_args {
        let Some(value) = arg.strip_prefix("--fwmark=") else {
            continue;
        };
        found = true;
        let configured = parse_hex_mark(value)?;
        if configured != expected {
            anyhow::bail!(
                "nfqws.base_args --fwmark={value} does not match isolation.desync_mark={desync_mark}"
            );
        }
    }
    if !found {
        tracing::warn!(
            desync_mark,
            "nfqws.base_args has no --fwmark=; expected it to match isolation.desync_mark"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolation(mode: &str) -> IsolationConfig {
        IsolationConfig {
            mode: mode.to_string(),
            queue_base: 200,
            mark_base: "0x20000000".to_string(),
            desync_mark: "0x40000000".to_string(),
            use_nft_vmap: true,
        }
    }

    #[test]
    fn fwmark_assignment_uses_queue_base_and_mark_base() {
        let assignments = generate_assignments(3, &isolation("fwmark"));
        assert_eq!(assignments.len(), 3);
        assert_eq!(assignments[0].qnum, 200);
        assert_eq!(assignments[1].qnum, 201);
        assert_eq!(assignments[2].qnum, 202);
        assert_eq!(assignments[0].fwmark, Some(0x20000001));
        assert_eq!(assignments[1].fwmark, Some(0x20000002));
        assert_eq!(assignments[2].fwmark, Some(0x20000003));
        assert!(assignments.iter().all(|item| item.source_port.is_none()));
    }

    #[test]
    fn source_port_assignment_has_no_fwmark() {
        let assignments = generate_assignments(2, &isolation("source_port"));
        assert!(assignments.iter().all(|item| item.fwmark.is_none()));
        assert_eq!(assignments[0].qnum, 200);
    }

    #[test]
    fn config_validation_rejects_invalid_mode_and_equal_marks() {
        let mut cfg = IsolationConfig {
            mode: "bad".to_string(),
            queue_base: 200,
            mark_base: "0x20000000".to_string(),
            desync_mark: "0x40000000".to_string(),
            use_nft_vmap: true,
        };
        assert!(IsolationMode::parse(&cfg.mode).is_err());

        cfg.mode = "fwmark".to_string();
        cfg.desync_mark = cfg.mark_base.clone();
        assert!(
            parse_hex_mark(&cfg.mark_base).unwrap() == parse_hex_mark(&cfg.desync_mark).unwrap()
        );
    }

    #[test]
    fn nfqws_desync_mark_mismatch_is_rejected() {
        let err =
            validate_nfqws_desync_mark(&["--fwmark=0x1".to_string()], "0x40000000").unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }
}
