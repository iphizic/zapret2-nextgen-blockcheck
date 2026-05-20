use crate::config::{BlobConfig, PayloadConfig, PayloadProtocolConfig};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const BUILTIN_PAYLOAD_ALIASES: [&str; 3] =
    ["fake_default_http", "fake_default_tls", "fake_default_quic"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PayloadProtocol {
    Http,
    Tls,
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadDef {
    pub protocol: PayloadProtocol,
    pub alias: String,
    pub path: Option<PathBuf>,
    pub builtin: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PayloadAliases {
    pub http: Vec<String>,
    pub tls: Vec<String>,
    pub quic: Vec<String>,
}

impl PayloadAliases {
    pub fn for_protocol_key(&self, protocol_key: &str) -> &[String] {
        match protocol_key {
            "http" => &self.http,
            "tls12" | "tls13" | "tls" => &self.tls,
            "quic" => &self.quic,
            _ => &[],
        }
    }
}

pub fn build_payload_registry(
    blobs: &BlobConfig,
    payloads: &PayloadConfig,
) -> anyhow::Result<Vec<PayloadDef>> {
    if payloads.max_per_protocol == 0 {
        anyhow::bail!("payloads.max_per_protocol must be greater than zero");
    }

    let base_dir = if blobs.auto_load {
        let base_dir = blobs.base_dir.as_ref().ok_or_else(|| {
            anyhow::anyhow!("blobs.base_dir is required when blobs.auto_load=true")
        })?;
        if !base_dir.exists() {
            anyhow::bail!("blobs.base_dir does not exist: {}", base_dir.display());
        }
        if !base_dir.is_dir() {
            anyhow::bail!("blobs.base_dir must be a directory: {}", base_dir.display());
        }
        Some(base_dir.as_path())
    } else {
        None
    };

    let mut registry = Vec::new();
    let mut aliases = BTreeSet::new();

    push_protocol_payloads(
        PayloadProtocol::Http,
        &payloads.http,
        payloads.max_per_protocol,
        base_dir,
        &mut aliases,
        &mut registry,
    )?;
    push_protocol_payloads(
        PayloadProtocol::Tls,
        &payloads.tls,
        payloads.max_per_protocol,
        base_dir,
        &mut aliases,
        &mut registry,
    )?;
    push_protocol_payloads(
        PayloadProtocol::Quic,
        &payloads.quic,
        payloads.max_per_protocol,
        base_dir,
        &mut aliases,
        &mut registry,
    )?;

    Ok(registry)
}

pub fn render_blob_args(payloads: &[PayloadDef]) -> Vec<String> {
    payloads
        .iter()
        .filter_map(|payload| {
            if payload.builtin {
                return None;
            }
            payload
                .path
                .as_ref()
                .map(|path| format!("--blob={}:@{}", payload.alias, path.display()))
        })
        .collect()
}

pub fn aliases_from_payloads(payloads: &[PayloadDef]) -> PayloadAliases {
    let mut aliases = PayloadAliases::default();
    for payload in payloads {
        let target = match payload.protocol {
            PayloadProtocol::Http => &mut aliases.http,
            PayloadProtocol::Tls => &mut aliases.tls,
            PayloadProtocol::Quic => &mut aliases.quic,
        };
        target.push(payload.alias.clone());
    }
    sort_and_dedup(&mut aliases.http);
    sort_and_dedup(&mut aliases.tls);
    sort_and_dedup(&mut aliases.quic);
    aliases
}

pub fn make_payload_alias(path: &Path) -> anyhow::Result<String> {
    let stem = path
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("payload file must have a valid UTF-8 file name"))?;

    let mut alias = String::new();
    let mut previous_underscore = false;
    for ch in stem.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            alias.push(ch);
            previous_underscore = false;
        } else if !previous_underscore {
            alias.push('_');
            previous_underscore = true;
        }
    }

    let alias = alias.trim_matches('_').to_string();
    validate_payload_alias(&alias)?;
    Ok(alias)
}

pub fn validate_payload_alias(alias: &str) -> anyhow::Result<()> {
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

fn push_protocol_payloads(
    protocol: PayloadProtocol,
    config: &PayloadProtocolConfig,
    max_per_protocol: usize,
    base_dir: Option<&Path>,
    aliases: &mut BTreeSet<String>,
    registry: &mut Vec<PayloadDef>,
) -> anyhow::Result<()> {
    let file_payload_count = config.files.len() + config.aliases.len();
    if file_payload_count > max_per_protocol {
        anyhow::bail!(
            "{protocol:?} has {file_payload_count} file payloads, but payloads.max_per_protocol is {max_per_protocol}"
        );
    }

    for alias in &config.builtin {
        validate_payload_alias(alias)?;
        insert_unique_alias(aliases, alias)?;
        registry.push(PayloadDef {
            protocol,
            alias: alias.clone(),
            path: None,
            builtin: true,
        });
    }

    let Some(base_dir) = base_dir else {
        return Ok(());
    };

    let mut file_payloads = BTreeMap::new();
    for file in &config.files {
        let alias = make_payload_alias(file)?;
        validate_file_payload_alias(&alias)?;
        let path = resolve_payload_path(base_dir, file);
        validate_payload_file(&path)?;
        file_payloads.insert(alias, path);
    }

    for (alias, file) in &config.aliases {
        validate_payload_alias(alias)?;
        validate_file_payload_alias(alias)?;
        let path = resolve_payload_path(base_dir, file);
        validate_payload_file(&path)?;
        file_payloads.insert(alias.clone(), path);
    }

    for (alias, path) in file_payloads {
        insert_unique_alias(aliases, &alias)?;
        registry.push(PayloadDef {
            protocol,
            alias,
            path: Some(path),
            builtin: false,
        });
    }

    Ok(())
}

fn resolve_payload_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn validate_payload_file(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("payload file does not exist: {}", path.display());
    }
    if !path.is_file() {
        anyhow::bail!("payload path is not a file: {}", path.display());
    }
    Ok(())
}

fn validate_file_payload_alias(alias: &str) -> anyhow::Result<()> {
    if BUILTIN_PAYLOAD_ALIASES.contains(&alias) {
        anyhow::bail!("payload alias {alias:?} conflicts with a builtin payload alias");
    }
    Ok(())
}

fn insert_unique_alias(aliases: &mut BTreeSet<String>, alias: &str) -> anyhow::Result<()> {
    if !aliases.insert(alias.to_string()) {
        anyhow::bail!("payload alias {alias:?} is duplicated");
    }
    Ok(())
}

fn sort_and_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BlobConfig, PayloadConfig, PayloadProtocolConfig};
    use std::{collections::BTreeMap, fs};

    #[test]
    fn builtin_does_not_create_blob_arg() {
        let registry = build_payload_registry(&BlobConfig::default(), &PayloadConfig::default())
            .expect("registry");

        assert_eq!(registry.len(), 3);
        assert!(render_blob_args(&registry).is_empty());
    }

    #[test]
    fn file_creates_blob_arg() {
        let (base_dir, file) = test_file("file_creates_blob_arg", "tls_fake.bin");
        let payloads = payloads_with_tls_file(file.file_name().unwrap().into());

        let registry = build_payload_registry(&auto_load_blobs(base_dir), &payloads).unwrap();
        let args = render_blob_args(&registry);

        assert_eq!(args, [format!("--blob=tls_fake:@{}", file.display())]);
    }

    #[test]
    fn config_alias_is_used() {
        let (base_dir, file) = test_file("config_alias_is_used", "clienthello.bin");
        let mut aliases = BTreeMap::new();
        aliases.insert("tls_google".to_string(), file.file_name().unwrap().into());
        let mut payloads = PayloadConfig::default();
        payloads.tls.aliases = aliases;

        let registry = build_payload_registry(&auto_load_blobs(base_dir), &payloads).unwrap();
        let args = render_blob_args(&registry);

        assert_eq!(args, [format!("--blob=tls_google:@{}", file.display())]);
    }

    #[test]
    fn file_alias_is_generated_from_name() {
        assert_eq!(
            make_payload_alias(Path::new("TLS ClientHello--WWW.Google.COM.bin")).unwrap(),
            "tls_clienthello_www_google_com"
        );
    }

    #[test]
    fn auto_load_false_ignores_files_and_does_not_check_path() {
        let mut payloads = PayloadConfig::default();
        payloads.http.files.push("missing.bin".into());

        let registry = build_payload_registry(&BlobConfig::default(), &payloads).unwrap();

        assert_eq!(registry.len(), 3);
        assert!(registry.iter().all(|payload| payload.builtin));
    }

    #[test]
    fn auto_load_true_nonexistent_file_returns_error() {
        let base_dir = test_dir("auto_load_true_nonexistent_file_returns_error");
        let payloads = payloads_with_tls_file("missing.bin".into());

        let err = build_payload_registry(&auto_load_blobs(base_dir), &payloads)
            .unwrap_err()
            .to_string();

        assert!(err.contains("payload file does not exist"));
    }

    #[test]
    fn duplicate_alias_returns_error() {
        let (base_dir, file) = test_file("duplicate_alias_returns_error", "same.bin");
        let mut aliases = BTreeMap::new();
        aliases.insert("same".to_string(), file.file_name().unwrap().into());
        let mut payloads = PayloadConfig::default();
        payloads.http.files.push(file.file_name().unwrap().into());
        payloads.tls.aliases = aliases;

        let err = build_payload_registry(&auto_load_blobs(base_dir), &payloads)
            .unwrap_err()
            .to_string();

        assert!(err.contains("duplicated"));
    }

    #[test]
    fn builtin_conflict_for_file_alias_returns_error() {
        let (base_dir, file) = test_file(
            "builtin_conflict_for_file_alias_returns_error",
            "fake_default_tls.bin",
        );
        let payloads = payloads_with_tls_file(file.file_name().unwrap().into());

        let err = build_payload_registry(&auto_load_blobs(base_dir), &payloads)
            .unwrap_err()
            .to_string();

        assert!(err.contains("conflicts with a builtin payload alias"));
    }

    #[test]
    fn max_per_protocol_counts_only_file_payloads() {
        let (base_dir, one) = test_file("max_per_protocol_counts_only_file_payloads", "one.bin");
        let two = base_dir.join("two.bin");
        fs::write(&two, [2]).unwrap();
        let mut payloads = PayloadConfig::default();
        payloads.max_per_protocol = 1;
        payloads.tls.builtin = vec![
            "fake_default_tls".to_string(),
            "custom_builtin_tls".to_string(),
        ];
        payloads.tls.files.push(one.file_name().unwrap().into());

        let registry = build_payload_registry(&auto_load_blobs(base_dir.clone()), &payloads)
            .expect("one file plus two builtins is allowed");
        assert_eq!(
            registry
                .iter()
                .filter(|payload| payload.protocol == PayloadProtocol::Tls)
                .count(),
            3
        );

        payloads.tls.files.push(two.file_name().unwrap().into());
        let err = build_payload_registry(&auto_load_blobs(base_dir), &payloads)
            .unwrap_err()
            .to_string();
        assert!(err.contains("max_per_protocol"));
    }

    #[test]
    fn aliases_from_payloads_groups_by_protocol() {
        let payloads = vec![
            PayloadDef {
                protocol: PayloadProtocol::Tls,
                alias: "tls_b".to_string(),
                path: None,
                builtin: true,
            },
            PayloadDef {
                protocol: PayloadProtocol::Http,
                alias: "http_a".to_string(),
                path: None,
                builtin: true,
            },
            PayloadDef {
                protocol: PayloadProtocol::Tls,
                alias: "tls_a".to_string(),
                path: None,
                builtin: true,
            },
            PayloadDef {
                protocol: PayloadProtocol::Quic,
                alias: "quic_a".to_string(),
                path: None,
                builtin: true,
            },
            PayloadDef {
                protocol: PayloadProtocol::Tls,
                alias: "tls_a".to_string(),
                path: None,
                builtin: true,
            },
        ];

        let aliases = aliases_from_payloads(&payloads);

        assert_eq!(aliases.http, ["http_a"]);
        assert_eq!(aliases.tls, ["tls_a", "tls_b"]);
        assert_eq!(aliases.quic, ["quic_a"]);
        assert_eq!(aliases.for_protocol_key("tls12"), aliases.tls.as_slice());
        assert_eq!(aliases.for_protocol_key("tls13"), aliases.tls.as_slice());
        assert_eq!(aliases.for_protocol_key("unknown"), &[] as &[String]);
    }

    fn payloads_with_tls_file(file: PathBuf) -> PayloadConfig {
        let mut payloads = PayloadConfig::default();
        payloads.tls.files.push(file);
        payloads
    }

    fn auto_load_blobs(base_dir: PathBuf) -> BlobConfig {
        BlobConfig {
            auto_load: true,
            base_dir: Some(base_dir),
        }
    }

    fn test_file(test_name: &str, file_name: &str) -> (PathBuf, PathBuf) {
        let dir = test_dir(test_name);
        let file = dir.join(file_name);
        fs::write(&file, [1]).unwrap();
        (dir, file)
    }

    fn test_dir(test_name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zapret_checker_payload_registry_{}_{}",
            test_name,
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[allow(dead_code)]
    fn protocol_config(
        builtin: Vec<String>,
        files: Vec<PathBuf>,
        aliases: BTreeMap<String, PathBuf>,
    ) -> PayloadProtocolConfig {
        PayloadProtocolConfig {
            builtin,
            files,
            aliases,
        }
    }
}
