#[tokio::test]
#[ignore = "requires root, nftables, and a disposable checker table"]
async fn nftables_setup_install_remove_requires_root() {}

#[tokio::test]
#[ignore = "requires root and iptables/ip6tables access"]
async fn iptables_install_remove_requires_root() {}

#[tokio::test]
#[ignore = "requires root, NFQUEUE kernel support, and nfqws2"]
async fn nfqueue_worker_isolation_requires_root() {}

#[tokio::test]
#[ignore = "requires an nfqws2 binary and process permissions"]
async fn nfqws2_process_lifecycle_requires_root() {}
