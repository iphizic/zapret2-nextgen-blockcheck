use std::net::IpAddr;
use zapret_checker::{
    config::IsolationConfig, firewall::*, isolation::generate_assignments, worker::WorkerAssignment,
};

#[test]
fn nft_ipv4_rule_uses_exact_sport() {
    let fw = NftablesFirewallManager {
        table: "zapret_checker".into(),
        hook: FirewallHook::Output,
        priority: "mangle".into(),
        cleanup_on_start: false,
    };
    let rule = WorkerFirewallRule {
        worker_id: 1,
        qnum: 200,
        source_port: 54321,
        target_ip: "93.184.216.34".parse::<IpAddr>().unwrap(),
        target_port: 443,
        protocol: L4Protocol::Tcp,
        hook: FirewallHook::Output,
    };
    let rendered = fw.render_add_rule(&rule).join(" ");
    assert!(rendered.contains("ip daddr 93.184.216.34"));
    assert!(rendered.contains("tcp sport 54321"));
    assert!(!rendered.contains("54321-"));
}

#[test]
fn nft_ipv6_rule_uses_ip6_daddr() {
    let fw = NftablesFirewallManager {
        table: "zapret_checker".into(),
        hook: FirewallHook::Output,
        priority: "mangle".into(),
        cleanup_on_start: false,
    };
    let rule = WorkerFirewallRule {
        worker_id: 1,
        qnum: 200,
        source_port: 54321,
        target_ip: "2606:2800:220:1:248:1893:25c8:1946"
            .parse::<IpAddr>()
            .unwrap(),
        target_port: 443,
        protocol: L4Protocol::Tcp,
        hook: FirewallHook::Output,
    };
    let rendered = fw.render_add_rule(&rule).join(" ");
    assert!(rendered.contains("ip6 daddr"));
    assert!(rendered.contains("tcp sport 54321"));
}

#[test]
fn iptables_rule_uses_exact_sport_and_queue() {
    let fw = IptablesFirewallManager;
    let rule = WorkerFirewallRule {
        worker_id: 1,
        qnum: 201,
        source_port: 54322,
        target_ip: "93.184.216.34".parse::<IpAddr>().unwrap(),
        target_port: 443,
        protocol: L4Protocol::Tcp,
        hook: FirewallHook::Output,
    };
    let rendered = fw.render_add_rule(&rule).join(" ");
    assert!(rendered.contains("--sport 54322"));
    assert!(rendered.contains("--queue-num 201"));
    assert!(!rendered.contains("54322:"));
}

#[test]
fn nft_rule_handle_is_extracted_for_exact_rule() {
    let rule = WorkerFirewallRule {
        worker_id: 1,
        qnum: 201,
        source_port: 54322,
        target_ip: "93.184.216.34".parse::<IpAddr>().unwrap(),
        target_port: 443,
        protocol: L4Protocol::Tcp,
        hook: FirewallHook::Output,
    };
    let output = r#"
table inet zapret_checker {
	chain output {
		type filter hook output priority mangle; policy accept;
		ip daddr 93.184.216.34 tcp sport 54322 tcp dport 443 queue flags bypass to 201 # handle 17
	}
}
"#;
    assert_eq!(find_nft_rule_handle(output, &rule), Some(17));
}

#[test]
fn nft_vmap_setup_contains_meta_and_ct_mark_maps() {
    let assignments = generate_assignments(
        2,
        &IsolationConfig {
            mode: "fwmark".to_string(),
            queue_base: 200,
            mark_base: "0x20000000".to_string(),
            desync_mark: "0x40000000".to_string(),
            use_nft_vmap: true,
        },
    );
    let fw = NftablesVmapFirewallManager {
        table: "zapret_checker".into(),
        hook: FirewallHook::Output,
        priority: "mangle".into(),
        cleanup_on_start: false,
        desync_mark: 0x40000000,
        assignments,
    };
    let script = fw.render_setup_script();
    assert!(script.contains("meta mark vmap @meta_mark_queue"));
    assert!(script.contains("ct mark vmap @ct_mark_queue"));
    assert!(script.contains("queue num 200 bypass"));
    assert!(script.contains("queue num 201 bypass"));
    assert!(script.contains("0x40000000 notrack"));
}

#[test]
fn source_port_assignments_have_no_fwmark() {
    let assignments = generate_assignments(
        2,
        &IsolationConfig {
            mode: "source_port".to_string(),
            queue_base: 200,
            mark_base: "0x20000000".to_string(),
            desync_mark: "0x40000000".to_string(),
            use_nft_vmap: false,
        },
    );
    assert!(assignments
        .iter()
        .all(|item: &WorkerAssignment| item.fwmark.is_none()));
}
