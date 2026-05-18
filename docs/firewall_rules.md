# Firewall rules

The checker uses its own table/chain and must not mutate user rules directly.

IPv4 output example:

```bash
nft add rule inet zapret_checker output \
  ip daddr <target_ip> \
  tcp sport <source_port> \
  tcp dport <target_port> \
  queue num <qnum> bypass
```

IPv6 output example:

```bash
nft add rule inet zapret_checker output \
  ip6 daddr <target_ip> \
  tcp sport <source_port> \
  tcp dport <target_port> \
  queue num <qnum> bypass
```

For LAN-forwarded traffic, configure `hook = "postrouting"`.
