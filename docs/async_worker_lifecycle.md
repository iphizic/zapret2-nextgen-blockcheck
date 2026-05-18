# Async worker lifecycle

Each active probe owns four resources:

1. Prepared TCP socket with OS-assigned source port.
2. Unique NFQUEUE qnum lease.
3. Dedicated nfqws2 process instance.
4. Temporary exact firewall rule mapping source port to qnum.

Cleanup order:

1. Remove firewall rule.
2. Stop nfqws2.
3. Release qnum lease.
4. Drop socket.

Infrastructure failures are not strategy failures and must not update Bayesian strategy priors negatively.
