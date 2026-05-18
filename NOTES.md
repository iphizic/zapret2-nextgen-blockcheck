# Notes

This package extends the previous Strategy Graph architecture with asynchronous isolated workers.

Important implementation notes:

- `src/probe.rs` already separates `prepare_socket()` and `probe_with_prepared_socket()`.
- `src/worker.rs` installs firewall after bind(0) and before connect().
- `src/queue.rs` provides async qnum leasing.
- `src/firewall.rs` renders exact nft rules; handle-based delete should be added for production.
- `src/nfqws.rs` launches one nfqws2 process per active probe.
- `curl` fallback is intentionally non-critical.

Potential production hardening:

- Replace expression-based nft delete with handle-based rule deletion.
- Add signal handling and global active-resource registry.
- Add local HTTP/TLS integration tests.
- Add real Beta sampling using a beta distribution crate or custom sampler.
- Add per-target DNS resolver stage and multi-IP scheduling.
