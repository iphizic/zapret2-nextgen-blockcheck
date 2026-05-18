# zapret-checker async strategy graph spec

Rust project skeleton for a fast parallel DPI strategy checker for zapret2/nfqws2.

Core architecture:

- Strategy Graph
- Transition Cost Matrix
- Bayesian Priors
- Adaptive Scoring
- TSP-like Local Ordering
- Early Pruning
- Parallel Workers
- Native Rust Probe Backend
- NFQUEUE isolation per active task
- Exact source-port based firewall routing

The main design constraint is source-port isolation:

1. Create a TCP socket.
2. Bind to `local_ip:0` and keep the socket open.
3. Read the OS-assigned ephemeral source port.
4. Allocate a unique NFQUEUE qnum.
5. Start a dedicated `nfqws2 --qnum=<qnum>` process.
6. Install a temporary firewall rule matching exact `tcp sport <assigned_source_port>` and target.
7. Connect using the same socket.
8. Run native TCP/TLS/HTTP probe.
9. Cleanup firewall, nfqws2, qnum lease, socket.

`curl` is only a debug/reference backend.

## Commands

`zapret-checker` uses subcommands. `--config` is passed after the subcommand.

```bash
zapret-checker check --config config/checker.toml --host example.org
zapret-checker baseline --config config/checker.toml --host example.org
zapret-checker cleanup --config config/checker.toml
```

### `check`

Runs the full strategy checker:

1. Resolves the target host once.
2. Runs a direct baseline probe without `nfqws2` and without firewall rules.
3. If the target is reachable, runs strategy probes in parallel.
4. Each active strategy gets its own OS-assigned source port, NFQUEUE qnum, firewall rule and `nfqws2` process.
5. Updates runtime Bayesian state after strategy results.

Examples:

```bash
zapret-checker check --config config/checker.toml --host youtube.com
zapret-checker check --config config/checker.toml --host youtube.com --workers 2
zapret-checker check --config config/checker.toml --host youtube.com --backend native
```

Options:

- `--config <FILE>`: checker config TOML/YAML.
- `--host <HOST>`: target domain used for DNS, TLS SNI and HTTP `Host`.
- `--workers <N>`: override worker count. Effective concurrency is limited by `min(workers, qnum_count)`.
- `--backend native`: normal mode. Uses native Rust TCP/TLS/HTTP probe.
- `--backend curl`: debug/reference mode only. Requires `debug.enable_curl_fallback = true`.
- `--strategies-dir <DIR>`: load `<DIR>/strategies.yaml` and `<DIR>/transition_matrix.yaml`.
- `--conf-dir <DIR>`: alias for `--strategies-dir`.
- `--bayes-state <FILE>`: load and update Bayesian runtime posteriors in a separate YAML/JSON file.
- `--nfqws-binary <FILE>`: override `[nfqws].binary` from config.
- `--nfqws-lib-dir <DIR>`: add a directory to `LD_LIBRARY_PATH` for the `nfqws2` child process. Can be passed multiple times.

Default strategy files come from `config/checker.toml`; this repo points them at:

```text
config/standart/strategies.yaml
config/standart/transition_matrix.yaml
```

On OpenWrt, make sure `nfqws2` exists and is executable. Either set it in
`config/checker.toml`:

```toml
[nfqws]
binary = "/opt/zapret2/nfqws2"
library_paths = ["/opt/zapret2/binaries/linux-arm64"]
base_args = [
  "--user=daemon",
  "--fwmark=0x40000000",
  "--lua-init=@/opt/zapret2/lua/zapret-lib.lua",
  "--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua",
  "--lua-init=@/opt/zapret2/lua/zapret-auto.lua",
]
```

Do not put `--qnum` into `base_args`. The checker allocates a unique queue number for each active probe and appends `--qnum=<allocated>` automatically.

or override it on the command line:

```bash
zapret-checker check --config config/checker.toml --host youtube.com --nfqws-binary /path/to/nfqws2
```

If `nfqws2` needs shared libraries from the zapret2 binary directory:

```bash
zapret-checker check \
  --config config/checker.toml \
  --host youtube.com \
  --nfqws-binary /opt/zapret2/binaries/linux-arm64/nfqws2 \
  --nfqws-lib-dir /opt/zapret2/binaries/linux-arm64
```

### `baseline`

Runs only a direct native probe to the target. It does **not** start `nfqws2`, does **not** install firewall rules and does **not** allocate NFQUEUE.

Use it to distinguish target/network problems from strategy failures. If baseline cannot connect or times out, a full `check` should not punish strategy Bayesian scores because the target may simply be unreachable.

Example:

```bash
zapret-checker baseline --config config/checker.toml --host youtube.com
```

### `cleanup`

Removes the checker-owned firewall table/rules. It does not touch unrelated user firewall rules.

Example:

```bash
zapret-checker cleanup --config config/checker.toml
```

## OpenWrt arm64 Build

Use an OpenWrt SDK or an OpenWrt aarch64 toolchain in `PATH`:

```bash
rustup target add aarch64-unknown-linux-musl
OPENWRT_SDK=/path/to/openwrt-sdk ./scripts/build-openwrt-arm64.sh
```

You can also point directly at the compiler:

```bash
OPENWRT_CC=/path/to/aarch64-openwrt-linux-musl-gcc ./scripts/build-openwrt-arm64.sh
```

Or let the script download the default OpenWrt 24.10.4 mediatek/filogic SDK into project-local `tmp/`:

```bash
./scripts/build-openwrt-arm64.sh
```

To override the downloaded SDK URL:

```bash
OPENWRT_SDK_URL=https://downloads.openwrt.org/.../openwrt-sdk-...tar.zst ./scripts/build-openwrt-arm64.sh
```

Artifacts are written to `dist/openwrt-arm64/`:

```text
dist/openwrt-arm64/zapret-checker
dist/openwrt-arm64/config/
```

## Status

This is an implementation-ready skeleton and Codex prompt package. Some modules intentionally contain TODOs where OS/root side effects must be implemented carefully.
