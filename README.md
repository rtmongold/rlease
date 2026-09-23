# rlease

Small DHCPv4 client in Rust (BusyBox `udhcpc`-class). Built for lean Linux images such as Northstar; works anywhere you have `ip` and raw sockets.

## Features

- DORA (Discover / Offer / Request / Ack)
- Oneshot (`-n`) or renew/rebind daemon
- Lease file + INIT-REBOOT on restart (`-l`)
- Nak handling
- ARP conflict probe + DHCP Decline
- Hostname option (`-H`, or `/etc/hostname`)
- SIGTERM / SIGINT → DHCP Release, deconfig, remove lease file
- Optional udhcpc-style `-s` hook script on `bound`

## Build

```bash
cargo build --release
# binary: target/release/rlease
```

Needs root (or `CAP_NET_BIND_SERVICE` / `CAP_NET_RAW` / `CAP_NET_ADMIN`) to bind UDP 68, configure addresses, and send ARP.

## Test

```bash
cargo test
```

Unit tests in `src/main.rs` cover message builders, mask/prefix helpers, hostname options, and lease file round-trip (no root or network required).

Integration test in `tests/help.rs` checks that `-h` prints usage and exits 2.

```bash
cargo test --test help
```

## Usage

```text
rlease -i IFACE [-n] [-q] [-s SCRIPT] [-l PATH] [-H NAME] [-t TRIES] [-T SECONDS]
```

| Flag | Meaning |
|------|---------|
| `-i` | Interface (required) |
| `-n` | Oneshot: exit after bound |
| `-q` | Quieter logs |
| `-s` | Hook script (`bound` + env like udhcpc) |
| `-l` | Lease file path |
| `-H` | Hostname to send (default: `/etc/hostname`) |
| `-t` | Discover attempts (default 8) |
| `-T` | Per-attempt timeout seconds (default 3) |

### Examples

```bash
# Northstar / boot oneshot
rlease -i eth0 -n -q

# Daemon with lease persistence
rlease -i eth0 -l /var/lib/rlease/eth0.lease -H mybox

# Apply via script instead of built-in ip
rlease -i eth0 -n -s /usr/share/udhcpc/default.script
```

Without `-n`, rlease stays running, renews at T1, rebinds at T2, and rediscovers if the lease is lost. Stop with SIGTERM/SIGINT for a clean Release.

## Northstar

The distro builds this crate from `~/forks/rlease` in `build.sh` and runs it from `config/dinit.d/scripts/network.sh` as:

```sh
mkdir -p /var/lib/rlease
/usr/bin/rlease -i "$IFACE" -n -q -l "/var/lib/rlease/${IFACE}.lease" -H "$(cat /etc/hostname 2>/dev/null)"
```

## License

MIT — see [LICENSE](LICENSE).
