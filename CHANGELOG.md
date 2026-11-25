# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - 2026-11-25

### Added
- `triagex` overview, `report` (text, JSON, Markdown), `check` and `about`.
- System checks: CPU load, memory and swap, disk space and inodes, failed systemd units.
- Log triage: journald and file sources, grouping with stable IDs, timelines, secret redaction.
- Docker diagnostics over the local socket (read-only): crash loops, OOM kills, health, restarts, exit codes explained.
- Redis diagnostics (`PING` and `INFO` only, no credentials): memory, evictions, persistence, replication, latency.
- nginx: config test (`nginx -t`), process count and `stub_status` (loopback only; `TRIAGEX_NGINX=off`, `TRIAGEX_NGINX_BIN`, `TRIAGEX_NGINX_STATUS_URL`). Error log is read by default and grouped with client, request and connection number removed.
- Process view: top CPU and memory processes in the overview, `check`, `report` and JSON. CPU% comes from two `/proc` readings taken around the other checks, so it adds no run time. Names only: command lines are never collected because they often contain secrets. Process names are stripped of control characters before display.
- `process.zombies` and `process.stuck` findings; the CPU-load and low-memory findings now name the busiest or largest process as evidence (never as a cause).
- File integrity: `baseline` and `verify` with BLAKE3, tamper-evident baselines, setuid and sensitive-path detection.
- Terminal UI: ASCII logo, panels, gauges, two themes, responsive from 40 to 100 columns, ASCII fallback.
- `--anonymize` to mask IPs, hostname and user name in any output.
- Finding and log-group IDs shown in the terminal, matching JSON and Markdown.
- Static musl release pipeline (x86_64, aarch64), `install.sh` with checksum verification, weekly `cargo audit`.
- `scripts/smoke.sh` (real Docker and Redis) and `scripts/vps-run.sh` (real-server run kit).

### Fixed
- Hang resistance (issue #2): `--deadline` / `TRIAGEX_DEADLINE` total-run limit with a hard watchdog (exit 124); `journalctl` and `systemctl` now run under the same deadline logic as `nginx -t`; a killed child is no longer waited on, and a grandchild holding the output pipes cannot stall the run; Docker and Redis Unix-socket connects are non-blocking with a timeout, and a Redis socket that exists but never accepts is now reported instead of shown as "not detected"; the integrity walker skips NFS/CIFS/autofs/FUSE mount points before touching them and gives up on a stalled scan (`baseline` refuses to save a partial baseline, `verify` reports the comparison as incomplete rather than listing unreached files as deleted); log files and disks on hung storage time out instead of blocking; `scripts/vps-run.sh` works in a local directory (not the home directory, which may be NFS), sends ssh keepalives, and limits every step and the whole run (`--remote-dir`, `--step-timeout`, `--total-timeout`).
- Log grouping: numbers glued to units (`2840112kB`, `250ms`) and short, letter-only or numeric request IDs no longer split groups (a 1M-line test went from 86,682 groups to 4).
- Docker: a container killed with exit 137 and a memory limit is now reported as a probable OOM kill even when Docker does not set `OOMKilled`.
- Disk finding suggests `lsof +L1` for deleted-but-open files (reported by a reader).
- Installer rejects version tags containing anything but letters, digits, `.`, `_`, `-`.

### Security
- No outbound network. Docker GET-only. Redis never sends credentials.
- Baselines are stored `0600`/`0700` and carry a digest that detects edits.
