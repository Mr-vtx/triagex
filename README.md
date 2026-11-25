# Triagex

**Linux server diagnostics. One static binary. Read-only. No outbound network.**

Triagex looks at a Linux server (CPU, memory, disks, services, Docker, Redis, logs, important files) and tells you what is wrong, with the **evidence** and the **next command to run**. It does not guess at root causes and it never changes your system.

```
$ triagex

 #####  ####   ###   ###    ####  #####  #   #
   #    #   #   #   #   #  #      #       # #    Linux server diagnostics
   #    ####    #   #####  # ###  ####     #     v0.1.0 · "Star Fish"
   #    #  #    #   #   #  #   #  #       # #    github.com/Mr-vtx/triagex
   #    #   #  ###  #   #   ###   #####  #   #

╭─ system ──────────────────────────────────────────────────────────────── vm ─╮
│                                                                              │
│ Ubuntu 24.04.5 LTS · kernel 6.18.44-fc-v470 · up 0m · 1 cores                │
│                                                                              │
│ LOAD       ▱▱▱▱▱▱▱▱▱▱▱▱▱▱  0.00/core  load 0.00 0.00 0.00                    │
│ MEMORY     ▰▱▱▱▱▱▱▱▱▱▱▱▱▱       5.8%  3.7 GiB free of 3.9 GiB                │
│ SWAP       ▱▱▱▱▱▱▱▱▱▱▱▱▱▱       none  no swap configured                     │
│ DISK /     ▰▰▰▰▰▰▰▰▱▱▱▱▱▱      57.3%  7.7 GiB free of 252.0 GiB, inodes 1.3% │
│                                                                              │
│ SYSTEMD    not available (see Skipped)                                       │
│ DOCKER     not detected                                                      │
│ REDIS      not detected                                                      │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
```

> **Status:** pre-release (v0.1.0 in progress). Linux only. Not an EDR, SIEM, malware detector or vulnerability scanner: it shows evidence for you to investigate.

## Install

Once v0.1.0 is released:

```sh
curl -fsSL https://raw.githubusercontent.com/Mr-vtx/triagex/main/install.sh | sh
```

The script downloads one archive for your CPU (x86_64 or aarch64), **verifies its SHA-256 checksum, and refuses to install on a mismatch**. It does not use sudo and installs to `/usr/local/bin` if writable, otherwise `~/.local/bin`. Read it first: [install.sh](install.sh).

From source (Rust 1.88 or newer):

```sh
git clone https://github.com/Mr-vtx/triagex && cd triagex
cargo build --release          # ./target/release/triagex
./scripts/build-static.sh      # a fully static musl binary, with a no-shared-libraries check
```

Servers need nothing installed: no Rust, no Node, no Docker.

## Quick start

```sh
triagex                                   # overview of this server
triagex report --format markdown -o report.md
triagex logs --since 2h                   # what is repeating in the logs?
triagex baseline /etc/ssh /etc/cron.d     # remember these files...
triagex verify                            # ...and see what changed
```

Run with `sudo` to read protected logs, `/etc/shadow`, and the Docker socket.

## Commands

| Command | What it does |
|---|---|
| `triagex` | Overview: system gauges, findings, top processes, Docker, Redis, top log groups |
| `triagex report` | Full investigation as text, JSON or Markdown (`--verify` adds file integrity) |
| `triagex check` | System checks only |
| `triagex logs` | Group repeated log messages and show when they happened |
| `triagex baseline PATH...` | Record hashes, permissions and owners |
| `triagex verify` | Compare against a baseline |
| `triagex about` | Version, codename, author, source |

Useful flags (on every command): `--json`, `--since 30m|2h|1d|1w|all`, `--anonymize`, `--theme purple|green`, `--color auto|always|never`, `--compact`, `--no-banner`, `--deadline SECS`.

**Exit codes:** `0` all clear, `1` warnings, `2` critical, `3` Triagex itself failed, `124` it was still running after its deadline (see [Hangs](#when-the-server-is-hung)). Use them in scripts and cron.

## What it looks at

| Area | Source | Needs |
|---|---|---|
| CPU, memory, swap | `/proc` | nothing |
| nginx | `nginx -v`, `nginx -t` (nginx's own checks), process count, `stub_status` on loopback only | nothing is reloaded or signalled; `-t` may create empty log files the config names; needs `sudo` to test the config |
| nginx error log | `/var/log/nginx/error.log` (or `--file`) | nothing; client IPs and request lines are dropped, so tokens in URLs never reach the output |
| Processes (top CPU and memory) | `/proc/<pid>/stat`, names only, never command lines | nothing (without `sudo`, `hidepid` mounts show only your own) |
| Disk space and inodes | `statvfs` per real filesystem | nothing |
| systemd | `systemctl --failed` | nothing |
| Docker | the local socket, **GET requests only** | access to the socket |
| Redis | `PING` and `INFO` only, **never credentials** | a reachable, password-free instance |
| Logs | journald and log files (auth.log, nginx-style, syslog) | read access |
| File integrity | BLAKE3 hashes, permissions, owners | read access |

A check that cannot run is listed under **Skipped** with the reason. It is never silently dropped.

## Findings

Every finding has the same shape: `id`, `severity`, `title`, `evidence`, `next_step`. The `id` is the same in the terminal, JSON and Markdown, so you can paste it into an issue.

| ID | Severity | Meaning |
|---|---|---|
| `cpu.load` | warn ≥1.0, crit ≥2.0 | 5-minute load per core |
| `mem.available` | warn <15%, crit <5% | available memory |
| `mem.swap` | warn ≥50%, crit ≥80% | swap in use |
| `disk.usage:<mount>` | warn ≥80%, crit ≥90% | space (also hints at deleted-but-open files) |
| `disk.inodes:<mount>` | warn ≥80%, crit ≥90% | inodes |
| `nginx.config` | crit | `nginx -t` fails |
| `nginx.dropped` | warn | accepted connections that were never handled |
| `log.nginx.*` | warn/crit | worker connections, open files, backend down or timing out, disk full, permission denied |
| `process.zombies` | warn ≥10, crit ≥100 | zombie processes a parent is not collecting |
| `process.stuck` | warn ≥3 | processes in disk wait (state D) at two readings in a row |
| `systemd.failed:<unit>` | warn | a unit is in a failed state |
| `docker.oom:<name>` | crit (flag) / warn (exit 137 + memory limit) | out-of-memory kill |
| `docker.restarting:<name>` | warn | crash loop |
| `docker.exited:<name>` | warn | exited with an error (exit code explained) |
| `docker.health:<name>` | warn | failing health check |
| `docker.restarts:<name>` | warn | running, but restarted 3+ times |
| `redis.memory` | warn ≥85%, crit ≥95% | close to `maxmemory` |
| `redis.evictions` | warn | keys are being evicted |
| `redis.fragmentation` / `redis.swapping` | warn | memory fragmentation, or Redis in swap |
| `redis.rejected` / `redis.clients` | warn | connection limit reached or nearly so |
| `redis.persistence.rdb` / `.aof` | crit | last save or AOF write failed |
| `redis.replication` | warn | replica lost its master |
| `redis.latency` | warn | `PING` ≥100 ms |
| `log.ssh.failed-passwords` | warn ≥20, crit ≥200 | password guessing |
| `log.repeat:<program>:<hash>` | warn ≥100, crit ≥1000 | one message repeated many times |
| `integrity.sensitive` | crit | a sensitive file changed (`/etc/passwd`, `sshd_config`, `authorized_keys`, ...) |
| `integrity.permissions.risky` / `integrity.new-setuid` | crit | setuid, setgid or world-write gained |
| `integrity.baseline-tampered` / `integrity.digest-mismatch` | crit | the baseline itself was edited |
| `integrity.modified` / `.added` / `.deleted` / `.type` / `.permissions` | warn | changes since the baseline |
| `integrity.unreadable` | info | paths that could not be checked |

## Logs

`triagex logs` collapses repeats: IPs, ports, numbers, hex, UUIDs, usernames, request and session IDs and numbers with units (`250ms`, `512MB`) become placeholders, so 420 failed SSH logins become one line with a count, first and last seen, and a timeline. Secrets (passwords, tokens, API keys, bearer headers, URL credentials) are redacted **before** anything is grouped or printed. A million lines (105 MB) takes about 3 seconds and 11 MiB.

## File integrity

```sh
sudo triagex baseline /etc /usr/local/bin --name web --exclude '/etc/mtab'
sudo triagex verify --name web
```

Scan-based, not real-time. Symlinks are never followed, special files are skipped, unreadable paths are reported. The baseline is stored `0600` in a `0700` directory (`/var/lib/triagex` as root, `~/.local/share/triagex` otherwise) and carries its own digest, so an edited baseline is detected. Keep the digest somewhere off the server and pass it with `verify --expect-digest`. Network and automounted filesystems (NFS, CIFS, autofs, FUSE) found *below* a path are skipped by name and reported, never entered. If a scan stops making progress, `baseline` refuses to save a partial result and `verify` says the comparison is incomplete instead of calling unreached files deleted.

## Sharing output safely

`--anonymize` masks IP addresses (`45.235.x.x`), the hostname and your user name, and keeps panels aligned. Use it for screenshots and bug reports, and still skim the output first: container names, image names and your own file paths are not masked.

## Configuration

| Variable | Effect |
|---|---|
| `TRIAGEX_THEME` | `purple` (default) or `green` |
| `TRIAGEX_REDIS_ADDR` | `host:port` or `unix:/path` for a non-default Redis |
| `DOCKER_HOST` | `unix:///path/to/docker.sock` |
| `NO_COLOR` | disable colors |
| `XDG_DATA_HOME` | where non-root baselines are stored |
| `TRIAGEX_DEADLINE` | total run limit in seconds, same as `--deadline` (`0` = none) |
| `TRIAGEX_STALL_SECS` | how long a file scan may make no progress before it is abandoned (default 15) |

### When the server is hung

Triagex is what you run when a server is unhealthy, so it is built not to hang with it. Every external call has a limit: `systemctl` and `nginx` (a killed child is never waited on), Docker and Redis socket connects (a wedged daemon cannot block them), `statvfs` on each disk, log files (open and read), and `journalctl`. A check that does not answer is listed under **Skipped** with the reason, and the rest of the run carries on.

`--deadline SECS` (default 120; 600 for `baseline` and `verify`; `0` disables) caps the whole run: checks still pending when it passes are skipped, and if something is blocked beyond the reach of any timeout, Triagex exits with code `124` five seconds later. The deadline covers gathering, not printing, so reading the output in a pager is never cut off. A thread stuck in the kernel cannot be cancelled; it is abandoned and ends when the call finally returns.

## Security model

- Read-only. The only files Triagex writes are baselines it was asked to create and reports you ask for with `-o`.
- No outbound network connections, no telemetry, no daemon.
- Docker: only `GET`. Redis: only `PING` and `INFO`, and never a password.
- Logs are redacted before use. Baselines are private and tamper-evident.
- Releases are built by GitHub Actions from a tag, and the workflow refuses to publish a binary that is not static. Checksums are published with every release.

Found a vulnerability? See [SECURITY.md](SECURITY.md) if present, or open a private advisory on GitHub.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
./scripts/smoke.sh                 # real Docker + Redis (needs docker)
./scripts/vps-run.sh user@host     # run on a real server and collect anonymized results
```

Layout: `crates/core` is the engine (collectors, rules, logs, integrity), `crates/cli` is the terminal interface. See [docs/](docs/) for the roadmap, VPS runbook and release process.

## License

MIT. See [LICENSE](LICENSE).
