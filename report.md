# Triagex report: parrot

Generated 2026-11-06 20:27:03 UTC by triagex 0.1.0. Log window: all time.

## Host

| | |
|---|---|
| Hostname | parrot |
| OS | Parrot Security 7.4 (echo) |
| Kernel | 7.1.13+parrot7-amd64 |
| Uptime | 12m |
| CPU cores | 8 |

## Checked

- load: 2.32 / 4.26 / 3.61 (1/5/15 min) on 8 cores
- memory: 62.8% available (9.7 GiB of 15.4 GiB)
- swap: 10.6% used
- disk /: 62.2% used (17.1 GiB free of 47.8 GiB), inodes 14.6% used
- disk /home: 42.3% used (97.1 GiB free of 177.3 GiB), inodes 8.0% used
- disk /boot/efi: 0.0% used (510.8 MiB free of 511.0 MiB)
- systemd: no failed units

## Summary

1 critical, 1 warning, 0 info.

## Findings

### [CRITICAL] Many failed SSH password attempts

- **Evidence:** 420 failed password attempts between 2026-10-26 02:00:19 and 2026-10-26 05:54:05 UTC.
- **Next step:** Prefer key-only SSH (PasswordAuthentication no in /etc/ssh/sshd_config) and consider fail2ban or firewall rate limiting.
- **Source:** auth log (`log.ssh.failed-passwords`)

### [WARNING] api repeated 160 times

- **Evidence:** "error upstream timed out after <n> ms while reading response" between 2026-10-26 18:02:32 and 2026-10-26 22:54:56 UTC.
- **Next step:** Inspect recent entries with: journalctl -t api --since "-1h" --no-pager | tail -n 50
- **Source:** logs (`log.repeat:api:240c8baf`)

## Log groups

607 lines scanned from examples/sample.log; showing the top 5 of 5 groups.

| # | Count | Program | Pattern | First seen (UTC) | Last seen (UTC) |
|---|---|---|---|---|---|
| 1 | 420 | sshd | `Failed password for invalid user <user> from <ip> port <n> ssh2` | 2026-10-26 02:00:19 | 2026-10-26 05:54:05 |
| 2 | 160 | api | `error upstream timed out after <n> ms while reading response` | 2026-10-26 18:02:32 | 2026-10-26 22:54:56 |
| 3 | 1 | nginx | `connect() failed (<n>: Connection refused) while connecting to upstream, password=<redacted>` | 2026-10-26 21:05:09 | 2026-10-26 21:05:09 |
| 4 | 1 | kernel | `Out of memory: Killed process <n> (node) total-vm:2840112kB` | 2026-10-26 11:40:31 | 2026-10-26 11:40:31 |
| 5 | 1 | cron | `(root) error: could not open /var/spool/cron/crontabs` | 2026-10-26 09:14:02 | 2026-10-26 09:14:02 |

---

Triagex only reads system state. Findings are evidence to investigate, not root-cause conclusions.
