# Triagex roadmap

Status of the 30-day build (Nov 1-30, 2026). Plans change; this file is the source of truth.

## Product shape

- `triagex`: one-command overview of this server
- `triagex report`: detailed investigation as text, JSON or Markdown
- `triagex check` / `logs` / `baseline` / `verify` / `about`: focused tools
- Later: `triagex watch` (background observation, local history, local dashboard)

One engine (`triagex-core`) feeds every interface. Every finding has the same shape: `id`, `severity`, `title`, `evidence`, `next_step`, `source`.

## Principles

Read-only by default. Local-first. No outbound network. Single static binary, nothing to install on the server. Show evidence, never claim a root cause. Report what could not be checked. Be honest about what is tested and what is not.

## Done

- [x] **Days 1-4** Workspace, finding model, CPU, memory, swap, disks, inodes, failed systemd units
- [x] **Day 5** Log triage: grouping, redaction, timelines
- [x] **Day 6** Merged overview and `triagex report` (text, JSON, Markdown)
- [x] **Day 7** Terminal UI: themes, gauges, responsive layout
- [x] **Day 8** UI v2 (ASCII logo, panels) and read-only Docker diagnostics
- [x] **Day 9** Redis diagnostics; finding and log-group IDs shown everywhere
- [x] **Day 10** File integrity: baseline and verify
- [x] **Day 11** Stress test (1M log lines), smoke test against real Docker and Redis
- [x] **Day 12** Static build, release pipeline, installer, dependency audit
- [x] **Day 13** `--anonymize`, VPS run kit; first real-Docker CI run found and fixed two issues (probable OOM kills, a non-deterministic Redis test)
- [x] **Day 14** README, CHANGELOG, SECURITY, this roadmap
- [x] **Day 16** nginx: config test, stub_status, error-log grouping
- [x] **Day 15** Process view: top CPU and memory, zombies, processes stuck in disk wait

## Verified vs not yet verified

| Verified | Not yet verified |
|---|---|
| unit tests, clippy, fmt | the musl build on a real target (CI is the first run) |
| real Docker and Redis in CI (smoke test) | aarch64 |
| a fully static glibc build, same smoke checks | the release workflow end to end |
| installer: success, checksum failure, hostile input | a real VPS run |
| `cargo audit`: clean | |

## Plan

### Week 3 (Nov 15-21): depth and v0.1.0
- ~~Process view in the overview (top CPU and memory processes)~~ done (Day 15)
- Nginx: config test and error-log grouping
- Config file (`triagex.toml`): ignore rules for noisy logs
- Integration test harness in CI (Docker, Redis, Nginx)
- Docs: CONTRIBUTING, issue templates, good-first-issue labels
- Performance numbers (1M lines in about 3 s, 11 MiB so far)
- **Release v0.1.0** (Day 21), after a `v0.1.0-rc1` dry run

### Week 4 (Nov 22-30): stretch, only if v0.1.0 is solid
- `triagex watch`: bounded history, status, "what changed since last run"
- Local dashboard (TypeScript, bundled into the binary), loopback only
- A second real-server run, a security review, a wrap-up

## Deferred to v0.2+

PostgreSQL, SQLite history, `.deb` and `.rpm`, signed releases, Ratatui UI, alerting.

## Not planned

AI root-cause analysis, auto-remediation, fleet management, Kubernetes, Windows or macOS, hosted dashboards, real-time filesystem monitoring.

## Honesty rules

- Unit tests are not integration tests: say which one a feature has.
- Do not claim a feature before it runs on a real machine.
- Triagex is not an EDR, SIEM, malware detector or vulnerability scanner.
