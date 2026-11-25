# Running Triagex on a real server

Unit tests and fakes only go so far. This is the checklist for the first run on a real VPS.

## The easy way

From your laptop, with SSH key access to the server:

```sh
./scripts/build-static.sh                 # once: a static binary that runs on any Linux
./scripts/vps-run.sh user@your-server --sudo
```

It copies the binary to a temporary folder on the server's local disk (`/var/tmp`, `/tmp`, `/dev/shm`, then the home directory; network storage and `noexec` mounts are skipped), runs 11 steps, copies the results back to `vps-results-<timestamp>/`, prints a summary table, and removes everything it created (including its baselines). Results are **anonymized by default**.

Options: `--sudo` (also run with `sudo -n`, needs passwordless sudo), `--raw` (no anonymizing, keep private), `--keep` (leave the folder on the server), `--binary PATH`, `--out DIR`, `--remote-dir DIR` (choose the working directory), `--step-timeout SECS` (default 900) and `--total-timeout SECS` (default 3600). ssh sends keepalives, so a dead connection is dropped in about 45 s. A step that hits its limit shows exit `124` in the summary.

## Reading the summary

| Exit | Meaning |
|---|---|
| 0 | clean |
| 1 | warnings found (normal on a real server) |
| 2 | critical findings |
| anything else | **an error in Triagex: open that step's `.txt` file** |

Then read `02-overview.txt` first. Look for:

- a **Skipped** panel: what could not be read, and why (permissions are the usual reason)
- findings you did not expect, and findings you expected but did not get
- a step slower than a few seconds (`07-logs-7d` on a busy server is the interesting one)

## What the run exercises

1. system overview, `check`, `logs`, `report` (Markdown)
2. the same with `sudo`, to see what extra access changes
3. a baseline and verify of `/etc/ssh`, `/etc/cron.d`, `/etc/sudoers.d` and `/usr/local/bin` (a clean verify is the expected result)
4. a baseline of a private fixture folder, then a change, add and delete, to prove detection on this machine

## Common problems

| Symptom | Likely cause | Fix |
|---|---|---|
| `cannot reach ... over ssh` | no key, wrong user | `ssh user@host` must work without a password prompt |
| `architecture mismatch` | x86_64 binary, ARM server | `./scripts/build-static.sh aarch64` or use the release |
| `Skipped: journalctl ... permission` | user is not in `systemd-journal` or `adm` | `--sudo`, or `sudo usermod -aG systemd-journal $USER` |
| `Skipped: docker: permission denied` | user is not in the `docker` group | `--sudo`, or add the user to `docker` |
| `redis ... requires a password` | Redis has `requirepass` | expected: Triagex never sends credentials |
| `sudo: a password is required` | `sudo -n` needs passwordless sudo | run the sudo steps by hand: `ssh -t host sudo ./triagex` |
| a step exits 3 | a Triagex bug | open the `.txt`, and file an issue with it (anonymized) |

## Before you share the results

`--anonymize` masks IPv4 and IPv6 addresses, the hostname, your user name, and `/home/<name>`. It does **not** mask container names, image names, service names, or your own file paths, and it never rewrites `root`. A hostname shorter than 3 characters is not masked. Skim every file once.

## Doing it by hand

```sh
scp target/x86_64-unknown-linux-musl/release/triagex user@host:
ssh user@host './triagex --anonymize'
ssh -t user@host 'sudo ./triagex --anonymize'
ssh user@host './triagex report --format markdown -o report.md --anonymize' && scp user@host:report.md .
```
