# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private reporting instead: *Security* tab, then *Report a vulnerability*. Include the version (`triagex --version`), what you ran, and what you expected. You will get a reply within a few days.

## What Triagex promises

- **Read-only.** It never modifies the system it inspects. The only files it writes are baselines you ask for (`0600`, in a `0700` directory) and reports you ask for with `-o`.
- **No outbound network.** No telemetry, no update checks, no daemon.
- **Docker:** only `GET` requests over the local socket.
- **Redis:** only `PING` and `INFO`, and it never sends a password.
- **Logs:** secrets are redacted before anything is grouped, printed or saved.
- **Baselines** carry a digest, so an edited baseline is detected.
- **Releases** are built by GitHub Actions from a tag and come with SHA-256 checksums. The release workflow refuses to publish a binary that is not static.

## What it does not promise

- It is not an EDR, SIEM, malware detector or vulnerability scanner, and a clean report does not mean a server is safe.
- Checksums show a download was not corrupted. They do not prove authenticity if the repository itself is compromised. Signed releases are planned.
- `--anonymize` masks IP addresses, the hostname and your user name. It does not mask container names, image names or your own file paths. Read output before sharing it.
- Docker socket access is privileged. Anyone who can read it can already control the host; Triagex only reads.

## Supported versions

Only the latest release is supported while Triagex is pre-1.0.
