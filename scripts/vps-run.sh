#!/usr/bin/env bash
# Run Triagex on a real server and bring the results back, anonymized and ready to share.
#
#   ./scripts/vps-run.sh user@host                # run as that user
#   ./scripts/vps-run.sh user@host --sudo         # also run with `sudo -n` (needs passwordless sudo)
#   ./scripts/vps-run.sh user@host --raw          # do NOT anonymize (results stay private!)
#   ./scripts/vps-run.sh user@host --binary PATH --out DIR --keep
#
# It copies one binary to a temporary folder in the server's home directory, runs every
# command, copies the results back, and removes everything it created. It never changes
# anything outside that folder and its own baseline file.
set -u
cd "$(dirname "$0")/.." || exit 2

SSH="${SSH:-ssh}"; SCP="${SCP:-scp}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
TARGET=""; USE_SUDO=0; ANON=1; KEEP=0; OUT=""; BIN=""

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --sudo) USE_SUDO=1 ;;
    --raw) ANON=0 ;;
    --keep) KEEP=1 ;;
    --binary) BIN="${2:?--binary needs a path}"; shift ;;
    --out) OUT="${2:?--out needs a directory}"; shift ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown option: $1" >&2; usage ;;
    *) [ -z "$TARGET" ] && TARGET="$1" || { echo "unexpected argument: $1" >&2; usage; } ;;
  esac
  shift
done
[ -n "$TARGET" ] || usage

# ---- the binary
if [ -z "$BIN" ]; then
  for c in target/x86_64-unknown-linux-musl/release/triagex target/aarch64-unknown-linux-musl/release/triagex target/release/triagex; do
    [ -x "$c" ] && { BIN="$c"; break; }
  done
fi
[ -x "$BIN" ] || { echo "no binary found. Build one: ./scripts/build-static.sh" >&2; exit 1; }
if ldd "$BIN" 2>&1 | grep -q "=>"; then
  echo "note: $BIN is dynamically linked. It may not run on an older server; ./scripts/build-static.sh makes a static one."
fi

echo "== connecting to $TARGET"
remote_arch="$($SSH "${SSH_OPTS[@]}" "$TARGET" uname -m 2>/dev/null)" || { echo "cannot reach $TARGET over ssh (keys set up? try: ssh $TARGET)" >&2; exit 1; }
case "$(file -b "$BIN")" in
  *x86-64*) local_arch=x86_64 ;; *aarch64*|*ARM\ aarch64*) local_arch=aarch64 ;; *) local_arch="$remote_arch" ;;
esac
if [ "$remote_arch" != "$local_arch" ] && [ "$remote_arch" != "amd64" ]; then
  echo "architecture mismatch: server is $remote_arch, binary is $local_arch" >&2; exit 1
fi
echo "   server architecture: $remote_arch (binary matches)"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
[ -n "$OUT" ] || OUT="vps-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
RDIR="triagex-vps-run"

# ---- the script that runs on the server
cat > "$WORK/remote.sh" <<'REMOTE'
set -u
SUDO="$1"; ANON="$2"
cd "$HOME/triagex-vps-run" || exit 2
rm -rf out && mkdir -p out fixture
: > out/summary.tsv
X="--color never --no-banner"
[ "$ANON" = 1 ] && X="$X --anonymize"
T=./triagex

step() { # name command...
  name="$1"; shift
  s=$(date +%s.%N); "$@" > "out/$name.txt" 2>&1; rc=$?; e=$(date +%s.%N)
  printf '%s\t%s\t%s\n' "$name" "$rc" "$(awk -v a="$s" -v b="$e" 'BEGIN{printf "%.2f", b-a}')" >> out/summary.tsv
}

{
  echo "kernel:  $(uname -r)"; echo "arch:    $(uname -m)"; echo "cpus:    $(nproc 2>/dev/null)"
  . /etc/os-release 2>/dev/null && echo "os:      ${PRETTY_NAME:-unknown}"
  awk '/MemTotal/ {printf "memory:  %.0f MiB\n", $2/1024}' /proc/meminfo
  echo "user:    $( [ "$(id -u)" = 0 ] && echo root || echo non-root )"
  echo "systemd: $(command -v systemctl >/dev/null && echo yes || echo no)"
  echo "docker:  $(command -v docker >/dev/null && echo installed || echo no)"
  echo "redis:   $(command -v redis-server >/dev/null && echo installed || echo no)"
} > out/00-server.txt

step 01-version      $T --version
step 02-overview     $T $X
step 03-check-json   $T check --json $X
step 04-logs-24h     $T logs --since 24h --top 5 $X
step 05-logs-json    $T logs --since 24h --json $X
step 06-report-md    $T report --format markdown -o out/report.md --since 24h $X
step 07-logs-7d      $T logs --since 7d --top 3 $X

if [ -n "$SUDO" ]; then
  step 10-overview-sudo   $SUDO $T $X
  step 11-logs-sudo       $SUDO $T logs --since 24h --top 5 $X
fi

# Integrity on the server's own sensitive paths: baseline, then verify (should be clean).
PATHS="/etc/ssh /etc/cron.d /etc/sudoers.d /usr/local/bin"
step 20-baseline-system $SUDO $T baseline $PATHS --name vps-run-system --force $X
step 21-verify-system   $SUDO $T verify --name vps-run-system $X

# Integrity change detection on a private fixture (touches nothing outside this folder).
echo one > fixture/a.txt; echo two > fixture/b.txt
step 22-baseline-fixture $T baseline "$PWD/fixture" --name vps-run-fixture --force $X
echo changed > fixture/a.txt; rm fixture/b.txt; echo new > fixture/c.txt
step 23-verify-fixture   $T verify --name vps-run-fixture $X

# Remove the baselines this run created.
for name in vps-run-system vps-run-fixture; do
  for dir in "${XDG_DATA_HOME:-$HOME/.local/share}/triagex" /var/lib/triagex; do
    rm -f "$dir/baselines/$name.json" 2>/dev/null
    [ -n "$SUDO" ] && $SUDO rm -f "$dir/baselines/$name.json" 2>/dev/null
  done
done
exit 0
REMOTE

# ---- copy, run, collect
$SSH "${SSH_OPTS[@]}" "$TARGET" "mkdir -p $RDIR" || exit 1
$SCP -q "${SSH_OPTS[@]}" "$BIN" "$TARGET:$RDIR/triagex" || { echo "copy failed" >&2; exit 1; }
$SSH "${SSH_OPTS[@]}" "$TARGET" "chmod 755 $RDIR/triagex"
sudo_cmd=""; [ "$USE_SUDO" = 1 ] && sudo_cmd="sudo -n"
echo "== running (anonymize: $([ "$ANON" = 1 ] && echo yes || echo NO), sudo: $([ "$USE_SUDO" = 1 ] && echo yes || echo no))"
$SSH "${SSH_OPTS[@]}" "$TARGET" "bash -s -- '$sudo_cmd' '$ANON'" < "$WORK/remote.sh" || echo "(the remote script reported a problem)"
$SCP -q -r "${SSH_OPTS[@]}" "$TARGET:$RDIR/out/." "$OUT/" || { echo "could not copy results back" >&2; exit 1; }
[ "$KEEP" = 1 ] || $SSH "${SSH_OPTS[@]}" "$TARGET" "rm -rf $RDIR"

# ---- summary
echo
echo "== results in $OUT/"
printf '   %-22s %-6s %s\n' STEP EXIT SECONDS
while IFS=$'\t' read -r name rc secs; do
  case "$rc" in
    0) note="" ;; 1) note="(warnings found)" ;; 2) note="(critical findings)" ;;
    *) note="<-- ERROR, read $name.txt" ;;
  esac
  printf '   %-22s %-6s %-8s %s\n' "$name" "$rc" "$secs" "$note"
done < "$OUT/summary.tsv"
echo
skipped=$(grep -l -i "skipped" "$OUT"/0[2-4]-*.txt "$OUT"/1*.txt 2>/dev/null | wc -l | tr -d ' ')
echo "   outputs with a \"skipped\" panel: $skipped (these say what could not be read and why)"
echo "   server profile:"; sed 's/^/     /' "$OUT/00-server.txt"
if [ "$ANON" = 1 ]; then
  echo
  echo "   IP addresses, the hostname and your user name were masked. Look through the files once before sharing."
else
  echo
  echo "   --raw was used: these files contain real addresses and names. Do not publish them."
fi
