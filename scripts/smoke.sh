#!/usr/bin/env bash
# Triagex smoke test: runs every feature against REAL things and checks the results.
#
#   ./scripts/smoke.sh                 # uses ./target/debug/triagex (builds it if missing)
#   TRIAGEX=./target/release/triagex ./scripts/smoke.sh
#   RUN=sudo ./scripts/smoke.sh        # if your user cannot use the Docker socket
#   SKIP_DOCKER=1 ./scripts/smoke.sh   # only the parts that need no containers
#
# It starts throwaway containers named tx-*, on ports 16379 and 16380 only, and removes
# them afterwards. It never touches your other containers or files.

set -u
cd "$(dirname "$0")/.." || exit 2

TRIAGEX="${TRIAGEX:-./target/debug/triagex}"
RUN="${RUN:-}"
DOCKER="${DOCKER:-docker}"
PASS=0; FAIL=0; SKIP=0
WORK="$(mktemp -d)"
export LANG="${LANG:-en_US.UTF-8}"

green() { printf '\033[32m%s\033[0m' "$1"; }
red()   { printf '\033[31m%s\033[0m' "$1"; }
ok()    { printf '  %s  %s\n' "$(green PASS)" "$*"; PASS=$((PASS+1)); }
bad()   { printf '  %s  %s\n' "$(red FAIL)" "$*"; FAIL=$((FAIL+1)); }
skip()  { printf '  SKIP  %s\n' "$*"; SKIP=$((SKIP+1)); }
section() { printf '\n== %s\n' "$*"; }

tx() { $RUN env "$@"; }   # run with extra environment variables, optionally under sudo

# has_id FILE REGEX  -> success when some finding id matches the regex fully
has_id() {
  python3 - "$1" "$2" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1]))
pat = re.compile(sys.argv[2])
sys.exit(0 if any(pat.fullmatch(f["id"]) for f in d.get("findings", [])) else 1)
PY
}
# json_get FILE EXPR -> prints a python expression evaluated on the parsed JSON `d`
json_get() {
  python3 - "$1" "$2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(eval(sys.argv[2]))
PY
}
expect_id() { # FILE REGEX LABEL
  if has_id "$1" "$2"; then ok "$3"; else bad "$3  (no finding matching $2)"; fi
}
expect_no_id() {
  if has_id "$1" "$2"; then bad "$3  (unexpected finding matching $2)"; else ok "$3"; fi
}

# When a Docker or Redis check fails, show what Triagex saw and what Docker/Redis say,
# so a failure in CI is explained by its own log.
show_context() {
  echo "  ---- context for the failures above ----"
  python3 - "$WORK/dock.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
for c in (d.get("docker") or {}).get("containers", []):
    if c["name"].startswith("tx-"):
        print(f"  triagex saw {c['name']:<14} state={c['state']:<10} exit={c['exit_code']} oom_flag={c['oom_killed']} "
              f"mem_limit={c.get('memory_limit')} restarts={c['restart_count']} health={c['health']}")
r = d.get("redis")
if r:
    pct = (100.0 * r["used_memory"] / r["max_memory"]) if r["max_memory"] else 0
    print(f"  triagex saw redis: used={r['used_memory']} max={r['max_memory']} ({pct:.1f}%) evicted={r['evicted_keys']}")
ids = sorted(f["id"] for f in d.get("findings", []) if f["id"].startswith(("docker.", "redis.")))
print("  triagex findings:", ", ".join(ids) if ids else "(none)")
PYEOF
  if [ "${ASSERT_ONLY:-0}" != 1 ]; then
    $RUN $DOCKER inspect -f '  docker says tx-oom: oom_flag={{.State.OOMKilled}} exit={{.State.ExitCode}} mem_limit={{.HostConfig.Memory}}' tx-oom 2>/dev/null
    $RUN $DOCKER exec tx-redis redis-cli info memory 2>/dev/null | tr -d '\r' | grep -E '^(used_memory|maxmemory):' | sed 's/^/  redis says: /'
  fi
}

cleanup() {
  if [ "${DOCKER_READY:-0}" = 1 ]; then
    $RUN $DOCKER rm -f tx-ok tx-crash tx-loop tx-oom tx-sick tx-redis tx-redis-auth >/dev/null 2>&1
  fi
  [ -n "${BASELINE_FILE:-}" ] && $RUN rm -f "$BASELINE_FILE" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------- 0. the binary
section "binary"
if [ ! -x "$TRIAGEX" ]; then
  echo "  building $TRIAGEX ..."
  cargo build -q -p triagex-cli || { bad "cargo build failed"; exit 1; }
fi
if "$TRIAGEX" --version >/dev/null 2>&1; then ok "$("$TRIAGEX" --version)"; else bad "binary does not run"; exit 1; fi
command -v python3 >/dev/null || { bad "python3 is needed for the JSON checks"; exit 1; }

# ---------------------------------------------------------------- 1. system
section "system checks (this machine)"
if "$TRIAGEX" check --json >"$WORK/check.json" 2>/dev/null || [ $? -le 2 ]; then
  if python3 -c "import json;json.load(open('$WORK/check.json'))" 2>/dev/null; then ok "check --json is valid JSON"; else bad "check --json is not valid JSON"; fi
fi
"$TRIAGEX" --json >"$WORK/overview.json" 2>/dev/null
if [ "$(json_get "$WORK/overview.json" "len(d['meters']) >= 3")" = True ]; then ok "overview has load, memory and disk gauges"; else bad "overview is missing gauges"; fi
if [ "$(json_get "$WORK/overview.json" "bool(d['host']['hostname'])")" = True ]; then ok "host info is filled in"; else bad "host info missing"; fi

# A real CPU burner: the process view must find it by pid and see it using most of a core.
python3 -c 'while True: pass' &
BURN_PID=$!
sleep 1
"$TRIAGEX" --json >"$WORK/proc.json" 2>/dev/null
kill "$BURN_PID" 2>/dev/null; wait "$BURN_PID" 2>/dev/null
if [ "$(json_get "$WORK/proc.json" "d['processes']['total'] > 0")" = True ]; then ok "process view reads /proc"; else bad "process view is empty"; fi
if [ "$(json_get "$WORK/proc.json" "any(e['pid'] == $BURN_PID and e['cpu_pct'] > 50 for e in d['processes']['top_cpu'])")" = True ]; then ok "a real CPU burner shows up in the top CPU list"; else bad "the CPU burner (pid $BURN_PID) was not found in top_cpu"; fi
if [ "$(json_get "$WORK/proc.json" "all(not any(ord(c) < 32 for c in e['name']) for e in d['processes']['top_mem'])")" = True ]; then ok "process names carry no control characters"; else bad "a process name has control characters"; fi

# ---------------------------------------------------------------- 2. logs
section "log triage (sample file)"
"$TRIAGEX" logs --file examples/sample.log --since all --json >"$WORK/logs.json" 2>/dev/null
if [ "$(json_get "$WORK/logs.json" "d['groups'][0]['count']")" = 420 ]; then ok "420 SSH failures collapse into one group"; else bad "SSH group count is not 420"; fi
expect_id "$WORK/logs.json" 'log\.ssh\.failed-passwords' "SSH brute-force finding"
if grep -q hunter2 "$WORK/logs.json"; then bad "a password leaked into the output"; else ok "secrets are redacted"; fi
if [ "$(json_get "$WORK/logs.json" "all(g['id'] for g in d['groups'])")" = True ]; then ok "every group has a stable id"; else bad "a group has no id"; fi

# ---------------------------------------------------------------- 3. reports
section "reports"
"$TRIAGEX" report --file examples/sample.log --since all --format markdown -o "$WORK/r.md" >/dev/null 2>&1
if head -1 "$WORK/r.md" | grep -q '^# Triagex report'; then ok "Markdown report written"; else bad "Markdown report looks wrong"; fi
"$TRIAGEX" report --file examples/sample.log --since all --format json -o "$WORK/r.json" >/dev/null 2>&1
if python3 -c "import json;json.load(open('$WORK/r.json'))" 2>/dev/null; then ok "JSON report written"; else bad "JSON report invalid"; fi

# ---------------------------------------------------------------- 4. integrity
section "file integrity"
TREE="$WORK/tree"; mkdir -p "$TREE/bin"
echo one > "$TREE/a.txt"; echo two > "$TREE/b.txt"; printf '#!/bin/sh\n' > "$TREE/bin/tool"; chmod 755 "$TREE/bin/tool"
NAME="tx-smoke-$$"
"$TRIAGEX" baseline "$TREE" --name "$NAME" --json >"$WORK/base.json" 2>"$WORK/base.err"
if [ -s "$WORK/base.json" ]; then
  BASELINE_FILE="$(json_get "$WORK/base.json" "d['path']")"
  ok "baseline created ($(json_get "$WORK/base.json" "d['files']") files)"
  if [ "$(stat -c %a "$BASELINE_FILE")" = 600 ]; then ok "baseline file is private (0600)"; else bad "baseline file is not 0600"; fi
else
  bad "baseline failed: $(cat "$WORK/base.err")"
fi
"$TRIAGEX" verify --name "$NAME" --json >"$WORK/v0.json" 2>/dev/null; rc=$?
if [ "$rc" = 0 ] && [ "$(json_get "$WORK/v0.json" "d['digest_ok']")" = True ]; then ok "unchanged tree verifies clean (exit 0)"; else bad "clean verify returned exit $rc"; fi
echo changed > "$TREE/a.txt"; echo new > "$TREE/c.txt"; rm "$TREE/b.txt"; chmod 4755 "$TREE/bin/tool"
"$TRIAGEX" verify --name "$NAME" --json >"$WORK/v1.json" 2>/dev/null; rc=$?
[ "$rc" = 2 ] && ok "changes give exit code 2" || bad "expected exit 2, got $rc"
expect_id "$WORK/v1.json" 'integrity\.modified'  "modified file detected"
expect_id "$WORK/v1.json" 'integrity\.added'     "added file detected"
expect_id "$WORK/v1.json" 'integrity\.deleted'   "deleted file detected"
expect_id "$WORK/v1.json" 'integrity\.permissions\.risky' "setuid bit flagged"
if [ -n "${BASELINE_FILE:-}" ]; then
  $RUN sed -i 's/"hash": "[0-9a-f]\{64\}"/"hash": "0000000000000000000000000000000000000000000000000000000000000000"/' "$BASELINE_FILE"
  "$TRIAGEX" verify --name "$NAME" --json >"$WORK/v2.json" 2>/dev/null
  expect_id "$WORK/v2.json" 'integrity\.baseline-tampered' "edited baseline is detected"
fi

# ---------------------------------------------------------------- 5. docker + redis
section "Docker and Redis (real containers)"
if [ "${SKIP_DOCKER:-0}" = 1 ]; then
  skip "SKIP_DOCKER=1"
elif ! $RUN $DOCKER info >/dev/null 2>&1; then
  skip "Docker is not usable here (try RUN=sudo ./scripts/smoke.sh)"
else
  DOCKER_READY=1
  if [ "${ASSERT_ONLY:-0}" != 1 ]; then
    echo "  pulling images (first run can take a minute) ..."
    for img in nginx:alpine alpine:3.20 redis:7; do $RUN $DOCKER pull -q "$img" >/dev/null 2>&1 || { bad "could not pull $img"; }; done
    $RUN $DOCKER rm -f tx-ok tx-crash tx-loop tx-oom tx-sick tx-redis tx-redis-auth >/dev/null 2>&1
    $RUN $DOCKER run -d --name tx-ok nginx:alpine >/dev/null
    $RUN $DOCKER run -d --name tx-crash alpine:3.20 sh -c 'exit 3' >/dev/null
    $RUN $DOCKER run -d --name tx-loop --restart always alpine:3.20 sh -c 'exit 1' >/dev/null
    $RUN $DOCKER run -d --name tx-oom -m 20m --memory-swap 20m alpine:3.20 tail /dev/zero >/dev/null
    $RUN $DOCKER run -d --name tx-sick --health-cmd 'exit 1' --health-interval 2s --health-retries 2 nginx:alpine >/dev/null
    $RUN $DOCKER run -d --name tx-redis -p 127.0.0.1:16379:6379 redis:7 redis-server --maxmemory 5mb --maxmemory-policy allkeys-lru >/dev/null
    $RUN $DOCKER run -d --name tx-redis-auth -p 127.0.0.1:16380:6379 redis:7 redis-server --requirepass secret >/dev/null
    echo "  waiting for the containers to misbehave ..."
    for _ in $(seq 1 30); do
      $RUN $DOCKER exec tx-redis redis-cli ping 2>/dev/null | grep -q PONG && break; sleep 1
    done
    $RUN $DOCKER exec tx-redis redis-benchmark -q -n 200000 -t set -d 200 -r 1000000 >/dev/null 2>&1
    # The benchmark's own client buffers count against the limit while it runs, so usage drops
    # once it ends. Pin the limit just above what is really stored, so the result is repeatable.
    used="$($RUN $DOCKER exec tx-redis redis-cli info memory 2>/dev/null | tr -d '\r' | awk -F: '/^used_memory:/{print $2}')"
    if [ -n "$used" ]; then
      $RUN $DOCKER exec tx-redis redis-cli config set maxmemory "$(( used * 108 / 100 ))" >/dev/null 2>&1
    fi
    for _ in $(seq 1 45); do
      running="$($RUN $DOCKER inspect -f '{{.State.Running}}' tx-oom 2>/dev/null)"
      sick="$($RUN $DOCKER inspect -f '{{.State.Health.Status}}' tx-sick 2>/dev/null)"
      [ "$running" = false ] && [ "$sick" = unhealthy ] && break; sleep 1
    done
    sleep 3
  fi

  FAIL_BEFORE=$FAIL
  tx TRIAGEX_REDIS_ADDR=127.0.0.1:16379 "$TRIAGEX" --json >"$WORK/dock.json" 2>"$WORK/dock.err"
  if [ ! -s "$WORK/dock.json" ]; then
    bad "triagex produced no output: $(head -3 "$WORK/dock.err")"
  else
    if [ "$(json_get "$WORK/dock.json" "len([c for c in (d.get('docker') or {}).get('containers', []) if c['name'].startswith('tx-')])")" -ge 5 ] 2>/dev/null; then ok "all test containers discovered"; else bad "test containers were not discovered (skipped: $(json_get "$WORK/dock.json" "d['skipped']"))"; fi
    expect_id "$WORK/dock.json" 'docker\.exited:tx-crash'  "crashed container (exit 3) flagged"
    expect_id "$WORK/dock.json" 'docker\.oom:tx-oom'       "OOM-killed container flagged (flag, or exit 137 with a limit)"
    expect_id "$WORK/dock.json" 'docker\.health:tx-sick'   "failing health check flagged"
    expect_id "$WORK/dock.json" 'docker\.(restarting|restarts):tx-loop' "crash-looping container flagged"
    expect_no_id "$WORK/dock.json" 'docker\..*:tx-ok'      "healthy container stays quiet"
    expect_id "$WORK/dock.json" 'redis\.evictions'         "Redis evictions flagged"
    expect_id "$WORK/dock.json" 'redis\.memory'            "Redis near its memory limit flagged"
    [ "$FAIL" -gt "$FAIL_BEFORE" ] && show_context
  fi
  tx TRIAGEX_REDIS_ADDR=127.0.0.1:16380 "$TRIAGEX" --json >"$WORK/auth.json" 2>/dev/null
  if [ -s "$WORK/auth.json" ] && [ "$(json_get "$WORK/auth.json" "any('requires a password' in s for s in d['skipped'])")" = True ]; then ok "password-protected Redis is reported, not bypassed"; else bad "password-protected Redis was not reported"; fi
fi

# ---------------------------------------------------------------- summary
printf '\n'
printf '%s passed, %s failed, %s skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" = 0 ] && exit 0 || exit 1
