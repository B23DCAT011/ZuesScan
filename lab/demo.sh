#!/bin/sh
# The finding lifecycle on the lab, after lab/up.sh:
#   1. wait for the first scan of both networks
#   2. claim the Apache and nginx findings fixed, accept the OpenSSH one with a reason
#   3. really fix only nginx (1.20.0 -> 1.27.5), then scan again
#   4. nginx is "fixed"; Apache is a "fake fix" - claimed fixed, still there (and a webhook
#      alert, if [notify] has one). Everything is in the audit trail and on the dashboard.
set -eu
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
compose() { docker compose -p reconkit-lab -f compose.yaml -f lab/compose.lab.yaml "$@"; }
rk() { compose exec -T worker reconkit "$@"; }
DB=/data/reconkit.db

runs() { rk runs --db "$DB" 2>/dev/null | grep -c ' completed ' || true; }
wait_runs() {
  printf 'waiting for %s completed run(s)' "$1"
  i=0
  while [ "$(runs)" -lt "$1" ]; do
    i=$((i + 1)); [ "$i" -gt 120 ] && { echo " - timed out"; exit 1; }
    printf '.'; sleep 5
  done
  echo
}
id_of() { rk findings --db "$DB" --all | awk -v cve="$1" '$0 ~ cve { print $1; exit }'; }

before="$(runs)"
[ "$before" -ge 2 ] || { wait_runs 2; before=2; }
APACHE="$(id_of CVE-2021-41773)"; NGINX="$(id_of CVE-2021-23017)"; SSH="$(id_of CVE-2018-15473)"
REVIEW="$(compose exec -T worker python -c 'import datetime as d; print(d.date.today() + d.timedelta(days=90))')"

echo "== people's decisions"
rk finding "$NGINX" --db "$DB" --claim-fixed --reason "nginx upgraded to 1.27.5 (change CHG-1042)" --operator demo
rk finding "$APACHE" --db "$DB" --claim-fixed --reason "ticket closed as patched" --operator demo
rk finding "$SSH" --db "$DB" --accept --reason "DMZ only; jump host replaced next quarter" \
  --until "$REVIEW" --operator demo

echo "== only nginx is really fixed"
LAB_NGINX=1.27.5 compose up -d nginx
rk enqueue lab-internal --config /config/service.toml --operator demo
rk enqueue lab-dmz --config /config/service.toml --operator demo
wait_runs $((before + 2))

echo "== what the scans say now"
rk findings --db "$DB" --all
echo
echo "nginx: fixed (verified by the scan). Apache: FAKE FIX (claimed fixed, still there)."
echo "See them on http://127.0.0.1:8000 (Findings), with the history of each decision."
