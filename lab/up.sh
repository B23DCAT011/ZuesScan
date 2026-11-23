#!/bin/sh
# Start the ZuesScan lab: the service (compose.yaml) + vulnerable targets on isolated
# networks (lab/compose.lab.yaml), under its own project name. On the first run, make an
# operator token and print it once.
#
#     sh lab/up.sh          then open http://127.0.0.1:8000
#     sh lab/down.sh        stop it and delete its data
set -eu
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1  # Git Bash on Windows: keep container paths as they are
compose() { docker compose -p zues-lab -f compose.yaml -f lab/compose.lab.yaml "$@"; }

[ -f lab/service.toml ] || cp lab/service.example.toml lab/service.toml
compose up -d --build
if ! grep -q '^\[\[tokens\]\]' lab/service.toml; then
  out="$(compose run --rm --no-deps web token --name lab-admin --role operator)"
  printf '\n%s\n' "$(printf '%s\n' "$out" | sed -n '/^\[\[tokens\]\]/,$p')" >> lab/service.toml
  echo
  echo "Dashboard: http://127.0.0.1:8000"
  echo "Operator token (shown once, not stored anywhere):"
  printf '%s\n' "$out" | sed -n 's/.*keep it secret): //p'
fi
echo
echo "The scheduler scans lab-dmz and lab-internal now and every 30 minutes."
echo "Follow it with: docker compose -p zues-lab logs -f worker"
