#!/bin/sh
# Stop the lab and delete its containers, networks and volumes (the lab's database too).
set -eu
cd "$(dirname "$0")/.."
docker compose -p reconkit-lab -f compose.yaml -f lab/compose.lab.yaml down -v --remove-orphans
