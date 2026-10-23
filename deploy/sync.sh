#!/usr/bin/env bash
# From mothership: rsync repo to the droplet and (re)install.
set -euo pipefail
IP=${1:-$(cat "$(dirname "$0")/../.droplet-ip")}
rsync -az --delete --exclude .git --exclude '.droplet-ip' --exclude 'deploy/.env' --exclude '__pycache__' "$(dirname "$0")/../" "root@$IP:/opt/secure/"
ssh "root@$IP" 'bash /opt/secure/deploy/install.sh'
