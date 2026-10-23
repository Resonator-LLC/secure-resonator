#!/usr/bin/env bash
# Run on the droplet as root from /opt/secure/deploy. Idempotent.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -f .env ]; then
  cat > .env <<E
DB_PASSWORD=$(openssl rand -hex 24)
KC_ADMIN_PASSWORD=$(openssl rand -hex 16)
SESSION_SECRET=$(openssl rand -hex 32)
OIDC_CLIENT_SECRET=$(openssl rand -hex 24)
AGENT_TOKEN_PEPPER=$(openssl rand -hex 24)
E
  chmod 600 .env
fi
install -m 0644 Caddyfile /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile >/dev/null
systemctl reload caddy || systemctl restart caddy
docker compose build --pull -q
docker compose up -d --remove-orphans
docker compose ps
