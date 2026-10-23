#!/usr/bin/env bash
# Enroll a host: download the collector to /usr/local/bin, report once, install hourly cron. Run as root.
# Usage: SECURE_TOKEN=srt_... bash enroll-host.sh
set -euo pipefail
: "${SECURE_TOKEN:?}"
URL=${SECURE_URL:-https://secure.resonator.am}
command -v jq >/dev/null || { apt-get install -y -qq jq >/dev/null 2>&1 || apk add -q jq || true; }
curl -fsSL "$URL/agent.sh" -o /usr/local/bin/secure-agent
chmod 755 /usr/local/bin/secure-agent
install -m 600 /dev/null /etc/secure-agent.env
echo "SECURE_TOKEN=$SECURE_TOKEN" > /etc/secure-agent.env
echo "SECURE_URL=$URL" >> /etc/secure-agent.env
cat > /etc/cron.d/secure-agent <<'C'
17 * * * * root . /etc/secure-agent.env && SECURE_TOKEN=$SECURE_TOKEN SECURE_URL=$SECURE_URL /usr/local/bin/secure-agent >/dev/null 2>&1
C
. /etc/secure-agent.env; SECURE_TOKEN=$SECURE_TOKEN SECURE_URL=$SECURE_URL /usr/local/bin/secure-agent
