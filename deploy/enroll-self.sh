#!/usr/bin/env bash
# One-off: enroll the droplet itself as the first monitored host, using the ops account token.
set -euo pipefail
TOK=$(awk '/agent_token/{print $2}' /root/.secure-ops)
printf 'SECURE_TOKEN=%s\nSECURE_URL=https://secure.resonator.am\n' "$TOK" > /etc/secure-agent.env
chmod 600 /etc/secure-agent.env
shred -u /root/.secure-ops
apt-get install -y -qq jq >/dev/null 2>&1 || true
install -m 755 /opt/secure/app/static/agent.sh /usr/local/bin/secure-agent
python3 - <<'P'
p='/usr/local/bin/secure-agent'; s=open(p).read().replace('__PUBLIC_URL__','https://secure.resonator.am'); open(p,'w').write(s)
P
cat > /etc/cron.d/secure-agent <<'C'
17 * * * * root . /etc/secure-agent.env && SECURE_TOKEN=$SECURE_TOKEN SECURE_URL=$SECURE_URL /usr/local/bin/secure-agent >/dev/null 2>&1
C
. /etc/secure-agent.env; export SECURE_TOKEN SECURE_URL
/usr/local/bin/secure-agent
