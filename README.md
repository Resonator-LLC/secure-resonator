# Secure Resonator

**secure.resonator.am** ("secure, resonator, am I?") is a service by Resonator LLC: security
advisories for exactly your stack, concrete fixes you approve, agents that apply them.

Live: https://secure.resonator.am (sign-up with mandatory TOTP second factor)

## How it works

1. **Inventory.** One of three ways:
   - collector agent: `SECURE_TOKEN=srt_... bash <(curl -fsSL https://secure.resonator.am/agent.sh)`
     reads dpkg/apk/rpm, pip, npm and running Docker images; only names and versions leave the host;
   - manual entry on the dashboard (`ecosystem name version` per line);
   - `POST /api/v1/inventory` with any scanner's output mapped to `{host, os, components:[{ecosystem,name,version,purl?}]}`.
2. **Advisory stream.** A worker continuously matches every component against consolidated
   vulnerability data (OSV.dev today, which federates distro trackers and language ecosystems;
   more sources plug into `secure/worker.py`). New findings become events and **proposals**.
3. **Approve, then apply.** A proposal is a list of steps (shell / verify / manual) with the
   fixed version. A human approves on the dashboard. Only then can an agent see it via
   `GET /api/v1/proposals?status=approved`, run it (`agent.sh --apply` asks per step), and
   report back via `POST /api/v1/proposals/{id}/result`.

## Business model

The software is MIT licensed and self-hostable without payment. Resonator LLC runs the public
instance and sells what is hard: the fast, consolidated advisory stream, and tokens for
AI-generated remediation plans (the `proposer` is pluggable), paid from a Resonator wallet via
the Resonator protocol (billing node). Agents acting on your behalf can be ours, yours, or any
Resonator peer.

## Layout

- `app/` FastAPI + Postgres + Jinja (HTMX-free, plain forms). `secure/main.py` web + API,
  `secure/worker.py` advisory matching, `secure/proposer.py` rule engine, `static/agent.sh` collector.
- `deploy/` docker compose (Postgres 16, Keycloak 26 optimized build, app, worker), Caddyfile,
  `configure-keycloak.sh` (realm `secure`: self-registration, TOTP REQUIRED in browser flow,
  brute-force lockout, 12-char password policy, PKCE S256 confidential client), `install.sh`, `sync.sh`.
- `tests/smoke_live.py` end-to-end against the live site: register with TOTP, re-login requires OTP,
  token, inventory, findings, approve, agent pulls approved work.

## Production host

DigitalOcean droplet `secure` (fra1, 2 vCPU / 4 GB), Ubuntu 24.04. ufw (22/80/443 only), fail2ban
(sshd aggressive + `caddy-auth` jail on 401/403/429 and Keycloak login failures from Caddy's JSON log),
unattended-upgrades with nightly reboot, Caddy with automatic TLS and HSTS. Keycloak admin console and
master realm are not reachable from the internet (Caddy returns 404); use `kcadm` over SSH.

## Self-host

```
git clone https://github.com/Resonator-LLC/secure-resonator && cd secure-resonator/deploy
# edit Caddyfile hostnames and docker-compose.yml KC_HOSTNAME / PUBLIC_URL / OIDC_ISSUER
sudo bash install.sh && sudo bash configure-keycloak.sh
```
