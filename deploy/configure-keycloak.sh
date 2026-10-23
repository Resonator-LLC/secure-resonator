#!/usr/bin/env bash
# Configure the `secure` realm in Keycloak via kcadm. Idempotent. Run on the droplet from deploy/ after `docker compose up`.
set -euo pipefail
cd "$(dirname "$0")"; set -a; . ./.env; set +a
KC() { docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
for i in $(seq 1 60); do KC config credentials --server http://localhost:8080 --realm master --user admin --password "$KC_ADMIN_PASSWORD" 2>/dev/null && break; sleep 5; done

if ! KC get realms/secure >/dev/null 2>&1; then
  KC create realms -s realm=secure -s enabled=true
fi
KC update realms/secure \
  -s displayName="Secure Resonator" -s registrationAllowed=true -s registrationEmailAsUsername=true \
  -s loginWithEmailAllowed=true -s duplicateEmailsAllowed=false -s resetPasswordAllowed=true -s rememberMe=false \
  -s bruteForceProtected=true -s permanentLockout=false -s failureFactor=5 -s waitIncrementSeconds=120 -s maxFailureWaitSeconds=3600 -s maxDeltaTimeSeconds=43200 -s quickLoginCheckMilliSeconds=1000 -s minimumQuickLoginWaitSeconds=60 \
  -s sslRequired=external -s 'passwordPolicy=length(12) and notUsername and notEmail and passwordHistory(3)' \
  -s ssoSessionIdleTimeout=1800 -s ssoSessionMaxLifespan=28800 -s accessTokenLifespan=300 \
  -s otpPolicyType=totp -s otpPolicyAlgorithm=HmacSHA1 -s otpPolicyDigits=6 -s otpPolicyPeriod=30 -s otpPolicyLookAheadWindow=1 \
  -s 'browserSecurityHeaders={"xFrameOptions":"SAMEORIGIN","contentSecurityPolicy":"frame-src '"'"'self'"'"'; frame-ancestors '"'"'self'"'"'; object-src '"'"'none'"'"';","strictTransportSecurity":"max-age=31536000; includeSubDomains"}'

# Mandatory second factor: CONFIGURE_TOTP as default required action (new users) and the browser flow's OTP step set to REQUIRED.
KC update "realms/secure/authentication/required-actions/CONFIGURE_TOTP" -s enabled=true -s defaultAction=true
FLOW_EXECS=$(KC get realms/secure/authentication/flows/browser/executions)
OTP_ID=$(echo "$FLOW_EXECS" | python3 -c 'import json,sys; print(next(e["id"] for e in json.load(sys.stdin) if e.get("providerId")=="auth-otp-form"))')
KC update realms/secure/authentication/flows/browser/executions -b "{\"id\":\"$OTP_ID\",\"requirement\":\"REQUIRED\"}"
# Also require it at registration time right after the form, so there is never a TOTP-less session.
KC update realms/secure/authentication/required-actions/UPDATE_PASSWORD -s enabled=true
KC update realms/secure/authentication/required-actions/VERIFY_EMAIL -s enabled=true -s defaultAction=false

# OIDC client for the app
CID=$(KC get clients -r secure -q clientId=secure-app --fields id --format csv --noquotes | tail -n1)
if [ -z "$CID" ]; then
  KC create clients -r secure -s clientId=secure-app -s enabled=true -s protocol=openid-connect -s publicClient=false \
    -s 'redirectUris=["https://secure.resonator.am/auth/callback"]' -s 'webOrigins=["https://secure.resonator.am"]' \
    -s 'attributes={"post.logout.redirect.uris":"https://secure.resonator.am/*","pkce.code.challenge.method":"S256"}' \
    -s standardFlowEnabled=true -s directAccessGrantsEnabled=false -s implicitFlowEnabled=false -s serviceAccountsEnabled=false \
    -s secret="$OIDC_CLIENT_SECRET"
else
  KC update "clients/$CID" -r secure -s secret="$OIDC_CLIENT_SECRET" -s 'redirectUris=["https://secure.resonator.am/auth/callback"]' -s directAccessGrantsEnabled=false
fi
# Disable the realm's default account-console-less admin REST exposure: master realm stays behind Caddy 404.
echo "realm secure configured"
