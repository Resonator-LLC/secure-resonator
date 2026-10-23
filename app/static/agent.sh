#!/usr/bin/env bash
# Secure Resonator collector agent. Reads what is installed on this host and reports it.
# Usage:  SECURE_TOKEN=srt_... bash <(curl -fsSL __PUBLIC_URL__/agent.sh)            # report once
#         SECURE_TOKEN=srt_... bash <(curl -fsSL __PUBLIC_URL__/agent.sh) --apply     # also run approved proposals (asks per step)
# Only ever sends package names and versions. Nothing else leaves the host. Source: https://github.com/Resonator-LLC/secure-resonator
set -euo pipefail
URL="${SECURE_URL:-__PUBLIC_URL__}"
: "${SECURE_TOKEN:?set SECURE_TOKEN (Settings -> Agent tokens)}"
HOST="${SECURE_HOST:-$(hostname -f 2>/dev/null || hostname)}"
OS="$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$ID $VERSION_ID}" )"
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

collect() {
  local first=1
  echo -n '{"host":"'"$(json_escape "$HOST")"'","os":"'"$(json_escape "$OS")"'","source":"agent","components":['
  emit() { [ $first = 1 ] || echo -n ','; first=0; echo -n '{"ecosystem":"'"$1"'","name":"'"$(json_escape "$2")"'","version":"'"$(json_escape "$3")"'"}'; }
  if command -v dpkg-query >/dev/null; then
    eco=Debian; grep -qi ubuntu /etc/os-release && eco=Ubuntu
    while read -r n v; do emit "$eco" "${n%%:*}" "$v"; done < <(dpkg-query -W -f='${binary:Package} ${Version}\n' 2>/dev/null)
  elif command -v apk >/dev/null; then
    while read -r line; do n="${line%-[0-9]*}"; v="${line#"$n"-}"; emit Alpine "$n" "$v"; done < <(apk info -v 2>/dev/null)
  elif command -v rpm >/dev/null; then
    while read -r n v; do emit "$(. /etc/os-release; echo "${ID^}")" "$n" "$v"; done < <(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n')
  fi
  if command -v pip3 >/dev/null; then
    while IFS='==' read -r n _ v; do [ -n "$v" ] && emit PyPI "$n" "$v"; done < <(pip3 list --format=freeze 2>/dev/null)
  fi
  if command -v npm >/dev/null; then
    while read -r n v; do emit npm "$n" "$v"; done < <(npm ls -g --depth=0 --json 2>/dev/null | sed -n 's/.*"\([^"]*\)": *{ *"version": *"\([^"]*\)".*/\1 \2/p')
  fi
  if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
    while read -r img; do [ "$img" = "<none>:<none>" ] && continue; emit Docker "${img%%:*}" "${img##*:}"; done < <(docker ps --format '{{.Image}}' | sort -u)
  fi
  echo ']}'
}

report() {
  collect | curl -fsS -X POST "$URL/api/v1/inventory" -H "Authorization: Bearer $SECURE_TOKEN" -H 'Content-Type: application/json' --data-binary @-
  echo
}

apply() {
  command -v jq >/dev/null || { echo "jq is required for --apply"; exit 1; }
  curl -fsS "$URL/api/v1/proposals?status=approved" -H "Authorization: Bearer $SECURE_TOKEN" | jq -c '.[] | select(.host=="'"$HOST"'")' | while read -r p; do
    id=$(jq -r .id <<<"$p"); echo "== Proposal $id: $(jq -r .title <<<"$p")"
    ok=true; log=""
    while read -r step; do
      kind=$(jq -r .kind <<<"$step"); run=$(jq -r '.run // empty' <<<"$step"); note=$(jq -r '.note // empty' <<<"$step")
      case $kind in
        shell|verify) echo "  [$kind] $run  ($note)"; read -r -p "  run? [y/N] " a </dev/tty; [ "$a" = y ] || { log+="skipped: $run\n"; continue; }
                      if out=$(bash -c "$run" 2>&1); then log+="ok: $run\n"; else ok=false; log+="FAILED: $run\n$out\n"; fi ;;
        manual) echo "  [manual] $note"; log+="manual: $note\n" ;;
      esac
    done < <(jq -c '.steps[]' <<<"$p")
    jq -n --argjson ok $ok --arg log "$log" '{ok:$ok, log:$log}' | curl -fsS -X POST "$URL/api/v1/proposals/$id/result" -H "Authorization: Bearer $SECURE_TOKEN" -H 'Content-Type: application/json' --data-binary @- >/dev/null
  done
  report
}

case "${1:-}" in --apply) apply ;; --print) collect ;; *) report ;; esac
