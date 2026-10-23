#!/usr/bin/env bash
# Isolated CAS Lab tunnel-client launcher. No production profile is modified.
set -euo pipefail
ROOT="$HOME/.local/state/styx-cas-lab/p0-20261018"
BIN="$HOME/.local/share/styx-cas-lab/bin/tunnel-client"
PROFILE="styx-cas-lab-p0"
for file in "$ROOT/tunnel-id.txt" "$ROOT/control-plane.key" "$ROOT/mcp-auth-header"; do
  if [[ ! -f "$file" ]]; then
    printf 'CAS_LAB_NOT_CONFIGURED: missing %s\n' "$(basename "$file")" >&2
    exit 3
  fi
  if [[ "$(stat -c %a "$file")" != "600" ]]; then
    printf 'CAS_LAB_SECRET_PERMISSIONS: %s needs mode 600\n' "$(basename "$file")" >&2
    exit 3
  fi
done
TUNNEL_ID="$(cat "$ROOT/tunnel-id.txt")"
if [[ ! "$TUNNEL_ID" =~ ^tunnel_[A-Za-z0-9_-]{8,128}$ ]]; then
  echo 'CAS_LAB_TUNNEL_ID_INVALID' >&2
  exit 3
fi
if [[ ! -x "$BIN" ]]; then echo 'CAS_LAB_CLIENT_MISSING' >&2; exit 3; fi
if ! ss -ltn | grep -q ':18895 '; then echo 'CAS_LAB_GATEWAY_NOT_LISTENING' >&2; exit 3; fi
"$BIN" init \
  --sample sample_mcp_remote_no_auth \
  --profile "$PROFILE" \
  --profile-dir "$ROOT/profiles" \
  --tunnel-id "$TUNNEL_ID" \
  --mcp-server-url "http://127.0.0.1:18895/mcp" \
  --health-listen-addr "127.0.0.1:0"
exec "$BIN" run \
  --profile "$PROFILE" \
  --profile-dir "$ROOT/profiles" \
  --control-plane.api-key "file:$ROOT/control-plane.key" \
  --mcp.extra-headers "Authorization: file:$ROOT/mcp-auth-header" \
  --mcp.discovery-extra-headers "Authorization: file:$ROOT/mcp-auth-header" \
  --health.listen-addr "127.0.0.1:0" \
  --health.url-file "$ROOT/tunnel-health.url"
