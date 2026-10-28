#!/usr/bin/env bash
# Publish the pitb documentation site on a VPS.
#
# Requires Docker (with the compose plugin), nginx, and certbot on the host.
# The site container listens on localhost. Host nginx terminates TLS.
#
#   cp deploy/vps.env.example deploy/vps.env   # set the domain and email
#   sudo bash deploy/vps-setup.sh
#
# Re-run after git pull to publish an update. Certbot's timer renews the certificate.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ROOT}/deploy/vps.env"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

DOMAIN="${PITB_DOMAIN:-pitb.yashodhantek.com}"
EMAIL="${CERTBOT_EMAIL:-}"
PORT="${PITB_PORT:-8088}"
WEBROOT="${PITB_WEBROOT:-/var/www/certbot}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root so nginx and certbot can be configured: sudo bash deploy/vps-setup.sh" >&2
  exit 1
fi
if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "PITB_DOMAIN must be a hostname, got: ${DOMAIN}" >&2
  exit 1
fi
if [[ ! "$EMAIL" =~ .+@.+\..+ ]]; then
  echo "Set CERTBOT_EMAIL in deploy/vps.env (copy deploy/vps.env.example)." >&2
  exit 1
fi
if [[ ! "$PORT" =~ ^[0-9]+$ ]]; then
  echo "PITB_PORT must be a number, got: ${PORT}" >&2
  exit 1
fi

for cmd in docker nginx certbot curl; do
  if ! command -v "$cmd" >/dev/null; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
done
docker compose version >/dev/null

export PITB_PORT="$PORT"

echo "Building the docs container for ${DOMAIN}"
docker compose -f "${ROOT}/deploy/docker-compose.yml" build
docker compose -f "${ROOT}/deploy/docker-compose.yml" up -d

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "docs container did not answer on 127.0.0.1:${PORT}" >&2
  exit 1
fi

render() {
  sed \
    -e "s/__DOMAIN__/${DOMAIN}/g" \
    -e "s/__PORT__/${PORT}/g" \
    -e "s|__WEBROOT__|${WEBROOT}|g" \
    "$1"
}

if [[ -d /etc/nginx/sites-available && -d /etc/nginx/sites-enabled ]]; then
  SITE="/etc/nginx/sites-available/${DOMAIN}.conf"
  ENABLED="/etc/nginx/sites-enabled/${DOMAIN}.conf"
else
  SITE="/etc/nginx/conf.d/${DOMAIN}.conf"
  ENABLED=""
fi

install_site() {
  local source="$1"
  render "$source" > "$SITE"
  if [[ -n "$ENABLED" ]]; then
    ln -sfn "$SITE" "$ENABLED"
  fi
  nginx -t
  systemctl reload nginx
}

mkdir -p "$WEBROOT"
CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
if [[ ! -f "$CERT" ]]; then
  echo "Requesting a certificate for ${DOMAIN}"
  echo "The DNS A record must already point at this server."
  install_site "${ROOT}/deploy/nginx/http.conf"
  certbot certonly \
    --webroot -w "$WEBROOT" \
    -d "$DOMAIN" \
    --email "$EMAIL" \
    --agree-tos \
    --non-interactive \
    --keep-until-expiring
fi

install_site "${ROOT}/deploy/nginx/site.conf"

HOOK_DIR="/etc/letsencrypt/renewal-hooks/deploy"
mkdir -p "$HOOK_DIR"
cat > "${HOOK_DIR}/reload-nginx.sh" <<'EOF'
#!/bin/sh
systemctl reload nginx
EOF
chmod 755 "${HOOK_DIR}/reload-nginx.sh"

echo "Published https://${DOMAIN}"
