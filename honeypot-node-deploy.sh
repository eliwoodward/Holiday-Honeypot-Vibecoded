#!/usr/bin/env bash
set -Eeuo pipefail

on_err() {
  local ec=$?
  echo
  echo "❌ ERROR (exit $ec) at line $1: $2"
  echo "   Tip: re-run with: sudo bash -x $0"
  exit "$ec"
}
trap 'on_err $LINENO "$BASH_COMMAND"' ERR

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] Missing required command: $1"
    exit 1
  }
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Please run as root (or via sudo)."
  exit 1
fi

echo "===================================================="
echo " Honeypot Node: nginx(80/443) -> promtail -> Loki   "
echo "===================================================="
echo

# ---- Prompts ----
read -r -p "Region tag (required, e.g., us-east-1): " REGION_TAG
REGION_TAG="${REGION_TAG:-}"
if [[ -z "${REGION_TAG}" ]]; then
  echo "[!] REGION_TAG is required."
  exit 1
fi

read -r -p "Collector Loki base URL (required, e.g., http://DO_IP:3100): " LOKI_BASE
LOKI_BASE="${LOKI_BASE:-}"
if [[ -z "${LOKI_BASE}" ]]; then
  echo "[!] LOKI_BASE is required."
  exit 1
fi
LOKI_PUSH_URL="${LOKI_BASE%/}/loki/api/v1/push"

read -r -p "Public hostname for TLS CN (optional) [holiday-honeypot]: " PUBLIC_HOSTNAME
PUBLIC_HOSTNAME="${PUBLIC_HOSTNAME:-holiday-honeypot}"

read -r -p "Edge log dir [/var/log/holiday-edge]: " EDGE_LOG_DIR
EDGE_LOG_DIR="${EDGE_LOG_DIR:-/var/log/holiday-edge}"

echo
echo "[*] Configuration:"
echo "    REGION_TAG=${REGION_TAG}"
echo "    LOKI_PUSH_URL=${LOKI_PUSH_URL}"
echo "    PUBLIC_HOSTNAME=${PUBLIC_HOSTNAME}"
echo "    EDGE_LOG_DIR=${EDGE_LOG_DIR}"
echo

# ---- OS deps ----
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y ca-certificates curl openssl nginx logrotate unzip
else
  echo "[!] This script expects Ubuntu/Debian (apt-get)."
  exit 1
fi

need_cmd curl
need_cmd openssl
need_cmd nginx

# ---- Directories ----
mkdir -p /etc/nginx/certs
mkdir -p "${EDGE_LOG_DIR}/nginx"
mkdir -p /etc/promtail /var/lib/promtail /opt/promtail
chmod 0755 "${EDGE_LOG_DIR}" || true

# ---- Self-signed cert ----
if [[ ! -f /etc/nginx/certs/cert.pem || ! -f /etc/nginx/certs/key.pem ]]; then
  echo "[*] Generating self-signed TLS certificate..."
  openssl req -x509 -newkey rsa:2048 -sha256 -days 365 \
    -nodes \
    -keyout /etc/nginx/certs/key.pem \
    -out /etc/nginx/certs/cert.pem \
    -subj "/CN=${PUBLIC_HOSTNAME}"
fi

# ---- Nginx config (log all URIs, return 404) ----
cat > /etc/nginx/nginx.conf <<'NGINX'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events { worker_connections 1024; }

http {
  log_format json_combined escape=json
    '{'
      '"ts":"$time_iso8601",'
      '"remote_addr":"$remote_addr",'
      '"x_forwarded_for":"$http_x_forwarded_for",'
      '"host":"$host",'
      '"method":"$request_method",'
      '"uri":"$request_uri",'
      '"status":$status,'
      '"bytes_sent":$bytes_sent,'
      '"request_time":$request_time,'
      '"ua":"$http_user_agent"'
    '}';

  access_log /var/log/nginx/access.json json_combined;
  error_log  /var/log/nginx/error.log warn;

  server {
    listen 80;
    server_name _;
    location / { return 404; }
  }

  server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    location / { return 404; }
  }
}
NGINX

# ---- Redirect nginx logs to chosen log dir via symlink ----
rm -f /var/log/nginx/access.json /var/log/nginx/error.log || true
ln -sf "${EDGE_LOG_DIR}/nginx/access.json" /var/log/nginx/access.json
ln -sf "${EDGE_LOG_DIR}/nginx/error.log"   /var/log/nginx/error.log

touch "${EDGE_LOG_DIR}/nginx/access.json" "${EDGE_LOG_DIR}/nginx/error.log"
chown -R www-data:adm "${EDGE_LOG_DIR}/nginx" || true
chmod 0644 "${EDGE_LOG_DIR}/nginx/"* || true

nginx -t
systemctl enable nginx >/dev/null 2>&1 || true
systemctl restart nginx

# ---- Local retention: 14 days, compressed, size-capped ----
cat > /etc/logrotate.d/holiday-edge-nginx <<ROT
${EDGE_LOG_DIR}/nginx/*.json
${EDGE_LOG_DIR}/nginx/*.log
{
  daily
  rotate 14
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
  maxsize 100M
}
ROT

# ---- Install promtail ----
PROMTAIL_VERSION="2.9.8"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) PROMTAIL_ARCH="amd64" ;;
  aarch64|arm64) PROMTAIL_ARCH="arm64" ;;
  *)
    echo "[!] Unsupported architecture: ${ARCH}"
    exit 1
    ;;
esac

cd /opt/promtail
if [[ ! -f /opt/promtail/promtail ]]; then
  echo "[*] Downloading promtail v${PROMTAIL_VERSION} (${PROMTAIL_ARCH})..."
  curl -fsSLo promtail.zip "https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail-linux-${PROMTAIL_ARCH}.zip"
  unzip -o promtail.zip
  mv -f "promtail-linux-${PROMTAIL_ARCH}" /opt/promtail/promtail
  chmod +x /opt/promtail/promtail
fi

# ---- Promtail config ----
cat > /etc/promtail/config.yml <<YAML
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /var/lib/promtail/positions.yaml

clients:
  - url: ${LOKI_PUSH_URL}

scrape_configs:
  - job_name: nginx_access
    static_configs:
      - targets: [localhost]
        labels:
          job: nginx
          region: ${REGION_TAG}
          __path__: ${EDGE_LOG_DIR}/nginx/access.json
YAML

# ---- systemd unit ----
cat > /etc/systemd/system/promtail.service <<'SERVICE'
[Unit]
Description=promtail log shipper
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/opt/promtail/promtail -config.file=/etc/promtail/config.yml
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now promtail

echo
echo "✅ Honeypot Node deployed."
echo
echo "Listening:"
echo "  - 80/tcp  HTTP  (logs all URIs, returns 404)"
echo "  - 443/tcp HTTPS (self-signed TLS, logs all URIs, returns 404)"
echo
echo "Shipping logs to:"
echo "  - ${LOKI_PUSH_URL}"
echo
echo "Local retention:"
echo "  - 14 days via logrotate (daily, compressed, maxsize 100M)"
echo
echo "Quick checks:"
echo "  systemctl status nginx --no-pager"
echo "  systemctl status promtail --no-pager"
echo "  tail -n 3 ${EDGE_LOG_DIR}/nginx/access.json"
echo "  journalctl -u promtail -n 50 --no-pager"
echo
echo "Test from another host:"
echo "  curl -v http://<edge_ip>/some/random/uri"
echo "  curl -k -v https://<edge_ip>/some/random/uri"
echo
