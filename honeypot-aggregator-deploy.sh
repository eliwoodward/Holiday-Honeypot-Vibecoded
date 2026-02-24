
---

## `honeypot-aggregator-deploy.sh` (DigitalOcean collector)

```bash
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

echo "==============================================="
echo " Honeypot Aggregator: Loki (90d) + Grafana     "
echo "==============================================="
echo

read -r -p "Grafana admin password (required): " -s GRAFANA_ADMIN_PW
echo
if [[ -z "${GRAFANA_ADMIN_PW}" ]]; then
  echo "[!] Grafana admin password is required."
  exit 1
fi

read -r -p "Install directory [/opt/holiday-collector]: " BASE_DIR
BASE_DIR="${BASE_DIR:-/opt/holiday-collector}"

# ---- OS deps (Ubuntu/Debian) ----
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y ca-certificates curl jq ufw docker-compose-plugin
else
  echo "[!] This script expects Ubuntu/Debian (apt-get)."
  exit 1
fi

need_cmd curl

# ---- Install Docker + compose plugin ----
if ! command -v docker >/dev/null 2>&1; then
  echo "[*] Installing Docker..."
  curl -fsSL https://get.docker.com | sh
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "[*] Installing docker compose plugin..."
  apt-get install -y docker-compose-plugin
fi

mkdir -p "${BASE_DIR}"/{provisioning/datasources,provisioning/dashboards,dashboards}
cd "${BASE_DIR}"

# ---- Loki config (single-node, filesystem, 90-day retention) ----
cat > "${BASE_DIR}/loki-config.yml" <<'YAML'
auth_enabled: false

server:
  http_listen_port: 3100

common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

limits_config:
  retention_period: 2160h  # 90 days

compactor:
  working_directory: /loki/compactor
  compaction_interval: 10m
  retention_enabled: true
  retention_delete_delay: 2h
  delete_request_store: filesystem
YAML

# ---- Grafana datasource provisioning ----
cat > "${BASE_DIR}/provisioning/datasources/loki.yml" <<'YAML'
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    isDefault: true
    editable: false
YAML

# ---- Grafana dashboard provisioning ----
cat > "${BASE_DIR}/provisioning/dashboards/dashboards.yml" <<'YAML'
apiVersion: 1
providers:
  - name: "Holiday Honeypot"
    orgId: 1
    folder: "Holiday Honeypot"
    type: file
    disableDeletion: false
    editable: true
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
YAML

# ---- Dashboard JSON ----
cat > "${BASE_DIR}/dashboards/holiday-honeypot.json" <<'JSON'
{
  "uid": "holiday-honeypot",
  "title": "Holiday Honeypot - Scanning Activity",
  "timezone": "browser",
  "schemaVersion": 39,
  "version": 1,
  "refresh": "30s",
  "tags": ["honeypot", "scanning", "nginx", "loki"],
  "templating": {
    "list": [
      {
        "name": "region",
        "type": "query",
        "datasource": "Loki",
        "refresh": 2,
        "query": "label_values({job=\"nginx\"}, region)",
        "includeAll": true,
        "multi": true,
        "current": { "text": "All", "value": "$__all" }
      },
      {
        "name": "prefix10",
        "type": "textbox",
        "label": "URI prefix (first 10 chars)",
        "current": { "text": "", "value": "" }
      }
    ]
  },
  "panels": [
    {
      "id": 1,
      "type": "timeseries",
      "title": "Requests / second by region",
      "datasource": "Loki",
      "gridPos": { "x": 0, "y": 0, "w": 24, "h": 8 },
      "targets": [
        {
          "refId": "A",
          "expr": "sum by (region) (rate({job=\"nginx\", region=~\"$region\"}[5m]))"
        }
      ]
    },
    {
      "id": 2,
      "type": "table",
      "title": "Rare URI prefixes (first 10 chars) — only 1–2 hits (last 1h)",
      "datasource": "Loki",
      "gridPos": { "x": 0, "y": 8, "w": 24, "h": 10 },
      "targets": [
        {
          "refId": "A",
          "expr": "sum by (region, prefix10) (count_over_time({job=\"nginx\", region=~\"$region\"} | regexp \"\\\\\\\"uri\\\\\\\":\\\\\\\"(?P<prefix10>.{0,10})\" [1h]))"
        }
      ],
      "transformations": [
        {
          "id": "filterByValue",
          "options": {
            "filters": [
              {
                "fieldName": "Value",
                "config": { "id": "range", "options": { "from": 1, "to": 2 } }
              }
            ],
            "type": "include",
            "match": "all"
          }
        },
        { "id": "sortBy", "options": { "sort": [ { "field": "Value", "desc": false } ] } }
      ]
    },
    {
      "id": 3,
      "type": "logs",
      "title": "Drilldown: Full URI + Source IPs for selected prefix (last 1h)",
      "datasource": "Loki",
      "gridPos": { "x": 0, "y": 18, "w": 24, "h": 12 },
      "targets": [
        {
          "refId": "A",
          "expr": "{job=\"nginx\", region=~\"$region\"} | json |~ \"\\\\\\\"uri\\\\\\\":\\\\\\\"$prefix10\" | line_format \"{{.remote_addr}}  {{.uri}}  UA={{.ua}}\""
        }
      ],
      "options": { "showTime": true, "wrapLogMessage": true }
    }
  ]
}
JSON

# ---- Docker compose ----
cat > "${BASE_DIR}/docker-compose.yml" <<EOF
services:
  loki:
    image: grafana/loki:3.0.0
    command: -config.file=/etc/loki/config.yml
    ports:
      - "3100:3100"
    volumes:
      - ./loki-config.yml:/etc/loki/config.yml:ro
      - loki-data:/loki
    restart: unless-stopped

  grafana:
    image: grafana/grafana:11.2.0
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PW}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
      - ./provisioning/datasources:/etc/grafana/provisioning/datasources:ro
      - ./provisioning/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./dashboards:/var/lib/grafana/dashboards:ro
    depends_on:
      - loki
    restart: unless-stopped

volumes:
  loki-data:
  grafana-data:
EOF

echo "[*] Starting Loki + Grafana..."
docker compose up -d

# ---- Firewall (UFW) ----
echo
echo "[*] Configuring UFW firewall..."
ufw default deny incoming
ufw default allow outgoing

# SSH
ufw allow 22/tcp

# Grafana (port 3000)
read -r -p "Your public IP/CIDR for Grafana (e.g., 1.2.3.4/32). Leave blank to allow all: " GRAFANA_IP
if [[ -n "${GRAFANA_IP}" ]]; then
  ufw allow from "${GRAFANA_IP}" to any port 3000 proto tcp
else
  ufw allow 3000/tcp
fi

# Loki ingest (port 3100)
read -r -p "Restrict Loki ingest (3100) to a CIDR? [0.0.0.0/0]: " LOKI_CIDR
LOKI_CIDR="${LOKI_CIDR:-0.0.0.0/0}"
if [[ "${LOKI_CIDR}" == "0.0.0.0/0" ]]; then
  ufw allow 3100/tcp
else
  ufw allow from "${LOKI_CIDR}" to any port 3100 proto tcp
fi

ufw --force enable
ufw status verbose || true

echo
echo "✅ Honeypot Aggregator deployed."
echo
echo "Grafana:     http://<DO_IP>:3000  (user: admin)"
echo "Loki ingest: http://<DO_IP>:3100/loki/api/v1/push"
echo
echo "Quick checks:"
echo "  cd ${BASE_DIR}"
echo "  docker compose ps"
echo "  curl -s http://localhost:3100/ready && echo"
echo
