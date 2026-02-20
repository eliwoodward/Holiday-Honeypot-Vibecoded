# Holiday-Honeypot-Vibecoded

# Holiday Honeypot — Minimal Multi-Region URI Telemetry

A minimal, disposable, multi-region internet honeypot for capturing **HTTP/HTTPS URI scanning activity** and centralizing it for analysis.

## Purpose

This honeypot is intentionally scoped to answer:

- **What URIs were probed**
- **From where**
- **When**

It is designed to surface unusual scanning behavior (including rare/uncommon URI probes) without collecting credentials or interacting with attackers beyond returning `404`.

## Scope (Intentionally Trimmed)

- No auth capture
- No credential handling
- No blocking
- No alerting
- No exploitation simulation
- Just **URI telemetry** + source IP + timestamp + UA

---

## Architecture

### Honeypot Nodes (AWS, multiple regions)

Each edge node:

- Runs **nginx** on **80/tcp** and **443/tcp**
- Uses a **self-signed TLS certificate** on 443 so HTTPS scanners complete TLS
- Logs every request in JSONL:
  - timestamp
  - source IP
  - host
  - method
  - full URI
  - status
  - user-agent
- Returns **404 for all paths**
- Ships logs to central Loki via **promtail**
- Keeps **14 days** of local logs (compressed, rotated)

### Honeypot Aggregator (DigitalOcean)

Collector node runs:

- **Loki** (log storage, 90-day retention)
- **Grafana** (dashboards + drilldowns)
- **UFW firewall** (restrict Grafana and optionally Loki ingest)

---

## What You’ll See in Grafana

Dashboard: **Holiday Honeypot – Scanning Activity**

Panels:

1. **Requests per second by region**
2. **Rare URI prefixes (first 10 chars)**  
   - Prefixes with only **1–2 hits** in the last hour
   - Grouped by region
3. **Drilldown panel**
   - Filter by prefix → inspect full URIs + source IPs + user agents

This is useful for spotting uncommon or emerging probing paths.

---

## Recommended Regions

Example AWS regions (adjust as desired):

- `us-east-1` (N. Virginia)
- `us-west-1` (N. California)
- `eu-west-1` (Ireland)
- `ap-northeast-1` (Tokyo)

---

## Files

- `honeypot-aggregator-deploy.sh` — Deploy Loki + Grafana collector (DigitalOcean / Ubuntu)
- `honeypot-node-deploy.sh` — Deploy one edge honeypot node (AWS EC2 Ubuntu)

---

## Deployment Order

1. **Deploy Aggregator first** (DigitalOcean)
2. **Deploy one or more Honeypot Nodes** (AWS regions)
3. Generate test traffic and validate logs in Grafana

---

# 1) Honeypot Aggregator (DigitalOcean)

## Create Droplet

Recommended:

- **OS:** Ubuntu 22.04 LTS or 24.04 LTS
- **Size:** Basic small instance is fine to start
- **Auth:** SSH key
- **Public IPv4:** Enabled

Make note of the public IP: `DO_IP`

## Inbound Ports (Collector)

- **22/tcp** — SSH (restrict to your IP)
- **3000/tcp** — Grafana UI (restrict to your IP recommended)
- **3100/tcp** — Loki ingest (allow edge nodes)

> The deployment script configures **UFW** for you.

## Run Aggregator Script

SSH into the droplet and run:

```bash
scp honeypot-aggregator-deploy.sh root@<DO_IP>:/root/
ssh root@<DO_IP>
chmod +x /root/honeypot-aggregator-deploy.sh
sudo /root/honeypot-aggregator-deploy.sh
