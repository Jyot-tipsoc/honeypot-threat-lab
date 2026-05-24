# 🏥 Healthcare IoT Deception Honeypot Network

A complete, production-grade **IoT honeypot system** for healthcare environments. Simulates vulnerable medical IoT devices (SSH/Telnet/Web panel), captures attacker behavior, enriches logs with GeoIP data, and visualizes everything on a real-time threat intelligence dashboard.

> **Academic / Research Project** — Built for cybersecurity internship. Run only in isolated/sandboxed environments you own and control.

---

## 📐 Architecture Overview

```
Internet / Test Network
        │
        ▼
┌─────────────────────────────────────────────────────┐
│                  HONEYPOT LAYER                      │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │   Cowrie     │    │   Fake IoT Web Panel     │   │
│  │  SSH :2222   │    │   Flask App  :8080       │   │
│  │ Telnet :2223 │    │  (unauthenticated admin) │   │
│  └──────┬───────┘    └────────────┬─────────────┘   │
└─────────┼───────────────────────-─┼─────────────────┘
          │  JSON logs              │  JSON logs
          ▼                         ▼
┌─────────────────────────────────────────────────────┐
│               DATA PIPELINE LAYER                    │
│  ┌───────────┐   ┌────────────┐   ┌──────────────┐  │
│  │ Filebeat  │──▶│Elasticsearch│   │  Log Parser  │  │
│  │(log ship) │   │  :9200     │   │ + GeoIP      │  │
│  └───────────┘   └────────────┘   │ + IoC extract│  │
│                                   └──────┬───────┘  │
└──────────────────────────────────────────┼──────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────┐
│              VISUALIZATION LAYER                     │
│  ┌──────────────────────────────────────────────┐   │
│  │   Threat Dashboard  :5000  (via Nginx :80)   │   │
│  │   • Live attack feed  • World map            │   │
│  │   • Top IPs/creds     • Timeline chart       │   │
│  │   • Malware hashes    • IoC report           │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
honeypot-project/
├── docker-compose.yml          ← Orchestrates all 7 containers
│
├── cowrie/                     ← SSH/Telnet honeypot
│   ├── Dockerfile
│   └── etc/
│       ├── cowrie.cfg          ← Device impersonation config
│       └── userdb.txt          ← Weak credentials (trap)
│
├── fake_panel/                 ← Fake IoT web admin panel
│   ├── Dockerfile
│   └── app.py                  ← Flask app, logs every click
│
├── filebeat/
│   └── filebeat.yml            ← Ships logs to Elasticsearch
│
├── dashboard/                  ← Threat intelligence dashboard
│   ├── Dockerfile
│   ├── app.py                  ← Flask API + template server
│   └── templates/
│       └── dashboard.html      ← Full interactive UI
│
├── scripts/
│   ├── Dockerfile              ← Log parser container
│   ├── parser.py               ← GeoIP enrichment + SQLite indexing
│   └── ioc_extractor.py        ← IoC report generator (Week 3)
│
├── nginx/
│   └── nginx.conf              ← Reverse proxy config
│
├── tests/
│   └── simulate_attacker.py    ← Generates fake traffic for testing
│
├── docs/
│   └── architecture.md         ← Detailed architecture notes
│
└── setup.sh                    ← One-command setup script
```

---

## 🚀 Quick Start (Step-by-Step)

### Prerequisites

| Requirement | Version | Check |
|---|---|---|
| Linux (Ubuntu 22.04 recommended) | Any | `uname -a` |
| Docker | ≥ 24.0 | `docker --version` |
| Docker Compose | ≥ 2.0 | `docker compose version` |
| RAM | ≥ 4 GB | `free -h` |
| Disk | ≥ 10 GB | `df -h` |

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/honeypot-project.git
cd honeypot-project
```

---

### Step 2 — Run the Setup Script

```bash
chmod +x setup.sh
./setup.sh
```

This script:
1. Checks Docker/Compose are installed
2. Tunes `vm.max_map_count` for Elasticsearch
3. Creates local log directories
4. Builds all Docker images
5. Starts all 7 containers
6. Waits for Elasticsearch to become healthy

---

### Step 3 — Verify Everything is Running

```bash
docker compose ps
```

You should see all services with status `Up`:

```
NAME                STATUS
cowrie_honeypot     Up (healthy)
fake_iot_panel      Up
filebeat            Up
elasticsearch       Up (healthy)
threat_dashboard    Up
log_parser          Up
nginx_proxy         Up
```

---

### Step 4 — Access the Dashboard

Open your browser:

```
http://localhost:5000     ← Threat Intelligence Dashboard
http://localhost:8080     ← Fake IoT Admin Panel (honeypot)
http://localhost:9200     ← Elasticsearch raw API
```

---

### Step 5 — Test with Simulated Traffic (Development)

If you want to populate the dashboard immediately without waiting for real attackers:

```bash
# Run the attacker simulator (targets local log file only — safe)
python3 tests/simulate_attacker.py \
  --log $(docker inspect cowrie_honeypot --format '{{range .Mounts}}{{.Destination}}{{end}}' | grep cowrie)/cowrie.json \
  --events 200
```

Or to write directly into the mounted volume:
```bash
python3 tests/simulate_attacker.py --log /tmp/cowrie_test.json --events 100
```

Refresh the dashboard — you'll see attack data appear within ~30 seconds.

---

### Step 6 — Manually Test the SSH Honeypot

```bash
# Try connecting to Cowrie (safe — it's a honeypot)
ssh root@localhost -p 2222
# Password: root   (or any from the weak credentials list)
# You'll land in a fake shell — type commands and watch the logs
```

```bash
# Watch live Cowrie logs
docker compose logs -f cowrie
```

---

### Step 7 — Generate an IoC Report (Week 3)

```bash
# Run the IoC extractor against the live database
docker compose exec log_parser python3 /app/ioc_extractor.py \
  --db /app/db/honeypot.db \
  --out /app/db

# Copy report to your local machine
docker cp log_parser:/app/db/ioc_report.txt ./ioc_report.txt
docker cp log_parser:/app/db/ioc_report.json ./ioc_report.json

cat ioc_report.txt
```

---

## 🗓️ Four-Week Engineering Roadmap

### Week 1 — Environment Setup and Device Simulation

**Goal:** Deploy and configure the honeypot to convincingly impersonate a medical IoT device.

**Tasks:**
```bash
# 1. Build and start all containers
./setup.sh

# 2. Verify Cowrie is listening
nmap -p 2222,2223 localhost

# 3. Check the fake SSH banner (looks like a Philips medical device)
nc -v localhost 2222

# 4. Verify fake web panel is serving the IoT admin UI
curl -I http://localhost:8080

# 5. View container isolation (ensure honeypot can't reach real network)
docker network inspect honeypot-project_honeypot_net
```

**Deliverable:** Cowrie returns `SSH-2.0-OpenSSH_7.4 (Philips IntelliVue IoT Gateway v3.2.1)` banner. Web panel shows realistic unauthenticated admin interface.

---

### Week 2 — Exposure and Data Capture

**Goal:** Confirm all attacker interactions are being fully logged.

**Tasks:**
```bash
# 1. Simulate brute-force SSH (from a second terminal)
for pass in root admin password 123456 toor; do
  sshpass -p "$pass" ssh -o StrictHostKeyChecking=no root@localhost -p 2222 \
    "uname -a; cat /etc/passwd" 2>/dev/null || true
done

# 2. Watch events appear in Cowrie log
docker compose exec cowrie tail -f var/log/cowrie/cowrie.json | python3 -m json.tool

# 3. Check web panel logs (every click is recorded)
curl -X POST http://localhost:8080/admin \
  -d "username=admin&password=admin123"
docker compose logs fake_panel

# 4. Verify Elasticsearch received events
curl http://localhost:9200/honeypot-events/_count
```

**Deliverable:** JSON log entries visible for every connection, login attempt, and command. Dashboard shows live data.

---

### Week 3 — Log Parsing and Threat Intelligence Extraction

**Goal:** Extract structured IoCs from raw logs.

**Tasks:**
```bash
# 1. Run the IoC extractor
docker compose exec log_parser python3 /app/ioc_extractor.py

# 2. Query attacker IPs directly from the database
docker compose exec log_parser python3 - <<'EOF'
import sqlite3, json
conn = sqlite3.connect("/app/db/honeypot.db")
rows = conn.execute("""
  SELECT src_ip, country, COUNT(*) as hits
  FROM events GROUP BY src_ip ORDER BY hits DESC LIMIT 10
""").fetchall()
for r in rows: print(r)
EOF

# 3. Check for captured malware
docker compose exec cowrie ls var/lib/cowrie/downloads/ 2>/dev/null || echo "No drops yet"

# 4. Export credential spray list
docker compose exec log_parser python3 - <<'EOF'
import sqlite3
conn = sqlite3.connect("/app/db/honeypot.db")
rows = conn.execute("""
  SELECT username, password, COUNT(*) as n
  FROM events WHERE event_type='AUTH_FAIL'
  GROUP BY username, password ORDER BY n DESC LIMIT 20
""").fetchall()
print("USERNAME           PASSWORD           ATTEMPTS")
for r in rows: print(f"{r[0]:<18} {r[1]:<18} {r[2]}")
EOF
```

**Deliverable:** `ioc_report.txt` and `ioc_report.json` with attacker IPs, malware hashes, credential pairs, suspicious commands.

---

### Week 4 — Dashboard and Geolocation Analysis

**Goal:** Visualize attack origins on a world map and categorize exploit techniques.

**Tasks:**
```bash
# 1. Open the dashboard
xdg-open http://localhost:5000   # Linux
# or open http://localhost:5000 in browser

# 2. Check geolocation is working
curl "http://localhost:5000/api/map_data" | python3 -m json.tool | head -40

# 3. Get country breakdown
curl "http://localhost:5000/api/country_stats" | python3 -m json.tool

# 4. Get timeline data
curl "http://localhost:5000/api/timeline" | python3 -m json.tool

# 5. Take screenshots of: map, timeline, top IPs, credential spray, command list
# These go in your final report

# 6. Generate final IoC report for the README
docker compose exec log_parser python3 /app/ioc_extractor.py \
  --db /app/db/honeypot.db --out /app/db
docker cp log_parser:/app/db/ioc_report.txt ./docs/final_ioc_report.txt
```

**Deliverable:** Working dashboard with world map, all charts populated, final IoC report committed to repo.

---

## 🔧 Useful Commands Reference

```bash
# ── Start / Stop ──────────────────────────────────────────────
docker compose up -d              # Start all services
docker compose down               # Stop all services
docker compose down -v            # Stop + delete ALL data (fresh start)
docker compose restart cowrie     # Restart just Cowrie

# ── Logs ─────────────────────────────────────────────────────
docker compose logs -f cowrie         # Live Cowrie SSH logs
docker compose logs -f log_parser     # GeoIP enrichment progress
docker compose logs -f dashboard      # Dashboard API logs
docker compose logs -f fake_panel     # Web panel interaction logs

# ── Database queries ──────────────────────────────────────────
# Open SQLite shell inside the parser container
docker compose exec log_parser python3 -c "
import sqlite3; conn = sqlite3.connect('/app/db/honeypot.db')
print(conn.execute('SELECT COUNT(*) FROM events').fetchone())
"

# ── Elasticsearch ─────────────────────────────────────────────
curl http://localhost:9200/_cat/indices?v    # List all indices
curl http://localhost:9200/honeypot-events/_count  # Event count
curl http://localhost:9200/honeypot-events/_search?size=1 | python3 -m json.tool

# ── Cowrie management ─────────────────────────────────────────
# View captured files/malware
docker compose exec cowrie ls var/lib/cowrie/downloads/

# ── Network isolation check ───────────────────────────────────
docker network ls
docker network inspect honeypot-project_honeypot_net
```

---

## 🔒 Security Notes

| Rule | Reason |
|------|--------|
| Run in a VM or isolated cloud instance | Prevents attackers from reaching your real system |
| Never expose port 9200 (Elasticsearch) to the internet | No auth = data leak |
| Keep port 5000 (dashboard) internal only | For analyst eyes only |
| Only expose 2222, 2223, 8080 externally | These are the honeypot trap ports |
| Use `docker compose down -v` to wipe captured malware | After analysis |
| This project is for **your own isolated network only** | Never target systems you don't own |

---

## 📊 Dashboard Features

| Panel | Description |
|-------|-------------|
| **Stat Cards** | Total events, auth failures, unique IPs, countries, commands, malware drops |
| **World Map** | Leaflet.js map with circle markers for each attacker IP (sized by event count) |
| **Attack Timeline** | 48-hour hourly event volume chart |
| **Live Feed** | Last 50 events with type badge, IP, location, credential/command |
| **Top Attacker IPs** | Bar chart ranked by total hits |
| **Top Credentials** | Most-tried username/password pairs |
| **Top Commands** | Most-executed shell commands in fake environment |
| **Malware Hashes** | SHA256 of all captured file drops + VirusTotal links |
| **Country Stats** | Attack volume by origin country |

Dashboard auto-refreshes every **15 seconds**.

---

## 📚 Technology Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| SSH/Telnet Honeypot | [Cowrie](https://github.com/cowrie/cowrie) | Purpose-built for logging brute force + shell interaction |
| Web Honeypot | Python Flask | Lightweight, easy to customize for any device profile |
| Log Shipping | Filebeat | Battle-tested log forwarder, native ES integration |
| Search & Storage | Elasticsearch | Full-text search + aggregation on attack events |
| GeoIP | ip-api.com | Free IP geolocation with ISP info, no API key needed |
| Local DB | SQLite | Zero-config, fast for dashboard queries |
| Dashboard | Flask + Chart.js + Leaflet | Pure web, no build step needed |
| Reverse Proxy | Nginx | Single entry point for analyst tools |
| Orchestration | Docker Compose | One-command deployment, strong isolation |

---

## 📄 License

MIT License — for educational and authorized security research use only.

---

## 🤝 Contributing / Extending

Ideas for extension:
- Add MQTT honeypot (port 1883) to simulate medical device messaging
- Integrate VirusTotal API for automatic malware hash lookup
- Add Slack/email alerting when a new attacker gets shell access
- Integrate with MISP for threat intelligence sharing
- Add DICOM protocol honeypot (port 11112) for PACS system simulation
