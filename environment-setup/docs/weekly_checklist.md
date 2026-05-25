# Weekly Progress Checklist

## Week 1 — Environment Setup and Device Simulation

### Tasks
- [ ] Run `./setup.sh` — all 7 containers start successfully
- [ ] Run `docker compose ps` — all services show `Up`
- [ ] Connect to SSH honeypot: `ssh root@localhost -p 2222` — see Philips device banner
- [ ] Connect to Telnet honeypot: `telnet localhost 2223`
- [ ] Visit fake web panel: `http://localhost:8080` — see IoT admin UI
- [ ] Visit threat dashboard: `http://localhost:5000` — dashboard loads
- [ ] Verify Elasticsearch: `curl http://localhost:9200` — returns cluster info
- [ ] Run `docker network inspect honeypot-project_honeypot_net` — confirm isolation

### Evidence to Capture
- Screenshot of `docker compose ps` showing all services running
- Screenshot of SSH banner showing Philips IntelliVue device identity
- Screenshot of fake web admin panel
- Screenshot of empty (baseline) threat dashboard

---

## Week 2 — Exposure and Data Capture

### Tasks
- [ ] Simulate brute-force SSH login attempts (use `tests/simulate_attacker.py`)
- [ ] Manually SSH in with a valid credential and run 5+ commands
- [ ] Submit the fake web panel login form and observe logs
- [ ] Verify cowrie.json is populated: `docker compose exec cowrie tail -20 var/log/cowrie/cowrie.json`
- [ ] Verify Elasticsearch received events: `curl http://localhost:9200/honeypot-events/_count`
- [ ] Verify dashboard shows live data (stat cards non-zero)
- [ ] Verify map shows at least one marker (if GeoIP is working)

### Evidence to Capture
- Screenshot of raw cowrie.json log entries (prettified with `| python3 -m json.tool`)
- Screenshot of Elasticsearch `_count` response
- Screenshot of dashboard with populated stat cards
- Screenshot of live event feed table

---

## Week 3 — Log Parsing and Threat Intelligence Extraction

### Tasks
- [ ] Run IoC extractor: `docker compose exec log_parser python3 /app/ioc_extractor.py`
- [ ] Copy reports: `docker cp log_parser:/app/db/ioc_report.txt ./ioc_report.txt`
- [ ] Review `ioc_report.txt` — confirm attacker IPs, commands, credentials listed
- [ ] Identify at least 3 distinct credential pairs tried by attackers
- [ ] Identify at least 3 suspicious commands (look for `wget`, `curl`, `uname -a`, `cat /etc/passwd`)
- [ ] Check for any malware drops: `docker compose exec cowrie ls var/lib/cowrie/downloads/`
- [ ] Query SQLite directly to verify GeoIP enrichment is working
- [ ] Commit `ioc_report.txt` to the repo (sanitize real IPs if needed for privacy)

### Evidence to Capture
- Full text of `ioc_report.txt`
- Screenshot of the credential spray table
- Screenshot of suspicious commands list
- Notes on any patterns observed (e.g., "Most attacks came from port 22 scanners")

---

## Week 4 — Dashboard and Geolocation Analysis

### Tasks
- [ ] Open dashboard — world map shows attack origin markers
- [ ] Verify timeline chart shows hourly attack volume
- [ ] Screenshot: top attacker countries bar chart
- [ ] Screenshot: top credentials tried
- [ ] Screenshot: top shell commands executed
- [ ] Verify at least 3 different countries represented in attack data
- [ ] Generate final IoC report and commit to `docs/final_ioc_report.txt`
- [ ] Write `docs/analysis_report.md` (500+ words summarizing findings)
- [ ] Final `git push` with all deliverables
- [ ] Record a short demo video walking through the dashboard

### Evidence to Capture
- Full-page screenshot of the threat dashboard
- Close-up screenshot of world map with markers
- Screenshot of timeline chart
- Exported `ioc_report.json` (add to repo)
- Written analysis report

---

## Final GitHub Repository Checklist

- [ ] `README.md` — complete with architecture diagram and setup instructions
- [ ] `docker-compose.yml` — all services defined
- [ ] `cowrie/` — Dockerfile + config files
- [ ] `fake_panel/` — Flask app
- [ ] `dashboard/` — Flask app + HTML template
- [ ] `scripts/parser.py` — log enrichment worker
- [ ] `scripts/ioc_extractor.py` — IoC report generator
- [ ] `tests/simulate_attacker.py` — traffic simulator
- [ ] `docs/architecture.md` — system design documentation
- [ ] `docs/final_ioc_report.txt` — threat intelligence findings
- [ ] `.gitignore` — excludes DB files, logs, malware, secrets
- [ ] At least 5 meaningful commits (one per major milestone)
- [ ] No API keys, passwords, or captured malware committed to repo
