#!/usr/bin/env python3
"""
Log Parser & GeoIP Enrichment Worker
=====================================
Reads Cowrie JSON logs, enriches each event with IP geolocation data,
extracts Indicators of Compromise (IoCs), and indexes everything into
Elasticsearch for dashboard consumption.

Run continuously: checks for new log lines every PARSE_INTERVAL seconds.
"""

import json
import os
import re
import time
import hashlib
import sqlite3
import logging
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Configuration ─────────────────────────────────────────────────
ES_HOST        = os.getenv("ES_HOST", "http://elasticsearch:9200")
LOG_PATH       = os.getenv("LOG_PATH", "/cowrie_logs/cowrie.json")
DB_PATH        = os.getenv("DB_PATH", "/app/db/honeypot.db")
PARSE_INTERVAL = int(os.getenv("PARSE_INTERVAL", "30"))
GEOIP_API      = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PARSER] %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

# ── Database setup ────────────────────────────────────────────────
def init_db(db_path: str) -> sqlite3.Connection:
    """Initialize SQLite database for fast dashboard queries."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            event_id    TEXT UNIQUE,
            event_type  TEXT,
            src_ip      TEXT,
            username    TEXT,
            password    TEXT,
            command     TEXT,
            file_hash   TEXT,
            country     TEXT,
            country_code TEXT,
            city        TEXT,
            lat         REAL,
            lon         REAL,
            isp         TEXT,
            raw         TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip          TEXT PRIMARY KEY,
            geo_data    TEXT,
            cached_at   TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attacker_sessions (
            session_id  TEXT PRIMARY KEY,
            src_ip      TEXT,
            start_time  TEXT,
            end_time    TEXT,
            commands    INTEGER DEFAULT 0,
            login_ok    INTEGER DEFAULT 0,
            files_dropped INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    return conn


# ── GeoIP lookup ──────────────────────────────────────────────────
def geoip_lookup(ip: str, conn: sqlite3.Connection) -> dict:
    """Lookup IP geolocation; cache results to avoid rate limiting."""
    # Check cache first (24 h TTL)
    row = conn.execute(
        "SELECT geo_data, cached_at FROM ip_cache WHERE ip=?", (ip,)
    ).fetchone()

    if row:
        cached_at = datetime.fromisoformat(row[1])
        age_hours = (datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)).seconds / 3600
        if age_hours < 24:
            return json.loads(row[0])

    # Private / internal IPs — don't geolocate
    private_ranges = ["127.", "10.", "172.", "192.168.", "::1"]
    if any(ip.startswith(r) for r in private_ranges):
        geo = {"country": "Internal", "countryCode": "INT", "city": "LAN",
               "lat": 0, "lon": 0, "isp": "Internal Network"}
        conn.execute(
            "INSERT OR REPLACE INTO ip_cache VALUES (?,?,?)",
            (ip, json.dumps(geo), datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        return geo

    try:
        resp = requests.get(GEOIP_API.format(ip=ip), timeout=5)
        geo = resp.json()
        if geo.get("status") == "success":
            conn.execute(
                "INSERT OR REPLACE INTO ip_cache VALUES (?,?,?)",
                (ip, json.dumps(geo), datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
            return geo
    except Exception as e:
        log.warning(f"GeoIP lookup failed for {ip}: {e}")

    return {"country": "Unknown", "countryCode": "XX", "city": "Unknown",
            "lat": 0, "lon": 0, "isp": "Unknown"}


# ── Event extraction ──────────────────────────────────────────────
EVENT_MAP = {
    "cowrie.login.failed":   "AUTH_FAIL",
    "cowrie.login.success":  "AUTH_SUCCESS",
    "cowrie.command.input":  "COMMAND",
    "cowrie.session.file_download": "FILE_DROP",
    "cowrie.session.connect": "CONNECT",
    "cowrie.session.closed": "DISCONNECT",
    "cowrie.client.version": "CLIENT_VERSION",
}

def parse_event(raw: dict, conn: sqlite3.Connection) -> dict | None:
    """Parse a single Cowrie JSON log entry into a structured event."""
    event_type_raw = raw.get("eventid", "")
    event_type = EVENT_MAP.get(event_type_raw, event_type_raw)

    if not event_type:
        return None

    src_ip = raw.get("src_ip", "0.0.0.0")
    geo = geoip_lookup(src_ip, conn)

    # Create a stable unique ID from content hash
    event_id = hashlib.md5(
        f"{raw.get('timestamp','')}{src_ip}{event_type_raw}{raw.get('input','')}".encode()
    ).hexdigest()

    event = {
        "timestamp":    raw.get("timestamp", datetime.utcnow().isoformat()),
        "event_id":     event_id,
        "event_type":   event_type,
        "src_ip":       src_ip,
        "session":      raw.get("session", ""),
        "username":     raw.get("username", ""),
        "password":     raw.get("password", ""),
        "command":      raw.get("input", ""),
        "file_hash":    raw.get("shasum", ""),
        "file_path":    raw.get("outfile", ""),
        "country":      geo.get("country", "Unknown"),
        "country_code": geo.get("countryCode", "XX"),
        "city":         geo.get("city", "Unknown"),
        "lat":          geo.get("lat", 0),
        "lon":          geo.get("lon", 0),
        "isp":          geo.get("isp", "Unknown"),
        "raw":          json.dumps(raw),
    }

    return event


def store_event(event: dict, conn: sqlite3.Connection):
    """Insert parsed event into SQLite and index into Elasticsearch."""
    try:
        conn.execute("""
            INSERT OR IGNORE INTO events
            (timestamp, event_id, event_type, src_ip, username, password,
             command, file_hash, country, country_code, city, lat, lon, isp, raw)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            event["timestamp"], event["event_id"], event["event_type"],
            event["src_ip"], event["username"], event["password"],
            event["command"], event["file_hash"], event["country"],
            event["country_code"], event["city"], event["lat"],
            event["lon"], event["isp"], event["raw"]
        ))
        conn.commit()
    except sqlite3.Error as e:
        log.error(f"DB insert error: {e}")

    # Also push to Elasticsearch
    try:
        es_url = f"{ES_HOST}/honeypot-events/_doc/{event['event_id']}"
        requests.put(es_url, json=event, timeout=5)
    except Exception as e:
        log.debug(f"ES index failed (non-critical): {e}")


# ── IoC extraction ────────────────────────────────────────────────
SUSPICIOUS_COMMANDS = [
    r"wget\s+http", r"curl\s+http", r"chmod\s+\+x", r"python\s+-c",
    r"base64\s+-d", r"nc\s+-", r"nmap\s+", r"masscan", r"/bin/sh",
    r"cat\s+/etc/passwd", r"cat\s+/etc/shadow", r"crontab\s+-",
    r"rm\s+-rf", r"dd\s+if=", r"uname\s+-a", r"id\b", r"whoami",
]
SUSPICIOUS_RE = [re.compile(p, re.I) for p in SUSPICIOUS_COMMANDS]

def extract_iocs(event: dict) -> list[dict]:
    """Extract indicators of compromise from a parsed event."""
    iocs = []
    cmd = event.get("command", "")

    for pattern, compiled in zip(SUSPICIOUS_COMMANDS, SUSPICIOUS_RE):
        if compiled.search(cmd):
            iocs.append({
                "type": "SUSPICIOUS_COMMAND",
                "indicator": cmd,
                "pattern": pattern,
                "src_ip": event["src_ip"],
                "timestamp": event["timestamp"],
            })

    if event.get("file_hash"):
        iocs.append({
            "type": "MALWARE_HASH",
            "indicator": event["file_hash"],
            "src_ip": event["src_ip"],
            "timestamp": event["timestamp"],
        })

    return iocs


# ── Main processing loop ──────────────────────────────────────────
def tail_log(path: str, conn: sqlite3.Connection):
    """Continuously tail the log file and process new lines."""
    state_file = Path(path).with_suffix(".offset")
    offset = int(state_file.read_text()) if state_file.exists() else 0

    try:
        with open(path, "r") as f:
            f.seek(offset)
            new_events = 0

            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    event = parse_event(raw, conn)
                    if event:
                        store_event(event, conn)
                        iocs = extract_iocs(event)
                        if iocs:
                            log.info(f"IoC detected from {event['src_ip']}: {iocs[0]['type']}")
                        new_events += 1
                except json.JSONDecodeError:
                    pass

            new_offset = f.tell()
            state_file.write_text(str(new_offset))

            if new_events:
                log.info(f"Processed {new_events} new events (offset={new_offset})")

    except FileNotFoundError:
        log.debug(f"Log not found yet: {path} — waiting…")


def main():
    log.info("🔍 Log Parser starting up")
    log.info(f"   Log file  : {LOG_PATH}")
    log.info(f"   Database  : {DB_PATH}")
    log.info(f"   ES host   : {ES_HOST}")
    log.info(f"   Interval  : {PARSE_INTERVAL}s")

    conn = init_db(DB_PATH)

    while True:
        try:
            tail_log(LOG_PATH, conn)
        except Exception as e:
            log.error(f"Parse cycle error: {e}")
        time.sleep(PARSE_INTERVAL)


if __name__ == "__main__":
    main()
