#!/usr/bin/env python3
"""
Threat Analysis Dashboard — Healthcare IoT Honeypot Network
===========================================================
Flask web app that reads the parsed SQLite database and renders
a live threat intelligence dashboard with:
  - Real-time attack feed
  - World map of attack origins (Leaflet.js)
  - Top attacker IPs / credentials / commands
  - IoC summary
  - Geolocation statistics
"""

import json
import os
import sqlite3
from datetime import datetime, timedelta
from collections import Counter
from flask import Flask, render_template, jsonify

app = Flask(__name__)

DB_PATH = os.getenv("DB_PATH", "/app/db/honeypot.db")


def get_db():
    """Get SQLite connection (read-only)."""
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def query(sql, params=()):
    try:
        conn = get_db()
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


# ── Dashboard routes ──────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    """High-level KPI counters for top stat cards."""
    total     = query("SELECT COUNT(*) AS n FROM events")[0]["n"]
    auth_fail = query("SELECT COUNT(*) AS n FROM events WHERE event_type='AUTH_FAIL'")[0]["n"]
    auth_ok   = query("SELECT COUNT(*) AS n FROM events WHERE event_type='AUTH_SUCCESS'")[0]["n"]
    commands  = query("SELECT COUNT(*) AS n FROM events WHERE event_type='COMMAND'")[0]["n"]
    malware   = query("SELECT COUNT(*) AS n FROM events WHERE file_hash != ''")[0]["n"]
    unique_ips= query("SELECT COUNT(DISTINCT src_ip) AS n FROM events")[0]["n"]
    countries = query("SELECT COUNT(DISTINCT country_code) AS n FROM events")[0]["n"]

    last24h = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    recent  = query("SELECT COUNT(*) AS n FROM events WHERE timestamp > ?", (last24h,))[0]["n"]

    return jsonify({
        "total_events": total,
        "auth_failures": auth_fail,
        "auth_successes": auth_ok,
        "commands_executed": commands,
        "malware_drops": malware,
        "unique_ips": unique_ips,
        "countries_seen": countries,
        "events_last_24h": recent,
    })


@app.route("/api/recent_events")
def api_recent_events():
    """Last 50 events for the live feed table."""
    rows = query("""
        SELECT timestamp, event_type, src_ip, country, city,
               username, password, command, file_hash
        FROM events
        ORDER BY timestamp DESC
        LIMIT 50
    """)
    return jsonify(rows)


@app.route("/api/map_data")
def api_map_data():
    """Attack origin coordinates for the world map."""
    rows = query("""
        SELECT src_ip, country, country_code, city, lat, lon, isp,
               COUNT(*) AS event_count
        FROM events
        WHERE lat != 0 AND country_code != 'INT'
        GROUP BY src_ip
        ORDER BY event_count DESC
        LIMIT 500
    """)
    return jsonify(rows)


@app.route("/api/top_ips")
def api_top_ips():
    rows = query("""
        SELECT src_ip, country, city, isp,
               COUNT(*) AS hits,
               SUM(CASE WHEN event_type='AUTH_SUCCESS' THEN 1 ELSE 0 END) AS successes
        FROM events
        GROUP BY src_ip
        ORDER BY hits DESC
        LIMIT 20
    """)
    return jsonify(rows)


@app.route("/api/top_credentials")
def api_top_credentials():
    rows = query("""
        SELECT username, password, COUNT(*) AS attempts
        FROM events
        WHERE event_type='AUTH_FAIL' AND username != ''
        GROUP BY username, password
        ORDER BY attempts DESC
        LIMIT 20
    """)
    return jsonify(rows)


@app.route("/api/top_commands")
def api_top_commands():
    rows = query("""
        SELECT command, COUNT(*) AS count
        FROM events
        WHERE event_type='COMMAND' AND command != ''
        GROUP BY command
        ORDER BY count DESC
        LIMIT 20
    """)
    return jsonify(rows)


@app.route("/api/country_stats")
def api_country_stats():
    rows = query("""
        SELECT country, country_code, COUNT(*) AS attacks
        FROM events
        WHERE country_code NOT IN ('INT','XX','')
        GROUP BY country
        ORDER BY attacks DESC
        LIMIT 15
    """)
    return jsonify(rows)


@app.route("/api/timeline")
def api_timeline():
    """Hourly attack volume for the last 48 hours."""
    rows = query("""
        SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) AS hour,
               COUNT(*) AS count
        FROM events
        WHERE timestamp > datetime('now', '-48 hours')
        GROUP BY hour
        ORDER BY hour ASC
    """)
    return jsonify(rows)


@app.route("/api/malware_hashes")
def api_malware_hashes():
    rows = query("""
        SELECT file_hash, src_ip, country, timestamp
        FROM events
        WHERE file_hash != ''
        ORDER BY timestamp DESC
        LIMIT 50
    """)
    return jsonify(rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
