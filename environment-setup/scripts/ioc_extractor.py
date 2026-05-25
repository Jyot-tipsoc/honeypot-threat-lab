#!/usr/bin/env python3
"""
ioc_extractor.py — Week 3: Threat Intelligence Extraction
==========================================================
Reads the parsed SQLite database and produces a structured
IoC report: attacker IPs, malware hashes, suspicious commands,
credential spray patterns.

Output: ioc_report.json + ioc_report.txt (human readable)

Usage:
    python3 scripts/ioc_extractor.py --db /app/db/honeypot.db
"""

import argparse
import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime

def get_conn(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def extract(db_path: str) -> dict:
    conn = get_conn(db_path)
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "attacker_ips": [],
        "malware_hashes": [],
        "suspicious_commands": [],
        "credential_spray": [],
        "top_countries": [],
        "summary": {}
    }

    # ── Attacker IPs ──────────────────────────────────────────
    rows = conn.execute("""
        SELECT src_ip, country, isp,
               COUNT(*) as total_events,
               SUM(CASE WHEN event_type='AUTH_SUCCESS' THEN 1 ELSE 0 END) as shell_access,
               SUM(CASE WHEN event_type='FILE_DROP' THEN 1 ELSE 0 END) as file_drops,
               MIN(timestamp) as first_seen,
               MAX(timestamp) as last_seen
        FROM events
        GROUP BY src_ip
        ORDER BY total_events DESC
        LIMIT 100
    """).fetchall()

    for r in rows:
        report["attacker_ips"].append({
            "ip": r["src_ip"],
            "country": r["country"],
            "isp": r["isp"],
            "total_events": r["total_events"],
            "shell_access": bool(r["shell_access"]),
            "file_drops": r["file_drops"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "threat_level": "HIGH" if r["shell_access"] or r["file_drops"] else "MEDIUM" if r["total_events"] > 20 else "LOW"
        })

    # ── Malware hashes ─────────────────────────────────────────
    rows = conn.execute("""
        SELECT DISTINCT file_hash, src_ip, country, timestamp
        FROM events WHERE file_hash != ''
        ORDER BY timestamp DESC
    """).fetchall()

    for r in rows:
        report["malware_hashes"].append({
            "sha256": r["file_hash"],
            "src_ip": r["src_ip"],
            "country": r["country"],
            "first_seen": r["timestamp"],
            "virustotal_url": f"https://www.virustotal.com/gui/file/{r['file_hash']}"
        })

    # ── Suspicious commands ────────────────────────────────────
    rows = conn.execute("""
        SELECT command, src_ip, country, timestamp
        FROM events WHERE event_type='COMMAND' AND command != ''
        ORDER BY timestamp DESC LIMIT 200
    """).fetchall()

    KEYWORDS = ["wget","curl","chmod +x","base64 -d","python -c","nc -","nmap",
                "masscan","/bin/sh","cat /etc/passwd","cat /etc/shadow",
                "crontab","rm -rf","dd if=","authorized_keys"]

    for r in rows:
        matched = [k for k in KEYWORDS if k in r["command"]]
        if matched:
            report["suspicious_commands"].append({
                "command": r["command"],
                "matched_patterns": matched,
                "src_ip": r["src_ip"],
                "country": r["country"],
                "timestamp": r["timestamp"]
            })

    # ── Credential spray ───────────────────────────────────────
    rows = conn.execute("""
        SELECT username, password, COUNT(*) as attempts,
               COUNT(DISTINCT src_ip) as unique_ips
        FROM events WHERE event_type='AUTH_FAIL' AND username != ''
        GROUP BY username, password
        ORDER BY attempts DESC LIMIT 50
    """).fetchall()

    for r in rows:
        report["credential_spray"].append({
            "username": r["username"],
            "password": r["password"],
            "attempts": r["attempts"],
            "unique_source_ips": r["unique_ips"]
        })

    # ── Countries ──────────────────────────────────────────────
    rows = conn.execute("""
        SELECT country, country_code, COUNT(*) as attacks,
               COUNT(DISTINCT src_ip) as unique_ips
        FROM events WHERE country_code NOT IN ('INT','XX','')
        GROUP BY country ORDER BY attacks DESC LIMIT 20
    """).fetchall()

    for r in rows:
        report["top_countries"].append(dict(r))

    # ── Summary ────────────────────────────────────────────────
    summary = conn.execute("""
        SELECT
          COUNT(*) as total_events,
          COUNT(DISTINCT src_ip) as unique_ips,
          SUM(CASE WHEN event_type='AUTH_FAIL' THEN 1 ELSE 0 END) as auth_failures,
          SUM(CASE WHEN event_type='AUTH_SUCCESS' THEN 1 ELSE 0 END) as auth_successes,
          SUM(CASE WHEN event_type='COMMAND' THEN 1 ELSE 0 END) as commands,
          SUM(CASE WHEN file_hash != '' THEN 1 ELSE 0 END) as malware_drops,
          MIN(timestamp) as earliest,
          MAX(timestamp) as latest
        FROM events
    """).fetchone()

    report["summary"] = dict(summary)
    conn.close()
    return report


def write_text_report(report: dict, path: str):
    lines = [
        "=" * 70,
        "  HEALTHCARE IOT HONEYPOT — THREAT INTELLIGENCE REPORT",
        f"  Generated: {report['generated_at']}",
        "=" * 70,
        "",
        "SUMMARY",
        "-------",
    ]
    s = report["summary"]
    lines += [
        f"  Total Events     : {s.get('total_events', 0)}",
        f"  Unique Attackers : {s.get('unique_ips', 0)}",
        f"  Auth Failures    : {s.get('auth_failures', 0)}",
        f"  Auth Successes   : {s.get('auth_successes', 0)}  ← attacker reached shell",
        f"  Commands Run     : {s.get('commands', 0)}",
        f"  Malware Dropped  : {s.get('malware_drops', 0)}",
        f"  Time Range       : {s.get('earliest','?')} → {s.get('latest','?')}",
        "",
        "TOP ATTACKER IPs",
        "----------------",
    ]
    for ip in report["attacker_ips"][:10]:
        lines.append(
            f"  [{ip['threat_level']:6s}] {ip['ip']:20s} {ip['country']:15s} "
            f"events={ip['total_events']}"
            + (" SHELL!" if ip["shell_access"] else "")
            + (f" drops={ip['file_drops']}" if ip["file_drops"] else "")
        )

    lines += ["", "MALWARE HASHES (SHA256)", "-----------------------"]
    if report["malware_hashes"]:
        for h in report["malware_hashes"]:
            lines.append(f"  {h['sha256']}  ← {h['src_ip']} ({h['country']})")
            lines.append(f"  VirusTotal: {h['virustotal_url']}")
    else:
        lines.append("  No malware captured yet.")

    lines += ["", "TOP CREDENTIAL SPRAY PAIRS", "--------------------------"]
    for c in report["credential_spray"][:15]:
        lines.append(f"  {c['username']:15s} / {c['password']:15s}  x{c['attempts']}")

    lines += ["", "SUSPICIOUS COMMANDS", "-------------------"]
    for cmd in report["suspicious_commands"][:15]:
        lines.append(f"  [{', '.join(cmd['matched_patterns'])}]")
        lines.append(f"    $ {cmd['command'][:80]}")
        lines.append(f"    from {cmd['src_ip']} at {cmd['timestamp']}")
        lines.append("")

    lines += ["", "TOP ATTACK ORIGINS", "------------------"]
    for c in report["top_countries"][:10]:
        lines.append(f"  {c['country_code']:3s}  {c['country']:25s}  attacks={c['attacks']}  unique_ips={c['unique_ips']}")

    lines += ["", "=" * 70]

    with open(path, "w") as f:
        f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db",  default="/app/db/honeypot.db", help="SQLite DB path")
    parser.add_argument("--out", default=".",                   help="Output directory")
    args = parser.parse_args()

    print("[IoC] Extracting threat intelligence…")
    report = extract(args.db)

    json_path = f"{args.out}/ioc_report.json"
    txt_path  = f"{args.out}/ioc_report.txt"

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    write_text_report(report, txt_path)

    print(f"[IoC] JSON report → {json_path}")
    print(f"[IoC] Text report → {txt_path}")
    print(f"[IoC] {report['summary'].get('unique_ips',0)} unique attackers, "
          f"{len(report['malware_hashes'])} malware hashes, "
          f"{len(report['suspicious_commands'])} suspicious commands.")


if __name__ == "__main__":
    main()
