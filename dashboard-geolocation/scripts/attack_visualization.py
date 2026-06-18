
#!/usr/bin/env python3

"""

Attack Pattern Visualization — Week 4

Generates text-based visualization of attack patterns.

"""

import json

from collections import Counter

from datetime import datetime

def load_logs(filepath):

    events = []

    with open(filepath) as f:

        for line in f:

            try:

                events.append(json.loads(line.strip()))

            except:

                pass

    return events

def generate_visualizations(events):

    report = []

    report.append("="*65)

    report.append("  ATTACK PATTERN VISUALIZATION REPORT")

    report.append(f"  Generated: {datetime.utcnow().isoformat()}Z")

    report.append("="*65)

    report.append("")

    # Event type distribution

    event_types = Counter(e.get("eventid","") for e in events)

    report.append("EVENT TYPE DISTRIBUTION")

    report.append("-"*65)

    max_count = max(event_types.values()) if event_types else 1

    for ev, count in event_types.most_common():

        bar_len = int((count / max_count) * 40)

        bar = "█" * bar_len

        pct = (count / len(events)) * 100 if events else 0

        report.append(f"  {ev:<40} {count:4d} ({pct:.1f}%) {bar}")

    report.append("")

    # Hourly attack pattern

    hourly = Counter(e.get("timestamp","")[:13] for e in events if e.get("timestamp"))

    report.append("HOURLY ATTACK PATTERN")

    report.append("-"*65)

    if hourly:

        max_h = max(hourly.values())

        for hour in sorted(hourly.keys()):

            bar_len = int((hourly[hour] / max_h) * 40)

            bar = "▓" * bar_len

            report.append(f"  {hour}  {hourly[hour]:4d}  {bar}")

    report.append("")

    # Credential analysis

    creds = [(e.get("username",""), e.get("password",""))

             for e in events if e.get("eventid") == "cowrie.login.failed"]

    if creds:

        report.append("TOP CREDENTIAL PAIRS ATTEMPTED")

        report.append("-"*65)

        report.append(f"  {'USERNAME':<15} {'PASSWORD':<15} {'COUNT'}")

        report.append("-"*65)

        for (u,p), count in Counter(creds).most_common(10):

            report.append(f"  {u:<15} {p:<15} {count}")

        report.append("")

    # Commands

    commands = [e.get("input","") for e in events

                if e.get("eventid") == "cowrie.command.input" and e.get("input")]

    if commands:

        report.append("COMMANDS EXECUTED IN FAKE SHELL")

        report.append("-"*65)

        for cmd in commands[:15]:

            report.append(f"  $ {cmd[:60]}")

        report.append("")

    # Risk assessment

    successes = sum(1 for e in events if e.get("eventid") == "cowrie.login.success")

    report.append("RISK ASSESSMENT")

    report.append("-"*65)

    report.append(f"  Total Events      : {len(events)}")

    report.append(f"  Successful Logins : {successes}")

    report.append(f"  Risk Level        : {'CRITICAL' if successes > 5 else 'HIGH' if successes > 0 else 'MEDIUM'}")

    report.append(f"  Recommendation    : Immediate credential rotation required")

    report.append("")

    report.append("="*65)

    return "\n".join(report)

if __name__ == "__main__":

    events = load_logs("cowrie_logs.json")

    report = generate_visualizations(events)

    print(report)

    with open("dashboard-geolocation/visualizations/attack_patterns.txt", "w") as f:

        f.write(report)

    print("\nVisualization saved!")

