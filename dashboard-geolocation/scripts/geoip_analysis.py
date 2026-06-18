
#!/usr/bin/env python3

"""

GeoIP Enrichment Script — Week 4

Enriches attack logs with geographic information.

Note: 172.20.0.1 is Docker internal IP (lab environment).

In production, external IPs would show real geolocation.

"""

import json

import requests

from datetime import datetime

from collections import Counter

def geoip_lookup(ip):

    """Lookup IP geolocation using free API."""

    # Skip private/internal IPs

    private = ["172.", "192.168.", "10.", "127."]

    if any(ip.startswith(p) for p in private):

        return {

            "ip": ip,

            "country": "Internal Network",

            "country_code": "INT",

            "city": "Lab Environment",

            "lat": 0, "lon": 0,

            "isp": "Docker Bridge Network",

            "note": "Private IP - Docker lab environment"

        }

    try:

        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)

        data = r.json()

        if data.get("status") == "success":

            return {

                "ip": ip,

                "country": data.get("country", "Unknown"),

                "country_code": data.get("countryCode", "XX"),

                "city": data.get("city", "Unknown"),

                "lat": data.get("lat", 0),

                "lon": data.get("lon", 0),

                "isp": data.get("isp", "Unknown")

            }

    except Exception as e:

        print(f"GeoIP lookup failed: {e}")

    return {"ip": ip, "country": "Unknown", "country_code": "XX"}

def analyze_logs(log_file):

    """Analyze cowrie logs and enrich with GeoIP."""

    events = []

    ips = set()

    with open(log_file) as f:

        for line in f:

            try:

                e = json.loads(line.strip())

                events.append(e)

                if e.get("src_ip"):

                    ips.add(e["src_ip"])

            except:

                pass

    print(f"Total events: {len(events)}")

    print(f"Unique IPs: {len(ips)}")

    print()

    # GeoIP enrichment

    geo_results = []

    for ip in ips:

        geo = geoip_lookup(ip)

        event_count = sum(1 for e in events if e.get("src_ip") == ip)

        geo["event_count"] = event_count

        geo_results.append(geo)

        print(f"IP: {ip}")

        print(f"  Location: {geo.get('city')}, {geo.get('country')}")

        print(f"  Events: {event_count}")

        print()

    return geo_results, events

if __name__ == "__main__":

    print("="*60)

    print("  GeoIP ENRICHMENT ANALYSIS")

    print("="*60)

    print()

    geo_results, events = analyze_logs("cowrie_logs.json")

    # Save results

    output = {

        "generated_at": datetime.utcnow().isoformat() + "Z",

        "lab_note": "Attacks from 172.20.0.1 (Docker internal) - simulated lab environment",

        "total_events": len(events),

        "geo_enriched_ips": geo_results

    }

    with open("dashboard-geolocation/reports/geoip_enrichment.json", "w") as f:

        json.dump(output, f, indent=2)

    print("GeoIP report saved!")

