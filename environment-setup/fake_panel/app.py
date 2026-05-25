"""
Fake Medical IoT Web Administration Panel
Simulates an unauthenticated Philips IntelliVue gateway web UI.
Every request is logged to /app/logs/panel.log for threat analysis.
"""

import json
import logging
import os
from datetime import datetime
from flask import Flask, request, render_template_string, redirect, jsonify

app = Flask(__name__)

# ── Logging setup ─────────────────────────────────────────────────
os.makedirs("/app/logs", exist_ok=True)
logging.basicConfig(
    filename="/app/logs/panel.log",
    level=logging.INFO,
    format="%(message)s"
)

def log_interaction(event_type, extra=None):
    """Structured JSON log entry for every attacker interaction."""
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "src_ip": request.remote_addr,
        "src_port": request.environ.get("REMOTE_PORT", "unknown"),
        "method": request.method,
        "path": request.full_path,
        "user_agent": request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
        "payload": request.get_data(as_text=True)[:2000],  # cap size
    }
    if extra:
        entry.update(extra)
    logging.info(json.dumps(entry))
    print(f"[PANEL LOG] {entry['src_ip']} → {event_type}")

# ── Fake device constants ─────────────────────────────────────────
DEVICE_INFO = {
    "model": "Philips IntelliVue MX800 Gateway",
    "firmware": "3.2.1-build20190814",
    "serial": "PH-MX800-00847261",
    "ip": "172.20.0.11",
    "mac": "00:1A:2B:3C:4D:5E",
    "uptime": "47 days, 3:12:09",
    "patients_monitored": 12,
}

# ── Routes ────────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    log_interaction("PAGE_VISIT_HOME")
    return render_template_string(HOME_TEMPLATE, device=DEVICE_INFO)

@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin/", methods=["GET", "POST"])
def admin():
    log_interaction("ADMIN_PANEL_ACCESS")
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        log_interaction("LOGIN_ATTEMPT", {"username": username, "password": password})
        # Always show "success" — drop attacker into fake dashboard
        return redirect("/admin/dashboard")
    return render_template_string(LOGIN_TEMPLATE, device=DEVICE_INFO)

@app.route("/admin/dashboard")
def dashboard():
    log_interaction("DASHBOARD_ACCESS")
    return render_template_string(DASHBOARD_TEMPLATE, device=DEVICE_INFO)

@app.route("/admin/config", methods=["GET", "POST"])
def config():
    log_interaction("CONFIG_ACCESS")
    if request.method == "POST":
        log_interaction("CONFIG_CHANGE_ATTEMPT", {"form_data": dict(request.form)})
    return render_template_string(CONFIG_TEMPLATE, device=DEVICE_INFO)

@app.route("/api/status")
def api_status():
    log_interaction("API_PROBE")
    return jsonify({
        "status": "online",
        "device": DEVICE_INFO,
        "network": {"ssid": "MED-IoT-Secure", "signal": -42},
    })

@app.route("/cgi-bin/", defaults={"path": ""})
@app.route("/cgi-bin/<path:path>")
def cgi_probe(path):
    log_interaction("CGI_PROBE", {"cgi_path": path})
    return "Not Found", 404

@app.errorhandler(404)
def not_found(e):
    log_interaction("404_PROBE")
    return render_template_string(ERROR_TEMPLATE, device=DEVICE_INFO, code=404), 404

# ── HTML Templates ────────────────────────────────────────────────
HOME_TEMPLATE = """
<!DOCTYPE html><html><head>
<title>Philips IntelliVue Gateway — Network Management</title>
<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:40px}
h1{color:#4fc3f7}a{color:#80cbc4}.box{border:1px solid #333;padding:20px;margin:10px 0;background:#16213e}
</style></head><body>
<h1>⚕ Philips IntelliVue IoT Gateway</h1>
<div class="box"><b>Model:</b> {{device.model}}<br>
<b>Firmware:</b> {{device.firmware}}<br>
<b>Serial:</b> {{device.serial}}<br>
<b>Uptime:</b> {{device.uptime}}</div>
<p><a href="/admin">Administration Panel</a> | <a href="/api/status">Device Status API</a></p>
</body></html>"""

LOGIN_TEMPLATE = """
<!DOCTYPE html><html><head>
<title>Admin Login — IntelliVue Gateway</title>
<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;display:flex;
justify-content:center;align-items:center;height:100vh;margin:0}
.card{background:#16213e;border:1px solid #4fc3f7;padding:40px;width:320px}
h2{color:#4fc3f7;margin-top:0}input{width:100%;padding:8px;margin:8px 0;
background:#0f3460;border:1px solid #4fc3f7;color:#fff;box-sizing:border-box}
button{width:100%;padding:10px;background:#4fc3f7;color:#000;border:none;cursor:pointer;font-weight:bold}
</style></head><body><div class="card">
<h2>⚕ IntelliVue Admin</h2>
<form method="POST">
<input name="username" placeholder="Username" value="admin"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Login</button>
</form><p style="font-size:0.8em;color:#aaa">Default: admin/admin</p>
</div></body></html>"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html><html><head>
<title>Dashboard — IntelliVue Gateway</title>
<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:30px}
h2{color:#4fc3f7}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:15px}
.card{background:#16213e;border:1px solid #333;padding:20px}
.val{font-size:2em;color:#80cbc4;font-weight:bold}
a{color:#4fc3f7;text-decoration:none}
</style></head><body>
<h2>⚕ IntelliVue Gateway — Dashboard</h2>
<p>Logged in as <b>admin</b> | <a href="/admin/config">Device Config</a></p>
<div class="grid">
<div class="card"><div class="val">{{device.patients_monitored}}</div>Patients Monitored</div>
<div class="card"><div class="val">Online</div>Network Status</div>
<div class="card"><div class="val">{{device.uptime}}</div>Uptime</div>
<div class="card"><div class="val">3.2.1</div>Firmware Version</div>
<div class="card"><div class="val">12/20</div>Active Channels</div>
<div class="card"><div class="val">Normal</div>Alarm Status</div>
</div>
</body></html>"""

CONFIG_TEMPLATE = """
<!DOCTYPE html><html><head>
<title>Config — IntelliVue Gateway</title>
<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:30px}
h2{color:#4fc3f7}input,select{background:#0f3460;border:1px solid #4fc3f7;color:#fff;padding:6px}
button{background:#4fc3f7;color:#000;padding:8px 20px;border:none;cursor:pointer;font-weight:bold}
.row{margin:12px 0}label{display:inline-block;width:200px}
</style></head><body>
<h2>⚕ Device Configuration</h2>
<form method="POST">
<div class="row"><label>Device Hostname:</label><input name="hostname" value="MED-IoT-Gateway-01"></div>
<div class="row"><label>Network Mode:</label><select name="net_mode"><option>DHCP</option><option>Static</option></select></div>
<div class="row"><label>SSH Port:</label><input name="ssh_port" value="22"></div>
<div class="row"><label>MQTT Broker IP:</label><input name="mqtt_ip" value="192.168.1.100"></div>
<div class="row"><label>HL7 FHIR Endpoint:</label><input name="fhir" value="http://ehr.internal:8080/fhir/r4"></div>
<div class="row"><button type="submit">Save Configuration</button></div>
</form></body></html>"""

ERROR_TEMPLATE = """
<!DOCTYPE html><html><head><title>{{code}}</title>
<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;text-align:center;padding:80px}
h1{color:#ef5350;font-size:5em}p{color:#aaa}</style></head><body>
<h1>{{code}}</h1><p>Resource not found on IntelliVue Gateway.</p>
<p><a href="/" style="color:#4fc3f7">← Home</a></p>
</body></html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
