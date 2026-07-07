from flask import Flask, jsonify, render_template_string
import sqlite3
from collections import defaultdict

DB = "dns_memory.db"
app = Flask(__name__)

# -----------------------------
# DEVICE NORMALIZATION
# -----------------------------
def normalize_device(device):
    if not device:
        return "UNKNOWN"

    d = device.strip().lower()

    # loopback noise
    if d in ["127.0.0.1", "::1"]:
        return "LOCALHOST_SYSTEM"

    # IPv6 multicast / unknown grouping
    if d == "::":
        return "UNKNOWN_IPV6"

    # reverse DNS noise
    if "in-addr.arpa" in d:
        return "REVERSE_DNS_SYSTEM"

    return device


# -----------------------------
# DOMAIN CLASSIFICATION (IMPROVED)
# -----------------------------
def classify(domain):
    d = domain.lower()

    # system noise
    if "in-addr.arpa" in d or "ip6.arpa" in d:
        return "SYSTEM"

    # CDNs
    if any(x in d for x in [
        "cloudfront", "googleapis", "gstatic",
        "fastly", "akamai", "amazonaws"
    ]):
        return "CDN"

    # telemetry / tracking
    if any(x in d for x in [
        "analytics", "doubleclick", "googletagmanager",
        "safebrowsing", "variations", "componentupdater"
    ]):
        return "TELEMETRY"

    # auth / secure services
    if any(x in d for x in [
        "login", "auth", "oauth", "proton", "chatgpt"
    ]):
        return "AUTH"

    return "BROWSING"


# -----------------------------
# LOAD DATA
# -----------------------------
def load_data():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
        SELECT device, domain
        FROM domain_events
        ORDER BY timestamp DESC
        LIMIT 1000
    """)

    rows = cur.fetchall()
    conn.close()

    return rows


# -----------------------------
# BUILD CLEAN VIEW
# -----------------------------
def build_view():
    raw = load_data()

    devices = defaultdict(lambda: defaultdict(int))

    for device, domain in raw:
        device = normalize_device(device)
        category = classify(domain)

        # filter out system noise completely
        if category == "SYSTEM":
            continue

        devices[device][(domain, category)] += 1

    return devices


# -----------------------------
# UI
# -----------------------------
HTML = """
<!doctype html>
<html>
<head>
<title>Phase 6.5 SOC</title>
<style>
body { background:#0b0f14; color:#e6e6e6; font-family:Arial; }
.device { border:1px solid #333; padding:10px; margin:10px; border-radius:8px; }
.CDN { color:#4fc3f7; }
.TELEMETRY { color:#ffb300; }
.AUTH { color:#81c784; }
.BROWSING { color:#e0e0e0; }
.SYSTEM { color:#616161; }
</style>
</head>

<body>
<h1>🧠 Phase 6.5 Clean SOC Dashboard</h1>
<div id="data"></div>

<script>
async function load(){
    const res = await fetch("/data");
    const data = await res.json();

    let html = "";

    for (let device in data){
        html += `<div class="device">`;
        html += `<h2>${device}</h2>`;

        let items = data[device];

        for (let i of items){
            html += `<div class="${i.category}">
                ${i.domain} (${i.count}x) — ${i.category}
            </div>`;
        }

        html += "</div>";
    }

    document.getElementById("data").innerHTML = html;
}

setInterval(load, 3000);
load();
</script>

</body>
</html>
"""


# -----------------------------
# API
# -----------------------------
@app.route("/data")
def data():
    view = build_view()

    output = {}

    for device, domains in view.items():
        output[device] = [
            {
                "domain": d,
                "category": c,
                "count": count
            }
            for (d, c), count in domains.items()
        ]

    return jsonify(output)


@app.route("/")
def home():
    return render_template_string(HTML)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
