from __future__ import annotations

from typing import Any

from flask import Flask, jsonify, render_template_string

from core.config import settings
from core.db import (
    database_stats,
    get_events,
    query_all,
)
from core.logger import get_logger


logger = get_logger(__name__)


HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PiHole-AI</title>
<style>
:root {
    color-scheme: dark;
    --bg: #101113;
    --panel: #181b1f;
    --line: #2d333a;
    --text: #f2f4f5;
    --muted: #aab2bb;
    --accent: #58c4a7;
    --warn: #e7b75f;
    --danger: #e86969;
}

* { box-sizing: border-box; }

body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: Arial, sans-serif;
    font-size: 14px;
}

header {
    align-items: center;
    border-bottom: 1px solid var(--line);
    display: flex;
    gap: 16px;
    justify-content: space-between;
    padding: 14px 18px;
}

h1 {
    font-size: 20px;
    font-weight: 700;
    margin: 0;
}

main {
    display: grid;
    gap: 16px;
    grid-template-columns: minmax(0, 1fr);
    padding: 16px;
}

.stats {
    display: grid;
    gap: 12px;
    grid-template-columns: repeat(4, minmax(120px, 1fr));
}

.stat,
.panel {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 8px;
}

.stat {
    padding: 12px;
}

.label {
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
}

.value {
    font-size: 26px;
    font-weight: 700;
    margin-top: 6px;
}

.grid {
    display: grid;
    gap: 16px;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
}

.panel {
    min-width: 0;
    overflow: hidden;
}

.panel h2 {
    border-bottom: 1px solid var(--line);
    font-size: 15px;
    margin: 0;
    padding: 12px;
}

table {
    border-collapse: collapse;
    width: 100%;
}

td,
th {
    border-bottom: 1px solid var(--line);
    overflow-wrap: anywhere;
    padding: 9px 12px;
    text-align: left;
    vertical-align: top;
}

th {
    color: var(--muted);
    font-size: 12px;
    font-weight: 600;
}

.risk-low { color: var(--accent); }
.risk-mid { color: var(--warn); }
.risk-high { color: var(--danger); }
.muted { color: var(--muted); }

@media (max-width: 900px) {
    .stats,
    .grid {
        grid-template-columns: minmax(0, 1fr);
    }
}
</style>
</head>
<body>
<header>
    <h1>PiHole-AI</h1>
    <span class="muted" id="updated">-</span>
</header>
<main>
    <section class="stats" id="stats"></section>
    <section class="grid">
        <div class="panel">
            <h2>Recent Events</h2>
            <table>
                <thead>
                    <tr>
                        <th>Device</th>
                        <th>Domain</th>
                        <th>Processed</th>
                    </tr>
                </thead>
                <tbody id="events"></tbody>
            </table>
        </div>
        <div class="panel">
            <h2>Recent Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Risk</th>
                        <th>Category</th>
                    </tr>
                </thead>
                <tbody id="analysis"></tbody>
            </table>
        </div>
    </section>
    <section class="panel">
        <h2>Devices</h2>
        <table>
            <thead>
                <tr>
                    <th>Device</th>
                    <th>Queries</th>
                    <th>Domains</th>
                    <th>Processed</th>
                </tr>
            </thead>
            <tbody id="devices"></tbody>
        </table>
    </section>
</main>
<script>
const text = (value) => String(value ?? "-");

function clear(node) {
    while (node.firstChild) {
        node.removeChild(node.firstChild);
    }
}

function cell(value, className = "") {
    const td = document.createElement("td");
    td.textContent = text(value);
    if (className) {
        td.className = className;
    }
    return td;
}

function row(values) {
    const tr = document.createElement("tr");
    values.forEach((value) => {
        if (Array.isArray(value)) {
            tr.appendChild(cell(value[0], value[1]));
        } else {
            tr.appendChild(cell(value));
        }
    });
    return tr;
}

function riskClass(risk) {
    if (risk >= 70) return "risk-high";
    if (risk >= 40) return "risk-mid";
    return "risk-low";
}

function renderStats(stats) {
    const target = document.getElementById("stats");
    clear(target);

    [
        ["Events", stats.events],
        ["Processed", stats.processed],
        ["Domains", stats.domains],
        ["Analyses", stats.analyses],
    ].forEach(([label, value]) => {
        const item = document.createElement("div");
        item.className = "stat";

        const labelNode = document.createElement("div");
        labelNode.className = "label";
        labelNode.textContent = label;

        const valueNode = document.createElement("div");
        valueNode.className = "value";
        valueNode.textContent = text(value);

        item.append(labelNode, valueNode);
        target.appendChild(item);
    });
}

function renderEvents(events) {
    const target = document.getElementById("events");
    clear(target);
    events.forEach((event) => {
        target.appendChild(row([
            event.device,
            event.domain,
            event.processed ? "yes" : "no",
        ]));
    });
}

function renderAnalysis(items) {
    const target = document.getElementById("analysis");
    clear(target);
    items.forEach((item) => {
        target.appendChild(row([
            item.domain,
            [item.risk, riskClass(item.risk)],
            item.category,
        ]));
    });
}

function renderDevices(devices) {
    const target = document.getElementById("devices");
    clear(target);
    devices.forEach((device) => {
        target.appendChild(row([
            device.device,
            device.query_count,
            device.domain_count,
            device.processed_count,
        ]));
    });
}

async function load() {
    const [stats, events, analysis, devices] = await Promise.all([
        fetch("/api/stats").then((res) => res.json()),
        fetch("/api/events").then((res) => res.json()),
        fetch("/api/analysis").then((res) => res.json()),
        fetch("/api/devices").then((res) => res.json()),
    ]);

    renderStats(stats);
    renderEvents(events);
    renderAnalysis(analysis);
    renderDevices(devices);
    document.getElementById("updated").textContent =
        new Date().toLocaleTimeString();
}

setInterval(load, 3000);
load();
</script>
</body>
</html>
"""


def row_to_dict(
    row: Any,
) -> dict[str, Any]:
    """
    Convert sqlite rows and tuple-like rows to plain dictionaries.
    """

    return dict(row)


def get_recent_analyses(
    limit: int = 100,
) -> list[dict[str, Any]]:
    """
    Return recent domain analyses for the dashboard/API.
    """

    rows = query_all(
        """
        SELECT

            domain,
            risk,
            category,
            reason,
            model,
            analyzed_at

        FROM analysis

        ORDER BY analyzed_at DESC

        LIMIT ?
        """,
        (limit,),
    )

    return [
        row_to_dict(row)
        for row in rows
    ]


def get_device_summary(
    limit: int = 100,
) -> list[dict[str, Any]]:
    """
    Return per-device event counts.
    """

    rows = query_all(
        """
        SELECT

            device,
            COUNT(*) AS query_count,
            COUNT(DISTINCT domain) AS domain_count,
            SUM(CASE WHEN processed = 1 THEN 1 ELSE 0 END) AS processed_count

        FROM events

        GROUP BY device

        ORDER BY query_count DESC

        LIMIT ?
        """,
        (limit,),
    )

    return [
        row_to_dict(row)
        for row in rows
    ]


def create_app() -> Flask:
    """
    Create the Flask dashboard application.
    """

    app = Flask(__name__)

    @app.get("/")
    def home():
        return render_template_string(HTML)

    @app.get("/api/stats")
    def stats():
        return jsonify(database_stats())

    @app.get("/api/events")
    def events():
        return jsonify(
            [
                row_to_dict(row)
                for row in get_events(100)
            ]
        )

    @app.get("/api/analysis")
    def analysis():
        return jsonify(
            get_recent_analyses(100)
        )

    @app.get("/api/devices")
    def devices():
        return jsonify(
            get_device_summary(100)
        )

    @app.get("/api/health")
    def health():
        return jsonify(
            {
                "status": "ok",
                "database": database_stats(),
            }
        )

    @app.get("/data")
    def legacy_data():
        return jsonify(
            get_device_summary(100)
        )

    return app


app = create_app()


def main() -> None:
    """
    Run the dashboard development server.
    """

    logger.info(
        "Starting dashboard on port %d.",
        settings.dashboard_port,
    )

    app.run(
        host="0.0.0.0",
        port=settings.dashboard_port,
    )


if __name__ == "__main__":
    main()
