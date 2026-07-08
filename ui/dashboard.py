from __future__ import annotations

from typing import Any

from flask import Flask, jsonify, render_template_string, request

from core.config import settings
from core.db import (
    database_stats,
    get_recent_actions as db_get_recent_actions,
    query_all,
)
from core.logger import get_logger
from pihole_ai.learn import get_reputations as load_reputations
from pihole_ai.rules import (
    add_rule,
    get_rules as load_domain_rules,
    remove_rule,
)
from pihole_ai.status import collect_status


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
    grid-template-columns: repeat(6, minmax(120px, 1fr));
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

.toolbar {
    align-items: center;
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}

input,
select {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 6px;
    color: var(--text);
    min-height: 36px;
    padding: 7px 10px;
}

input {
    min-width: min(360px, 100%);
}

.toolbar button {
    background: var(--accent);
    border: 0;
    border-radius: 6px;
    color: #06110d;
    font-weight: 700;
    min-height: 36px;
    padding: 7px 12px;
}

.inline-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}

.inline-actions button {
    background: transparent;
    border: 1px solid var(--line);
    border-radius: 6px;
    color: var(--text);
    min-height: 30px;
    padding: 5px 8px;
}

.inline-actions button:hover {
    border-color: var(--accent);
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
    <section class="toolbar">
        <input id="search" type="search" placeholder="Search domains or devices">
        <select id="min-risk">
            <option value="0">All risks</option>
            <option value="40">Risk 40+</option>
            <option value="70">Risk 70+</option>
        </select>
        <select id="limit">
            <option value="50">50 rows</option>
            <option value="100" selected>100 rows</option>
            <option value="250">250 rows</option>
        </select>
        <button id="refresh" type="button">Refresh</button>
    </section>
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
                        <th>Confidence</th>
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
    <section class="panel">
        <h2>Action Audit</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Action</th>
                    <th>Status</th>
                    <th>Risk</th>
                    <th>Reason</th>
                    <th>Manage</th>
                </tr>
            </thead>
            <tbody id="actions"></tbody>
        </table>
    </section>
    <section class="panel">
        <h2>Domain Rules</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Decision</th>
                    <th>Source</th>
                    <th>Reason</th>
                    <th>Manage</th>
                </tr>
            </thead>
            <tbody id="rules"></tbody>
        </table>
    </section>
    <section class="panel">
        <h2>Learned Reputation</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Score</th>
                    <th>Confidence</th>
                    <th>Signals</th>
                </tr>
            </thead>
            <tbody id="reputations"></tbody>
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

function button(label, onClick) {
    const item = document.createElement("button");
    item.type = "button";
    item.textContent = label;
    item.addEventListener("click", onClick);
    return item;
}

function actionCell(actions) {
    const td = document.createElement("td");
    const wrapper = document.createElement("div");
    wrapper.className = "inline-actions";
    actions.forEach((action) => wrapper.appendChild(action));
    td.appendChild(wrapper);
    return td;
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
        ["Actions", stats.actions],
        ["Reputations", stats.reputations],
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
            item.confidence,
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

function renderActions(actions) {
    const target = document.getElementById("actions");
    clear(target);
    actions.forEach((action) => {
        const tr = row([
            action.domain,
            action.action,
            action.status,
            action.risk ?? "-",
            action.reason,
        ]);
        tr.appendChild(actionCell([
            button("Allow", () => saveRule(action.domain, "allow")),
            button("Block", () => saveRule(action.domain, "block")),
        ]));
        target.appendChild(tr);
    });
}

function renderRules(rules) {
    const target = document.getElementById("rules");
    clear(target);
    rules.forEach((rule) => {
        const tr = row([
            rule.domain,
            rule.decision,
            rule.source,
            rule.reason,
        ]);
        tr.appendChild(actionCell([
            button("Remove", () => removeRule(rule.domain)),
        ]));
        target.appendChild(tr);
    });
}

function renderReputations(reputations) {
    const target = document.getElementById("reputations");
    clear(target);
    reputations.forEach((reputation) => {
        target.appendChild(row([
            reputation.domain,
            [reputation.score, riskClass(reputation.score)],
            reputation.confidence,
            reputation.signals,
        ]));
    });
}

async function saveRule(domain, decision) {
    await fetch("/api/rules", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            domain,
            decision,
            reason: `Dashboard ${decision}`,
        }),
    });
    await load();
}

async function removeRule(domain) {
    await fetch(`/api/rules/${encodeURIComponent(domain)}`, {
        method: "DELETE",
    });
    await load();
}

async function load() {
    const params = new URLSearchParams();
    const search = document.getElementById("search").value.trim();
    const minRisk = document.getElementById("min-risk").value;
    const limit = document.getElementById("limit").value;

    if (search) params.set("q", search);
    if (minRisk !== "0") params.set("min_risk", minRisk);
    params.set("limit", limit);

    const suffix = `?${params.toString()}`;
    const [stats, events, analysis, devices, actions, rules, reputations] = await Promise.all([
        fetch("/api/stats").then((res) => res.json()),
        fetch(`/api/events${suffix}`).then((res) => res.json()),
        fetch(`/api/analysis${suffix}`).then((res) => res.json()),
        fetch(`/api/devices${suffix}`).then((res) => res.json()),
        fetch(`/api/actions${suffix}`).then((res) => res.json()),
        fetch(`/api/rules${suffix}`).then((res) => res.json()),
        fetch(`/api/reputations${suffix}`).then((res) => res.json()),
    ]);

    renderStats(stats);
    renderEvents(events);
    renderAnalysis(analysis);
    renderDevices(devices);
    renderActions(actions);
    renderRules(rules);
    renderReputations(reputations);
    document.getElementById("updated").textContent =
        new Date().toLocaleTimeString();
}

document.getElementById("refresh").addEventListener("click", load);
document.getElementById("search").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        load();
    }
});
document.getElementById("min-risk").addEventListener("change", load);
document.getElementById("limit").addEventListener("change", load);
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


def parse_limit(
    value: str | None,
    default: int = 100,
    maximum: int = 500,
) -> int:
    """
    Parse and clamp endpoint limit parameters.
    """

    try:
        limit = int(value or default)

    except ValueError:
        return default

    return max(
        1,
        min(limit, maximum),
    )


def parse_int(
    value: str | None,
    default: int = 0,
) -> int:
    """
    Parse integer query parameters.
    """

    try:
        return int(value or default)

    except ValueError:
        return default


def get_recent_events(
    limit: int = 100,
    search: str = "",
    processed: int | None = None,
) -> list[dict[str, Any]]:
    """
    Return recent events with optional filtering.
    """

    where = []
    params: list[Any] = []

    if search:
        where.append("(domain LIKE ? OR device LIKE ?)")
        pattern = f"%{search}%"
        params.extend([pattern, pattern])

    if processed is not None:
        where.append("processed = ?")
        params.append(processed)

    where_sql = ""

    if where:
        where_sql = "WHERE " + " AND ".join(where)

    rows = query_all(
        f"""
        SELECT

            id,
            device,
            domain,
            timestamp,
            processed

        FROM events

        {where_sql}

        ORDER BY id DESC

        LIMIT ?
        """,
        tuple(params + [limit]),
    )

    return [
        row_to_dict(row)
        for row in rows
    ]


def get_recent_analyses(
    limit: int = 100,
    search: str = "",
    min_risk: int = 0,
    category: str = "",
) -> list[dict[str, Any]]:
    """
    Return recent domain analyses for the dashboard/API.
    """

    where = []
    params: list[Any] = []

    if search:
        where.append("domain LIKE ?")
        params.append(f"%{search}%")

    if min_risk > 0:
        where.append("risk >= ?")
        params.append(min_risk)

    if category:
        where.append("category = ?")
        params.append(category)

    where_sql = ""

    if where:
        where_sql = "WHERE " + " AND ".join(where)

    rows = query_all(
        """
        SELECT

            domain,
            risk,
            confidence,
            category,
            reason,
            model,
            analyzed_at

        FROM analysis

        {where_sql}

        ORDER BY analyzed_at DESC

        LIMIT ?
        """.format(where_sql=where_sql),
        tuple(params + [limit]),
    )

    return [
        row_to_dict(row)
        for row in rows
    ]


def get_device_summary(
    limit: int = 100,
    search: str = "",
) -> list[dict[str, Any]]:
    """
    Return per-device event counts.
    """

    where_sql = ""
    params: list[Any] = []

    if search:
        where_sql = "WHERE device LIKE ? OR domain LIKE ?"
        pattern = f"%{search}%"
        params.extend([pattern, pattern])

    rows = query_all(
        """
        SELECT

            device,
            COUNT(*) AS query_count,
            COUNT(DISTINCT domain) AS domain_count,
            SUM(CASE WHEN processed = 1 THEN 1 ELSE 0 END) AS processed_count

        FROM events

        {where_sql}

        GROUP BY device

        ORDER BY query_count DESC

        LIMIT ?
        """.format(where_sql=where_sql),
        tuple(params + [limit]),
    )

    return [
        row_to_dict(row)
        for row in rows
    ]


def get_recent_actions(
    limit: int = 100,
    search: str = "",
    action: str = "",
    status: str = "",
) -> list[dict[str, Any]]:
    """
    Return recent action audit rows for the dashboard/API.
    """

    return [
        row_to_dict(row)
        for row in db_get_recent_actions(
            limit=limit,
            search=search,
            action=action,
            status=status,
        )
    ]


def get_domain_rules(
    limit: int = 100,
    search: str = "",
    decision: str = "",
) -> list[dict[str, Any]]:
    """
    Return active domain rules for the dashboard/API.
    """

    return load_domain_rules(
        limit=limit,
        search=search,
        decision=decision,
    )


def get_reputations(
    limit: int = 100,
    search: str = "",
    min_score: int = 0,
) -> list[dict[str, Any]]:
    """
    Return learned reputation rows for the dashboard/API.
    """

    return load_reputations(
        limit=limit,
        search=search,
        min_score=min_score,
    )


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
        processed_arg = request.args.get("processed")
        processed = None

        if processed_arg in {"0", "1"}:
            processed = int(processed_arg)

        return jsonify(
            get_recent_events(
                limit=parse_limit(request.args.get("limit")),
                search=request.args.get("q", "").strip(),
                processed=processed,
            )
        )

    @app.get("/api/analysis")
    def analysis():
        return jsonify(
            get_recent_analyses(
                limit=parse_limit(request.args.get("limit")),
                search=request.args.get("q", "").strip(),
                min_risk=parse_int(request.args.get("min_risk")),
                category=request.args.get("category", "").strip(),
            )
        )

    @app.get("/api/devices")
    def devices():
        return jsonify(
            get_device_summary(
                limit=parse_limit(request.args.get("limit")),
                search=request.args.get("q", "").strip(),
            )
        )

    @app.get("/api/actions")
    def actions():
        return jsonify(
            get_recent_actions(
                limit=parse_limit(request.args.get("limit")),
                search=request.args.get("q", "").strip(),
                action=request.args.get("action", "").strip(),
                status=request.args.get("status", "").strip(),
            )
        )

    @app.get("/api/rules")
    def rules():
        return jsonify(
            get_domain_rules(
                limit=parse_limit(request.args.get("limit")),
                search=request.args.get("q", "").strip(),
                decision=request.args.get("decision", "").strip(),
            )
        )

    @app.get("/api/reputations")
    def reputations():
        return jsonify(
            get_reputations(
                limit=parse_limit(request.args.get("limit")),
                search=request.args.get("q", "").strip(),
                min_score=parse_int(request.args.get("min_score")),
            )
        )

    @app.post("/api/rules")
    def create_rule():
        payload = request.get_json(silent=True) or {}
        domain = str(payload.get("domain", "")).strip()
        decision = str(payload.get("decision", "")).strip()
        reason = str(payload.get("reason", "")).strip()
        apply_block = bool(payload.get("apply", False))

        if not domain:
            return jsonify({"error": "domain is required"}), 400

        if decision not in {"allow", "block"}:
            return jsonify({"error": "decision must be allow or block"}), 400

        add_rule(
            domain=domain,
            decision=decision,
            reason=reason,
            apply_block=apply_block,
        )

        return jsonify(
            {
                "domain": domain,
                "decision": decision,
                "status": "saved",
            }
        )

    @app.delete("/api/rules/<path:domain>")
    def delete_rule(domain: str):
        removed = remove_rule(
            domain,
        )

        return jsonify(
            {
                "domain": domain,
                "removed": removed,
            }
        )

    @app.get("/api/health")
    def health():
        include_ollama = request.args.get("ollama") in {
            "1",
            "true",
            "yes",
        }

        return jsonify(
            collect_status(
                include_ollama=include_ollama,
            )
        )

    @app.get("/data")
    def legacy_data():
        return jsonify(
            get_device_summary(
                limit=parse_limit(request.args.get("limit")),
                search=request.args.get("q", "").strip(),
            )
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
