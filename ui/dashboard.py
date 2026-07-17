from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    current_app,
    g,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

from core.config import CONFIG_FILE, settings
from core.db import (
    database_stats_readonly as database_stats,
    decision_metrics as db_decision_metrics,
    get_recent_actions as db_get_recent_actions,
    list_intel_source_status,
    query_all_readonly,
    readonly_database,
    threat_intel_diagnostics,
    threat_intel_stats,
)
from core.logger import get_logger
from pihole_ai.explain import (
    compare_domain_decisions,
    decision_history,
    explain_domain,
    is_valid_domain_query,
)
from pihole_ai.calibration import reliability_metrics
from pihole_ai.feedback import FEEDBACK_VERDICTS, record_feedback
from pihole_ai.learn import get_reputations as load_reputations
from pihole_ai.rules import (
    add_rule,
    get_rules as load_domain_rules,
    remove_rule,
)
from pihole_ai.setup import evaluate_setup
from pihole_ai.status import collect_status


logger = get_logger(__name__)
BRANDING_DIR = Path(__file__).resolve().parent.parent / "assets" / "branding"

MAX_CONTENT_LENGTH = 32 * 1024
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW_SECONDS = 300
LOGIN_LOCKOUT_SECONDS = 300
MAX_LOGIN_FAILURE_RECORDS = 512
AUTH_SESSION_KEY = "authenticated"
CSRF_SESSION_KEY = "csrf_token"
LOGIN_FAILURES: dict[tuple[str, str], list[float]] = {}

ROUTE_SECURITY = {
    "GET /login": "public",
    "POST /login": "public_state_changing_csrf",
    "GET /live": "public_liveness",
    "GET /": "authenticated_read",
    "GET /api/stats": "authenticated_read",
    "GET /api/polling": "authenticated_read",
    "GET /api/settings": "authenticated_read",
    "GET /api/setup": "authenticated_read",
    "POST /api/settings": "authenticated_write_csrf",
    "POST /api/services/<action>": "authenticated_write_csrf",
    "GET /api/metrics/decisions": "authenticated_read",
    "GET /api/events": "authenticated_read",
    "GET /api/analysis": "authenticated_read",
    "GET /api/devices": "authenticated_read",
    "GET /api/actions": "authenticated_read",
    "GET /api/rules": "authenticated_read",
    "GET /api/reputations": "authenticated_read",
    "GET /api/intel/sources": "authenticated_read",
    "GET /api/intel/stats": "authenticated_read",
    "GET /api/explain/<domain>": "authenticated_read",
    "GET /api/explain/<domain>/history": "authenticated_read",
    "GET /api/explain/<domain>/decision/<decision_id>": "authenticated_read",
    "GET /api/explain/<domain>/compare": "authenticated_read",
    "GET /api/reliability": "authenticated_read",
    "POST /api/feedback": "authenticated_write_csrf",
    "POST /api/rules": "authenticated_write_csrf",
    "DELETE /api/rules/<domain>": "authenticated_write_csrf",
    "GET /api/status": "authenticated_read",
    "GET /api/health": "authenticated_read",
    "GET /data": "authenticated_read",
    "POST /logout": "authenticated_write_csrf",
}

SETTINGS_ENV_PATH = CONFIG_FILE

AI_SETTING_KEYS = {
    "ai_enabled": "AI_ENABLED",
    "ai_max_calls_per_minute": "AI_MAX_CALLS_PER_MINUTE",
    "ai_cooldown_seconds": "AI_COOLDOWN_SECONDS",
    "ai_timeout_seconds": "AI_TIMEOUT_SECONDS",
}

DASHBOARD_SETTING_KEYS = {
    "dashboard_refresh_interval_ms": "PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS",
    "dev_access_logs": "DEV_ACCESS_LOGS",
}

LOGIN_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PiHole-AI Login</title>
<link rel="icon" href="{{ url_for('branding_asset', filename='favicon.ico') }}">
<link rel="manifest" href="{{ url_for('branding_asset', filename='site.webmanifest') }}">
<style nonce="__CSP_NONCE__">
:root { color-scheme: dark; }
body {
    align-items: center;
    background: #0f1113;
    color: #f2f4f5;
    display: flex;
    font-family: Arial, sans-serif;
    min-height: 100vh;
    margin: 0;
    padding: 18px;
}
.login {
    background: #1a1f23;
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 10px;
    display: grid;
    gap: 14px;
    margin: auto;
    max-width: 360px;
    padding: 20px;
    width: 100%;
}
.login-logo {
    height: 46px;
    width: auto;
}
h1 { font-size: 22px; margin: 0; }
p { color: #aab2bb; margin: 0; }
label { display: grid; gap: 6px; }
input {
    background: #161a1e;
    border: 1px solid #2b3238;
    border-radius: 6px;
    color: #f2f4f5;
    min-height: 38px;
    padding: 8px 10px;
}
button {
    background: #58c4a7;
    border: 0;
    border-radius: 6px;
    color: #06110d;
    font-weight: 700;
    min-height: 38px;
    padding: 8px 12px;
}
.error { color: #e86969; min-height: 18px; }
</style>
</head>
<body>
<form class="login" method="post" action="/login" autocomplete="on">
    <img class="login-logo" src="{{ url_for('branding_asset', filename='logo-transparent.png') }}" alt="PiHole-AI logo">
    <h1>PiHole-AI</h1>
    <p>Sign in to the companion appliance.</p>
    <input type="hidden" name="csrf_token" value="__CSRF_TOKEN__">
    <input type="hidden" name="next" value="__NEXT__">
    <label>
        Username
        <input name="username" type="text" autocomplete="username" required>
    </label>
    <label>
        Password
        <input name="password" type="password" autocomplete="current-password" required>
    </label>
    <div class="error">__ERROR__</div>
    <button type="submit">Sign in</button>
</form>
</body>
</html>
"""


HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PiHole-AI</title>
<link rel="icon" href="{{ url_for('branding_asset', filename='favicon.ico') }}">
<link rel="manifest" href="{{ url_for('branding_asset', filename='site.webmanifest') }}">
<meta name="csrf-token" content="__CSRF_TOKEN__">
<style nonce="__CSP_NONCE__">
:root {
    color-scheme: dark;
    --bg: #0f1113;
    --sidebar: #15191d;
    --panel: #1a1f23;
    --panel-soft: #161a1e;
    --line: #2b3238;
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

.layout {
    display: grid;
    grid-template-columns: 220px minmax(0, 1fr);
    min-height: 100vh;
}

.sidebar {
    background: var(--sidebar);
    border-right: 1px solid var(--line);
    display: flex;
    flex-direction: column;
    gap: 18px;
    padding: 18px 14px;
    position: sticky;
    top: 0;
    height: 100vh;
}

.brand {
    align-items: center;
    display: grid;
    gap: 4px;
    padding: 4px 4px 10px;
}

.brand-logo {
    height: 46px;
    width: auto;
}

.brand strong {
    font-size: 20px;
}

.brand span {
    color: var(--muted);
    font-size: 12px;
}

.side-nav {
    display: grid;
    gap: 6px;
}

.nav-link {
    align-items: center;
    display: flex;
    background: transparent;
    border: 0;
    border-radius: 8px;
    color: var(--muted);
    cursor: pointer;
    font: inherit;
    min-height: 38px;
    padding: 8px 10px;
    text-align: left;
}

.nav-link.active {
    background: var(--panel);
    color: var(--text);
}

.nav-link:hover {
    color: var(--text);
}

.workspace {
    min-width: 0;
}

header {
    align-items: center;
    display: flex;
    gap: 16px;
    justify-content: space-between;
    padding: 18px 22px 0;
}

.userbar {
    align-items: center;
    display: flex;
    gap: 10px;
}

.logout-button {
    background: transparent;
    border: 1px solid var(--line);
    border-radius: 6px;
    color: var(--text);
    min-height: 32px;
    padding: 5px 9px;
}

h1 {
    font-size: 20px;
    font-weight: 700;
    margin: 0;
}

main {
    display: grid;
    gap: 16px;
    grid-template-columns: minmax(0, 1fr) 360px;
    padding: 16px 22px 22px;
}

.topbar {
    align-items: center;
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    justify-content: space-between;
}

.content {
    display: grid;
    gap: 16px;
    min-width: 0;
}

.tab-panel {
    display: none;
}

.tab-panel.active {
    display: grid;
    gap: 16px;
}

.details {
    align-self: start;
    position: sticky;
    top: 16px;
}

.stats {
    display: grid;
    gap: 12px;
    grid-template-columns: repeat(4, minmax(120px, 1fr));
}

.metrics {
    display: grid;
    gap: 12px;
    grid-template-columns: repeat(4, minmax(0, 1fr));
}

.stat,
.panel {
    background: var(--panel);
    border: 1px solid rgba(255, 255, 255, 0.04);
    border-radius: 10px;
}

.stat {
    padding: 12px;
}

.metric {
    padding: 12px;
}

.metric h3 {
    font-size: 13px;
    margin: 0 0 10px;
}

.metric-row {
    align-items: center;
    border-top: 1px solid rgba(255, 255, 255, 0.05);
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 7px 0;
}

.metric-row:first-of-type {
    border-top: 0;
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
    background: var(--panel-soft);
    border: 1px solid var(--line);
    border-radius: 6px;
    color: var(--text);
    min-height: 36px;
    padding: 7px 10px;
}

input {
    min-width: min(360px, 100%);
}

.search-wrap {
    flex: 1 1 280px;
}

.search-wrap input {
    width: 100%;
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

.summary-text {
    color: var(--muted);
    line-height: 1.5;
    padding: 14px;
}

.settings-form {
    display: grid;
    gap: 14px;
    padding: 12px;
}

.settings-group {
    background: var(--panel-soft);
    border-radius: 8px;
    display: grid;
    gap: 10px;
    padding: 12px;
}

.settings-row {
    align-items: center;
    display: grid;
    gap: 10px;
    grid-template-columns: minmax(160px, 1fr) minmax(120px, 180px);
}

.settings-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}

.settings-actions button,
.settings-form button {
    background: transparent;
    border: 1px solid var(--line);
    border-radius: 6px;
    color: var(--text);
    min-height: 32px;
    padding: 6px 10px;
}

.settings-form button.primary {
    background: var(--accent);
    border: 0;
    color: #06110d;
    font-weight: 700;
}

.settings-message {
    color: var(--muted);
    padding: 0 12px 12px;
}

.inline-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}

.inline-actions button,
.explain-feedback button {
    background: transparent;
    border: 1px solid var(--line);
    border-radius: 6px;
    color: var(--text);
    min-height: 30px;
    padding: 5px 8px;
}

.badge {
    border-radius: 999px;
    display: inline-flex;
    font-size: 12px;
    font-weight: 700;
    line-height: 1;
    padding: 5px 8px;
}

.badge.risk-low {
    background: rgba(88, 196, 167, 0.14);
}

.badge.risk-mid {
    background: rgba(231, 183, 95, 0.14);
}

.badge.risk-high {
    background: rgba(232, 105, 105, 0.14);
}

.inline-actions button:hover,
.explain-feedback button:hover {
    border-color: var(--accent);
}

.domain-link {
    background: transparent;
    border: 0;
    color: var(--text);
    cursor: pointer;
    font: inherit;
    padding: 0;
    text-align: left;
}

.domain-link:hover {
    color: var(--accent);
}

.explain-grid {
    display: grid;
    gap: 12px;
    grid-template-columns: minmax(0, 1fr);
    padding: 12px;
}

.explain-feedback {
    align-items: center;
    border-bottom: 1px solid var(--line);
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    padding: 12px;
}

.explain-feedback strong {
    margin-right: 4px;
}

.explain-item {
    background: var(--panel-soft);
    border-radius: 8px;
    padding: 10px;
}

.explain-item strong {
    display: block;
    margin-bottom: 6px;
}

.explain-item pre {
    color: var(--muted);
    font-family: inherit;
    margin: 0;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
}

.explain-section {
    background: var(--panel-soft);
    border-radius: 8px;
    display: grid;
    gap: 8px;
    padding: 10px;
}

.explain-section h3 {
    font-size: 13px;
    margin: 0;
}

.decision-summary {
    display: grid;
    gap: 6px;
}

.decision-metrics,
.trace-row,
.evidence-card {
    display: grid;
    gap: 6px;
}

.decision-metrics {
    grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
}

.metric-chip {
    color: var(--muted);
    font-size: 12px;
}

.metric-chip strong {
    color: var(--text);
    display: block;
    font-size: 14px;
}

.evidence-card {
    border-left: 3px solid var(--line);
    padding: 8px 0 8px 10px;
}

.evidence-card.decisive {
    border-left-color: var(--accent);
}

.history-row {
    width: 100%;
    border: 0;
    border-bottom: 1px solid var(--line);
    background: transparent;
    color: var(--text);
    padding: 9px 0;
    text-align: left;
    cursor: pointer;
}

.history-row:hover {
    color: var(--accent);
}

.evidence-meta,
.trace-meta {
    color: var(--muted);
    font-size: 12px;
}

.evidence-details summary {
    color: var(--muted);
    cursor: pointer;
    font-size: 12px;
}

.explain-message {
    color: var(--muted);
    padding: 12px;
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
    font-size: 15px;
    margin: 0;
    padding: 12px;
}

.panel-title {
    align-items: center;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    display: flex;
    gap: 10px;
    justify-content: space-between;
    padding: 12px;
}

.panel-title h2 {
    border-bottom: 0;
    padding: 0;
}

.empty {
    color: var(--muted);
    padding: 18px 12px;
}

.setup-banner {
    background: rgba(231, 183, 95, 0.12);
    border: 1px solid rgba(231, 183, 95, 0.22);
    border-radius: 10px;
    display: none;
    gap: 10px;
    padding: 12px;
}

.setup-banner.ready {
    background: rgba(88, 196, 167, 0.12);
    border-color: rgba(88, 196, 167, 0.22);
}

.setup-banner.blocked {
    background: rgba(232, 105, 105, 0.12);
    border-color: rgba(232, 105, 105, 0.22);
}

.setup-steps {
    display: grid;
    gap: 8px;
    padding: 12px;
}

.setup-step {
    background: var(--panel-soft);
    border-radius: 8px;
    display: grid;
    gap: 4px;
    padding: 10px;
}

.setup-step-header {
    align-items: center;
    display: flex;
    gap: 8px;
    justify-content: space-between;
}

.timeline {
    display: grid;
    gap: 10px;
    padding: 12px;
}

.timeline-item {
    background: var(--panel-soft);
    border-radius: 8px;
    display: grid;
    gap: 6px;
    padding: 10px;
}

.timeline-meta {
    color: var(--muted);
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    font-size: 12px;
}

table {
    border-collapse: collapse;
    width: 100%;
}

td,
th {
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
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
    .layout {
        grid-template-columns: minmax(0, 1fr);
    }

    .sidebar {
        border-bottom: 1px solid var(--line);
        border-right: 0;
        height: auto;
        overflow-x: auto;
        position: static;
    }

    .side-nav {
        grid-auto-flow: column;
        grid-auto-columns: max-content;
        overflow-x: auto;
    }

    main,
    .stats,
    .metrics,
    .grid,
    .explain-grid {
        grid-template-columns: minmax(0, 1fr);
    }

    .details {
        position: static;
    }

    .settings-row {
        grid-template-columns: minmax(0, 1fr);
    }
}
</style>
</head>
<body>
<div class="layout">
<aside class="sidebar">
    <div class="brand">
        <img class="brand-logo" src="{{ url_for('branding_asset', filename='logo-transparent.png') }}" alt="PiHole-AI logo">
        <strong>PiHole-AI</strong>
        <span>Companion appliance</span>
    </div>
    <nav class="side-nav" aria-label="Dashboard sections">
        <button class="nav-link active" type="button" data-page="overview">Overview</button>
        <button class="nav-link" type="button" data-page="activity">Activity</button>
        <button class="nav-link" type="button" data-page="domains">Domains</button>
        <button class="nav-link" type="button" data-page="devices">Devices</button>
        <button class="nav-link" type="button" data-page="intelligence">Intelligence</button>
        <button class="nav-link" type="button" data-page="reliability">Reliability</button>
        <button class="nav-link" type="button" data-page="rules">Rules</button>
        <button class="nav-link" type="button" data-page="settings">Settings</button>
    </nav>
</aside>
<div class="workspace">
<header>
    <h1 id="page-title">Overview</h1>
    <div class="userbar">
        <span class="muted" id="updated">-</span>
        <span class="muted" id="logged-in-user">__USERNAME__</span>
        <button class="logout-button" id="logout" type="button">Logout</button>
    </div>
</header>
<main>
    <div class="content">
        <section class="topbar">
            <section class="toolbar">
                <div class="search-wrap">
                    <input id="search" type="search" placeholder="Search domains or devices">
                </div>
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
        </section>

        <section class="setup-banner" id="setup-banner"></section>

        <section class="tab-panel active" id="page-overview">
            <section class="panel" id="setup-panel">
                <div class="panel-title">
                    <h2>Setup</h2>
                    <span class="muted">Derived from live state</span>
                </div>
                <div class="setup-steps" id="setup-steps"></div>
            </section>
            <section class="stats" id="stats"></section>
            <section class="metrics" id="service-status"></section>
            <section class="panel">
                <div class="panel-title">
                    <h2>Network Summary</h2>
                    <span class="muted">Live view</span>
                </div>
                <div class="summary-text" id="network-summary"></div>
            </section>
            <section class="panel">
                <div class="panel-title">
                    <h2>Recent High-Risk Domains</h2>
                    <span class="muted">Risk 70+</span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Risk</th>
                            <th>Confidence</th>
                            <th>Category</th>
                        </tr>
                    </thead>
                    <tbody id="overview-high-risk"></tbody>
                </table>
            </section>
        </section>

        <section class="tab-panel" id="page-activity">
            <section class="panel">
                <div class="panel-title">
                    <h2>Activity Timeline</h2>
                    <span class="muted">Events, analysis, and actions</span>
                </div>
                <div class="timeline" id="activity"></div>
            </section>
        </section>

        <section class="tab-panel" id="page-domains">
            <section class="panel">
                <h2>Domains</h2>
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
                <div class="empty" id="reputations-empty">No reputation data yet</div>
            </section>
        </section>

        <section class="tab-panel" id="page-devices">
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
        </section>

        <section class="tab-panel" id="page-intelligence">
            <section class="metrics" id="intelligence-cards"></section>
            <section class="panel">
                <div class="panel-title">
                    <h2>Classifier Contribution</h2>
                    <span class="muted">Models and local classifiers</span>
                </div>
                <section class="metrics" id="decision-metrics"></section>
            </section>
        </section>

        <section class="tab-panel" id="page-reliability">
            <section class="metrics" id="reliability-summary"></section>
            <section class="panel">
                <div class="panel-title">
                    <h2>Confidence</h2>
                    <span class="muted">Reporting only</span>
                </div>
                <section class="metrics" id="reliability-confidence"></section>
                <div class="empty" id="calibration-empty">No active calibration profile yet</div>
            </section>
            <section class="panel">
                <div class="panel-title">
                    <h2>Errors</h2>
                    <span class="muted">From benchmark labels and telemetry</span>
                </div>
                <section class="metrics" id="reliability-errors"></section>
            </section>
            <section class="panel">
                <div class="panel-title">
                    <h2>Utilization</h2>
                    <span class="muted">Classifiers, models, prompts</span>
                </div>
                <section class="metrics" id="reliability-utilization"></section>
            </section>
            <section class="panel">
                <div class="panel-title">
                    <h2>Benchmark History</h2>
                    <span class="muted">Recent persisted runs</span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Run</th>
                            <th>Status</th>
                            <th>Samples</th>
                            <th>Accuracy</th>
                            <th>F1</th>
                            <th>Fixture</th>
                        </tr>
                    </thead>
                    <tbody id="benchmark-history"></tbody>
                </table>
                <div class="empty" id="benchmark-empty">No benchmark runs yet</div>
            </section>
        </section>

        <section class="tab-panel" id="page-rules">
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
                <div class="empty" id="rules-empty">No rules yet</div>
            </section>
        </section>

        <section class="tab-panel" id="page-settings">
            <section class="panel">
                <h2>Settings</h2>
                <div class="settings-form">
                    <div class="settings-group">
                        <strong>Service control</strong>
                        <div class="settings-actions">
                            <button type="button" data-service-action="start">Start engine</button>
                            <button type="button" data-service-action="stop">Stop engine</button>
                            <button type="button" data-service-action="restart">Restart all services</button>
                            <button type="button" id="service-status-button">View service status</button>
                        </div>
                    </div>
                    <div class="settings-group">
                        <strong>AI settings</strong>
                        <label class="settings-row">
                            <span>AI enabled</span>
                            <input id="setting-ai-enabled" type="checkbox">
                        </label>
                        <label class="settings-row">
                            <span>Max calls per minute</span>
                            <input id="setting-ai-max-calls" type="number" min="0" step="1">
                        </label>
                        <label class="settings-row">
                            <span>Cooldown seconds</span>
                            <input id="setting-ai-cooldown" type="number" min="0" step="1">
                        </label>
                        <label class="settings-row">
                            <span>Timeout seconds</span>
                            <input id="setting-ai-timeout" type="number" min="1" step="1">
                        </label>
                    </div>
                    <div class="settings-group">
                        <strong>Dashboard settings</strong>
                        <label class="settings-row">
                            <span>Refresh interval</span>
                            <input id="setting-refresh" type="number" min="1000" step="1000">
                        </label>
                        <label class="settings-row">
                            <span>Access logs / dev logs</span>
                            <input id="setting-dev-logs" type="checkbox">
                        </label>
                    </div>
                    <div class="settings-actions">
                        <button class="primary" id="save-settings" type="button">Save settings</button>
                        <button id="restart-required" type="button">Restart required</button>
                    </div>
                </div>
                <div class="settings-message" id="settings-message"></div>
                <div class="explain-grid" id="settings-summary"></div>
                <div class="empty" id="threat-intel-empty">No threat intel imported yet</div>
            </section>
        </section>
    </div>

    <aside class="panel details">
        <h2>Explain</h2>
        <div class="explain-feedback" id="explain-feedback"></div>
        <div class="explain-grid" id="explain"></div>
    </aside>
</main>
</div>
</div>
<script nonce="__CSP_NONCE__">
const csrfToken = document.querySelector("meta[name='csrf-token']")?.content ?? "";
const text = (value) => String(value ?? "-");

function csrfHeaders(extra = {}) {
    return {
        ...extra,
        "X-CSRF-Token": csrfToken,
    };
}

async function checkedFetch(url, options = {}) {
    const response = await fetch(url, options);
    if (response.status === 401) {
        window.location.href = "/login";
        throw new Error("authentication required");
    }
    if (response.status === 403) {
        settingsMessage("Security token expired. Refresh the page and try again.");
        throw new Error("csrf failed");
    }
    return response;
}

function clear(node) {
    if (!node) return;
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

function riskCell(risk) {
    const td = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge ${riskClass(Number(risk) || 0)}`;
    badge.textContent = text(risk);
    td.appendChild(badge);
    return td;
}

function domainButton(domain) {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "domain-link";
    item.textContent = text(domain);
    item.addEventListener("click", () => explainDomain(domain));
    return item;
}

function domainCell(domain) {
    const td = document.createElement("td");
    td.appendChild(domainButton(domain));
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

function formatTime(value) {
    const numeric = Number(value ?? 0);
    if (!numeric) return "-";
    return new Date(numeric * 1000).toLocaleString();
}

function emptyState(id, show) {
    const target = document.getElementById(id);
    if (target) {
        target.style.display = show ? "block" : "none";
    }
}

function renderKeyValue(target, values) {
    clear(target);
    values.forEach(([label, value]) => {
        const item = document.createElement("div");
        item.className = "explain-item";

        const heading = document.createElement("strong");
        heading.textContent = label;

        const body = document.createElement("pre");
        body.textContent = text(value);

        item.append(heading, body);
        target.appendChild(item);
    });
}

function renderStats(stats) {
    const target = document.getElementById("stats");
    clear(target);

    [
        ["Health", "Online"],
        ["Processed", `${stats.processed ?? 0} / ${stats.events ?? 0}`],
        ["Domains", stats.domains],
        ["Reputation", stats.reputations ?? 0],
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

function setupBadgeClass(status) {
    if (status === "complete" || status === "skipped") return "risk-low";
    if (status === "blocked") return "risk-high";
    return "risk-mid";
}

function renderSetup(report) {
    const banner = document.getElementById("setup-banner");
    const stepsTarget = document.getElementById("setup-steps");
    clear(banner);
    clear(stepsTarget);

    banner.style.display = "grid";
    banner.classList.toggle("ready", Boolean(report.ready));
    banner.classList.toggle("blocked", report.overall_stage === "blocked");

    const title = document.createElement("strong");
    title.textContent = report.ready && report.has_warnings
        ? "Setup complete with warnings"
        : report.ready
        ? "Setup complete"
        : `Setup needs attention: ${text(report.overall_stage)}`;
    const body = document.createElement("span");
    body.className = "muted";
    body.textContent = report.ready && report.has_warnings
        ? "PiHole-AI is operational; review recommended configuration warnings."
        : report.ready
        ? "The dashboard is using live appliance state."
        : "Diagnostics remain available while you finish setup from the CLI.";
    banner.append(title, body);

    (report.steps ?? []).forEach((step) => {
        const item = document.createElement("div");
        item.className = "setup-step";

        const header = document.createElement("div");
        header.className = "setup-step-header";
        const name = document.createElement("strong");
        name.textContent = step.title;
        const badge = document.createElement("span");
        badge.className = `badge ${setupBadgeClass(step.status)}`;
        badge.textContent = step.status;
        header.append(name, badge);

        const summary = document.createElement("span");
        summary.className = "muted";
        summary.textContent = step.summary;
        item.append(header, summary);

        if (step.remediation) {
            const remediation = document.createElement("span");
            remediation.className = "muted";
            remediation.textContent = step.remediation;
            item.appendChild(remediation);
        }
        stepsTarget.appendChild(item);
    });
}

function renderServiceStatus(status) {
    const target = document.getElementById("service-status");
    clear(target);
    const database = status.database ?? {};
    const collector = status.collector ?? {};
    const ai = status.ai ?? {};
    const config = status.config ?? {};

    target.appendChild(metricPanel("Service", [
        ["Events DB", config.events_db ?? "-"],
        ["Pi-hole DB", config.pihole_db ?? "-"],
        ["Collector ID", collector.last_query_id ?? "0"],
    ]));
    target.appendChild(metricPanel("AI Status", [
        ["Enabled", config.ai_enabled],
        ["Calls", ai.ai_calls ?? 0],
        ["Skipped", ai.ai_skipped ?? 0],
        ["Timeouts", ai.ai_timeouts ?? 0],
    ]));
    target.appendChild(metricPanel("Processing", [
        ["Events", database.events ?? 0],
        ["Processed", database.processed ?? 0],
        ["Domains", database.domains ?? 0],
        ["Analyses", database.analyses ?? 0],
    ]));
}

function renderNetworkSummary(status) {
    const target = document.getElementById("network-summary");
    const database = status.database ?? {};
    const ai = status.ai ?? {};
    const processed = database.processed ?? 0;
    const events = database.events ?? 0;
    const domains = database.domains ?? 0;
    const skipped = ai.ai_skipped ?? 0;

    target.textContent =
        `${processed} of ${events} DNS events have been processed across ` +
        `${domains} observed domains. AI fallback has made ${ai.ai_calls ?? 0} ` +
        `call(s) and skipped ${skipped} request(s) to keep the appliance responsive.`;
}

function metricPanel(title, rows) {
    const item = document.createElement("div");
    item.className = "panel metric";

    const heading = document.createElement("h3");
    heading.textContent = title;
    item.appendChild(heading);

    rows.forEach(([label, value]) => {
        const row = document.createElement("div");
        row.className = "metric-row";

        const labelNode = document.createElement("span");
        labelNode.className = "muted";
        labelNode.textContent = label;

        const valueNode = document.createElement("strong");
        valueNode.textContent = text(value);

        row.append(labelNode, valueNode);
        item.appendChild(row);
    });

    return item;
}

function formatPercent(value) {
    if (value === null || value === undefined) return "-";
    return `${(Number(value) * 100).toFixed(1)}%`;
}

function objectRows(values) {
    const entries = Object.entries(values ?? {});

    if (!entries.length) {
        return [["None", 0]];
    }

    return entries;
}

function renderReliability(payload) {
    const summary = payload.summary ?? {};
    const confidence = payload.confidence ?? {};
    const errors = payload.errors ?? {};
    const utilization = payload.utilization ?? {};
    const diagnostics = payload.diagnostics ?? {};
    const profiles = payload.calibration_profiles ?? [];
    const history = payload.benchmark_history ?? [];

    const summaryTarget = document.getElementById("reliability-summary");
    clear(summaryTarget);
    summaryTarget.appendChild(metricPanel("Telemetry", [
        ["Coverage", formatPercent(summary.telemetry_coverage_rate)],
        ["AI Invocation", formatPercent(summary.ai_invocation_rate)],
        ["Cache Hit", formatPercent(summary.cache_hit_rate)],
    ]));
    summaryTarget.appendChild(metricPanel("Latency", [
        ["Average", summary.average_latency_ms == null ? "-" : `${Number(summary.average_latency_ms).toFixed(1)}ms`],
        ["P95", summary.p95_latency_ms == null ? "-" : `${summary.p95_latency_ms}ms`],
    ]));
    summaryTarget.appendChild(metricPanel("Calibration", [
        ["Active Profiles", summary.active_calibration_profiles ?? 0],
        ["Profiles", diagnostics.calibration_profile_count ?? profiles.length],
        ["Benchmark Runs", summary.benchmark_runs ?? 0],
    ]));

    const confidenceTarget = document.getElementById("reliability-confidence");
    clear(confidenceTarget);
    confidenceTarget.appendChild(metricPanel("Raw Distribution", objectRows(confidence.raw_distribution)));
    confidenceTarget.appendChild(metricPanel("Calibrated Distribution", objectRows(confidence.calibrated_distribution)));
    confidenceTarget.appendChild(metricPanel("Calibration Error", [
        ["ECE", confidence.expected_calibration_error == null ? "-" : Number(confidence.expected_calibration_error).toFixed(4)],
        ["Brier", confidence.brier_score == null ? "-" : Number(confidence.brier_score).toFixed(4)],
    ]));
    emptyState("calibration-empty", (summary.active_calibration_profiles ?? 0) === 0);

    const errorTarget = document.getElementById("reliability-errors");
    clear(errorTarget);
    errorTarget.appendChild(metricPanel("Benchmark Errors", [
        ["False Positives", errors.false_positive_count ?? 0],
        ["False Negatives", errors.false_negative_count ?? 0],
        ["Abstention Rate", formatPercent(errors.abstention_rate)],
    ]));
    errorTarget.appendChild(metricPanel("AI Runtime Errors", [
        ["Parse Failures", errors.parse_failures ?? 0],
        ["Timeouts", errors.timeouts ?? 0],
        ["Incomplete Telemetry", diagnostics.incomplete_telemetry_runs ?? 0],
    ]));

    const utilizationTarget = document.getElementById("reliability-utilization");
    clear(utilizationTarget);
    utilizationTarget.appendChild(metricPanel("Classifiers", objectRows(utilization.classifier_counts)));
    utilizationTarget.appendChild(metricPanel("Models", objectRows(utilization.model_counts)));
    utilizationTarget.appendChild(metricPanel("Prompts", objectRows(utilization.prompt_version_counts)));

    const historyTarget = document.getElementById("benchmark-history");
    clear(historyTarget);
    emptyState("benchmark-empty", history.length === 0);
    history.forEach((run) => {
        const metrics = run.metrics ?? {};
        historyTarget.appendChild(row([
            run.run_id,
            run.status,
            run.sample_count,
            formatPercent(metrics.accuracy),
            metrics.f1 == null ? "-" : Number(metrics.f1).toFixed(3),
            String(run.fixture_digest ?? "").slice(0, 12),
        ]));
    });
}

function renderDecisionMetrics(metrics) {
    const target = document.getElementById("decision-metrics");
    clear(target);

    target.appendChild(metricPanel("Risk Bands", [
        ["Low", metrics.analysis.low_risk],
        ["Medium", metrics.analysis.medium_risk],
        ["High", metrics.analysis.high_risk],
        ["Retry", metrics.analysis.zero_confidence],
    ]));
    target.appendChild(metricPanel(
        "Categories",
        objectRows(metrics.categories)
    ));
    target.appendChild(metricPanel(
        "Classifiers",
        objectRows(metrics.models)
    ));
    target.appendChild(metricPanel(
        "Actions",
        objectRows(metrics.actions.by_action)
    ));
}

function renderEvents(events) {
    const target = document.getElementById("events");
    clear(target);
    events.forEach((event) => {
        const tr = row([
            event.device,
            event.processed ? "yes" : "no",
        ]);
        tr.insertBefore(domainCell(event.domain), tr.children[1]);
        target.appendChild(tr);
    });
}

function renderAnalysis(items, targetId = "analysis") {
    const target = document.getElementById(targetId);
    clear(target);
    items.forEach((item) => {
        const tr = row([item.confidence, item.category]);
        tr.insertBefore(domainCell(item.domain), tr.firstChild);
        tr.insertBefore(riskCell(item.risk), tr.children[1]);
        target.appendChild(tr);
    });
}

function renderActivity(events, analysis, actions) {
    const target = document.getElementById("activity");
    clear(target);
    const items = [];

    events.forEach((event) => items.push({
        type: "DNS event",
        domain: event.domain,
        source: event.device,
        detail: event.processed ? "processed" : "pending",
        risk: null,
        time: event.timestamp ?? 0,
    }));
    analysis.forEach((item) => items.push({
        type: "Analysis",
        domain: item.domain,
        source: item.model,
        detail: `${item.category} risk ${item.risk}`,
        risk: item.risk,
        time: item.analyzed_at ?? 0,
    }));
    actions.forEach((action) => items.push({
        type: "Action",
        domain: action.domain,
        source: action.source,
        detail: `${action.action} ${action.status}`,
        risk: action.risk,
        time: action.created_at ?? 0,
    }));

    items.sort((a, b) => b.time - a.time);
    items.slice(0, 40).forEach((item) => {
        const wrapper = document.createElement("div");
        wrapper.className = "timeline-item";

        const title = document.createElement("div");
        title.appendChild(domainButton(item.domain));

        const meta = document.createElement("div");
        meta.className = "timeline-meta";
        [
            item.type,
            item.detail,
            `source ${text(item.source)}`,
            item.risk == null ? "" : `risk ${item.risk}`,
        ].filter(Boolean).forEach((value) => {
            const span = document.createElement("span");
            span.textContent = value;
            meta.appendChild(span);
        });

        wrapper.append(title, meta);
        target.appendChild(wrapper);
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
            action.action,
            action.status,
            action.risk ?? "-",
            action.reason,
        ]);
        tr.insertBefore(domainCell(action.domain), tr.firstChild);
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
    emptyState("rules-empty", rules.length === 0);
    rules.forEach((rule) => {
        const tr = row([
            rule.decision,
            rule.source,
            rule.reason,
        ]);
        tr.insertBefore(domainCell(rule.domain), tr.firstChild);
        tr.appendChild(actionCell([
            button("Remove", () => removeRule(rule.domain)),
        ]));
        target.appendChild(tr);
    });
}

function renderReputations(reputations) {
    const target = document.getElementById("reputations");
    clear(target);
    emptyState("reputations-empty", reputations.length === 0);
    reputations.forEach((reputation) => {
        const tr = row([
            [reputation.score, riskClass(reputation.score)],
            reputation.confidence,
            reputation.signals,
        ]);
        tr.insertBefore(domainCell(reputation.domain), tr.firstChild);
        target.appendChild(tr);
    });
}

function renderSettings(status) {
    const target = document.getElementById("settings-summary");
    const database = status.database ?? {};
    const config = status.config ?? {};

    renderKeyValue(target, [
        ["Events DB", config.events_db],
        ["Pi-hole DB", config.pihole_db],
        ["Dashboard Port", config.dashboard_port],
        ["AI Enabled", config.ai_enabled],
        ["AI Calls / Minute", config.ai_max_calls_per_minute],
        ["AI Cooldown Seconds", config.ai_cooldown_seconds],
        ["AI Timeout Seconds", config.ai_timeout_seconds],
    ]);
    emptyState("threat-intel-empty", (database.threat_intel ?? 0) === 0);
}

function renderSettingsControls(payload) {
    const ai = payload.ai ?? {};
    const dashboard = payload.dashboard ?? {};
    document.getElementById("setting-ai-enabled").checked = Boolean(ai.enabled);
    document.getElementById("setting-ai-max-calls").value = ai.max_calls_per_minute ?? 2;
    document.getElementById("setting-ai-cooldown").value = ai.cooldown_seconds ?? 60;
    document.getElementById("setting-ai-timeout").value = ai.timeout_seconds ?? 20;
    document.getElementById("setting-refresh").value = dashboard.refresh_interval_ms ?? 5000;
    document.getElementById("setting-dev-logs").checked = Boolean(dashboard.dev_access_logs);
}

function settingPayload() {
    return {
        ai: {
            enabled: document.getElementById("setting-ai-enabled").checked,
            max_calls_per_minute: Number(document.getElementById("setting-ai-max-calls").value),
            cooldown_seconds: Number(document.getElementById("setting-ai-cooldown").value),
            timeout_seconds: Number(document.getElementById("setting-ai-timeout").value),
        },
        dashboard: {
            refresh_interval_ms: Number(document.getElementById("setting-refresh").value),
            dev_access_logs: document.getElementById("setting-dev-logs").checked,
        },
    };
}

function settingsMessage(message) {
    document.getElementById("settings-message").textContent = message;
}

function renderIntelligence(metrics, status, intelSources) {
    const target = document.getElementById("intelligence-cards");
    clear(target);
    const database = status.database ?? {};
    const ai = status.ai ?? {};
    const config = status.config ?? {};
    const sources = Array.isArray(intelSources?.sources) ? intelSources.sources : [];
    const intelStats = intelSources?.stats ?? {};
    const enabledSources = intelStats.enabled_sources ?? sources.filter((source) => source.enabled).length;
    const failedSources = intelStats.failed_sources ?? sources.filter((source) => source.status === "failed").length;
    const staleSources = intelStats.stale_sources ?? sources.filter((source) => source.status === "stale").length;

    target.appendChild(metricPanel("AI Controls", [
        ["Enabled", config.ai_enabled],
        ["Calls", ai.ai_calls ?? 0],
        ["Skipped", ai.ai_skipped ?? 0],
        ["Timeouts", ai.ai_timeouts ?? 0],
    ]));
    target.appendChild(metricPanel("AI Reliability", [
        ["Parse Errors", ai.ai_parse_errors ?? 0],
        ["Rate Skips", ai.rate_limit_skips ?? 0],
        ["Cooldown Skips", ai.cooldown_skips ?? 0],
        ["Disabled Skips", ai.disabled_skips ?? 0],
    ]));
    target.appendChild(metricPanel("Reputation", [
        ["Rows", database.reputations ?? 0],
        ["Rules", (metrics.rules?.allow ?? 0) + (metrics.rules?.block ?? 0)],
        ["Blocks", metrics.rules?.block ?? 0],
    ]));
    target.appendChild(metricPanel("Threat Intel", [
        ["Indicators", intelStats.active_indicators ?? database.threat_intel ?? 0],
        ["Sources", intelStats.sources_total ?? sources.length],
        ["Enabled", enabledSources],
        ["Failed/Stale", `${failedSources}/${staleSources}`],
    ]));
    target.appendChild(metricPanel("Feed Updates", [
        ["Last Success", formatTime(intelStats.last_success_at)],
        ["Last Attempt", formatTime(intelStats.last_attempt_at)],
        ["Integrity", intelStats.integrity_issues ?? 0],
    ]));
}

function renderExplanation(explanation) {
    const target = document.getElementById("explain");
    const feedbackTarget = document.getElementById("explain-feedback");
    clear(target);
    clear(feedbackTarget);

    const feedbackLabel = document.createElement("strong");
    feedbackLabel.textContent = "Feedback";
    feedbackTarget.appendChild(feedbackLabel);
    feedbackTarget.appendChild(button("Safe", () => saveFeedback(
        explanation.domain,
        "safe",
        true
    )));
    feedbackTarget.appendChild(button("Bad", () => saveFeedback(
        explanation.domain,
        "bad",
        true
    )));
    feedbackTarget.appendChild(button("False positive", () => saveFeedback(
        explanation.domain,
        "false-positive",
        true
    )));
    feedbackTarget.appendChild(button("False negative", () => saveFeedback(
        explanation.domain,
        "false-negative",
        true
    )));
    feedbackTarget.appendChild(button("Noisy", () => saveFeedback(
        explanation.domain,
        "noisy",
        false
    )));

    renderDecisionSection(target, explanation);
    renderEvidenceSection(target, "Decisive evidence", explanation.decisive_evidence, true);
    renderEvidenceSection(target, "Supporting risk evidence", explanation.risk_evidence, false);
    renderEvidenceSection(target, "Supporting safety evidence", explanation.safety_evidence, false);
    renderEvidenceSection(target, "Neutral/context evidence", explanation.neutral_evidence, false);
    renderTraceSection(target, explanation.classifier_trace ?? []);
    renderListSection(target, "Conflicts and uncertainty", explanation.conflicts ?? []);
    renderHistorySection(target, explanation.domain);

    if (explanation.legacy) {
        renderListSection(target, "Legacy decision", [
            explanation.legacy_note || "This decision predates structured evidence storage.",
        ]);
    }
}

function section(title) {
    const node = document.createElement("section");
    node.className = "explain-section";
    const heading = document.createElement("h3");
    heading.textContent = title;
    node.appendChild(heading);
    return node;
}

function metricChip(label, value) {
    const chip = document.createElement("div");
    chip.className = "metric-chip";
    const strong = document.createElement("strong");
    strong.textContent = text(value);
    const span = document.createElement("span");
    span.textContent = label;
    chip.append(strong, span);
    return chip;
}

function renderDecisionSection(target, explanation) {
    const node = section("Final decision");
    const decision = explanation.decision;
    if (!decision) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No decision stored for this domain.";
        node.appendChild(empty);
        target.appendChild(node);
        return;
    }

    const summary = document.createElement("div");
    summary.className = "decision-summary";
    const badge = document.createElement("span");
    badge.className = `badge ${riskClass(decision.risk_score ?? decision.risk ?? 0)}`;
    badge.textContent = text(decision.verdict || "unknown");
    const explanationText = document.createElement("p");
    explanationText.textContent = text(decision.explanation);
    summary.append(badge, explanationText);

    const metrics = document.createElement("div");
    metrics.className = "decision-metrics";
    const confidence = Number(decision.confidence ?? 0);
    metrics.append(
        metricChip("Risk", `${decision.risk_score ?? decision.risk ?? 0}/100`),
        metricChip("Confidence", confidence <= 1 ? `${Math.round(confidence * 100)}%` : `${confidence}%`),
        metricChip("Category", decision.category),
        metricChip("Source", decision.source),
        metricChip("Policy", decision.policy_version ?? explanation.policy_version ?? "-"),
        metricChip("Time", formatTime(decision.created_at))
    );
    node.append(summary, metrics);
    target.appendChild(node);
}

async function renderHistorySection(target, domain) {
    const node = section("Decision history");
    const loading = document.createElement("div");
    loading.className = "empty";
    loading.textContent = "Loading history...";
    node.appendChild(loading);
    target.appendChild(node);

    const response = await checkedFetch(`/api/explain/${encodeURIComponent(domain)}/history?limit=10`);
    clear(node);
    const heading = document.createElement("h3");
    heading.textContent = "Decision history";
    node.appendChild(heading);
    if (!response.ok) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "History unavailable.";
        node.appendChild(empty);
        return;
    }
    const payload = await response.json();
    const history = Array.isArray(payload.history) ? payload.history : [];
    if (history.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No decision history yet.";
        node.appendChild(empty);
        return;
    }
    history.forEach((item) => {
        const row = document.createElement("button");
        row.type = "button";
        row.className = "history-row";
        row.textContent = `${formatTime(item.created_at)} · ${text(item.verdict)} · risk ${item.risk_score} · ${text(item.trigger)}${item.current ? " · current" : ""}`;
        row.addEventListener("click", () => loadHistoricalDecision(domain, item.decision_id));
        node.appendChild(row);
    });
    if (history.length >= 2) {
        const compare = button("Compare latest to previous", () => compareDecisions(
            domain,
            history[1].decision_id,
            history[0].decision_id
        ));
        node.appendChild(compare);
    }
}

async function loadHistoricalDecision(domain, decisionId) {
    const response = await checkedFetch(`/api/explain/${encodeURIComponent(domain)}/decision/${encodeURIComponent(decisionId)}`);
    if (response.ok) {
        renderExplanation(await response.json());
    }
}

async function compareDecisions(domain, olderId, newerId) {
    const target = document.getElementById("explain");
    const response = await checkedFetch(
        `/api/explain/${encodeURIComponent(domain)}/compare?older=${encodeURIComponent(olderId)}&newer=${encodeURIComponent(newerId)}`
    );
    if (!response.ok) {
        return;
    }
    const comparison = await response.json();
    const node = section("Decision comparison");
    renderListSection(node, "Changes", [
        `Verdict changed: ${comparison.verdict_changed}`,
        `Risk delta: ${comparison.risk_delta}`,
        `Confidence delta: ${comparison.confidence_delta}`,
        `Policy changed: ${comparison.policy_changed}`,
        `Decisive evidence changed: ${comparison.decisive_evidence_changed}`,
        comparison.summary,
    ]);
    renderEvidenceSection(node, "Evidence added", comparison.added_evidence ?? [], false);
    renderEvidenceSection(node, "Evidence removed", comparison.removed_evidence ?? [], false);
    target.appendChild(node);
}

function renderEvidenceSection(target, title, evidence = [], decisive = false) {
    const node = section(title);
    if (!Array.isArray(evidence) || evidence.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "None";
        node.appendChild(empty);
        target.appendChild(node);
        return;
    }
    evidence.forEach((item) => {
        const card = document.createElement("article");
        card.className = `evidence-card${decisive || item.decisive ? " decisive" : ""}`;
        const titleLine = document.createElement("strong");
        titleLine.textContent = `${text(item.classifier)} · ${text(item.evidence_type)}`;
        const summary = document.createElement("div");
        summary.textContent = text(item.summary);
        const meta = document.createElement("div");
        meta.className = "evidence-meta";
        const score = Number(item.score ?? 0);
        const confidence = Number(item.confidence ?? 0);
        meta.textContent = `score ${score >= 0 ? "+" : ""}${score} · confidence ${Math.round(confidence * 100)}%`;
        card.append(titleLine, summary, meta);

        const policyReason = item.metadata?.policy_reason || item.metadata?.precedence;
        if (policyReason) {
            const policy = document.createElement("div");
            policy.className = "evidence-meta";
            policy.textContent = `policy: ${text(policyReason)}`;
            card.appendChild(policy);
        }

        if (item.details || Object.keys(item.metadata ?? {}).length > 0) {
            const details = document.createElement("details");
            details.className = "evidence-details";
            const summaryNode = document.createElement("summary");
            summaryNode.textContent = "Details";
            const pre = document.createElement("pre");
            pre.textContent = JSON.stringify({
                details: item.details || undefined,
                metadata: item.metadata || {},
            }, null, 2);
            details.append(summaryNode, pre);
            card.appendChild(details);
        }
        node.appendChild(card);
    });
    target.appendChild(node);
}

function renderTraceSection(target, trace) {
    const node = section("Classifier trace");
    if (!Array.isArray(trace) || trace.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No classifier trace stored.";
        node.appendChild(empty);
        target.appendChild(node);
        return;
    }
    trace.forEach((item) => {
        const row = document.createElement("div");
        row.className = "trace-row";
        const title = document.createElement("strong");
        title.textContent = `${text(item.classifier)} · ${text(item.status)}`;
        const meta = document.createElement("div");
        meta.className = "trace-meta";
        meta.textContent = `evidence ${item.evidence_count ?? 0} · latency ${item.latency_ms ?? 0}ms`;
        row.append(title, meta);
        if (item.reason) {
            const reason = document.createElement("div");
            reason.className = "trace-meta";
            reason.textContent = text(item.reason);
            row.appendChild(reason);
        }
        node.appendChild(row);
    });
    target.appendChild(node);
}

function renderListSection(target, title, values) {
    const node = section(title);
    if (!Array.isArray(values) || values.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "None";
        node.appendChild(empty);
        target.appendChild(node);
        return;
    }
    values.forEach((value) => {
        const item = document.createElement("div");
        item.textContent = text(value);
        node.appendChild(item);
    });
    target.appendChild(node);
}

async function explainDomain(domain) {
    const target = document.getElementById("explain");
    const feedbackTarget = document.getElementById("explain-feedback");
    clear(target);
    clear(feedbackTarget);
    const loading = document.createElement("div");
    loading.className = "explain-message";
    loading.textContent = "Loading explanation...";
    target.appendChild(loading);

    const response = await checkedFetch(`/api/explain/${encodeURIComponent(domain)}`);
    if (response.status === 404) {
        clear(target);
        const message = document.createElement("div");
        message.className = "explain-message";
        message.textContent = "No local decision or evidence for this domain yet.";
        target.appendChild(message);
        return;
    }
    if (!response.ok) {
        clear(target);
        const message = document.createElement("div");
        message.className = "explain-message";
        message.textContent = response.status === 400
            ? "That domain is not valid."
            : "Explanation could not be loaded.";
        target.appendChild(message);
        return;
    }
    renderExplanation(await response.json());
}

async function saveRule(domain, decision) {
    await checkedFetch("/api/rules", {
        method: "POST",
        headers: csrfHeaders({"Content-Type": "application/json"}),
        body: JSON.stringify({
            domain,
            decision,
            reason: `Dashboard ${decision}`,
        }),
    });
    await Promise.all([
        loadRules(),
        loadActivity(),
    ]);
}

async function removeRule(domain) {
    await checkedFetch(`/api/rules/${encodeURIComponent(domain)}`, {
        method: "DELETE",
        headers: csrfHeaders(),
    });
    await loadRules();
}

async function saveFeedback(domain, verdict, promote) {
    await checkedFetch("/api/feedback", {
        method: "POST",
        headers: csrfHeaders({"Content-Type": "application/json"}),
        body: JSON.stringify({
            domain,
            verdict,
            promote,
            apply: verdict === "bad" || verdict === "false-negative",
            reason: `Dashboard ${verdict}`,
        }),
    });
    await Promise.all([
        loadOverview(),
        loadActivity(),
        loadRules(),
        loadReputations(),
        explainDomain(domain),
    ]);
}

function paramsForTables() {
    const params = new URLSearchParams();
    const search = document.getElementById("search").value.trim();
    const minRisk = document.getElementById("min-risk").value;
    const limit = document.getElementById("limit").value;

    if (search) params.set("q", search);
    if (minRisk !== "0") params.set("min_risk", minRisk);
    params.set("limit", limit);

    return `?${params.toString()}`;
}

async function loadOverview() {
    const [setup, stats, status, highRisk] = await Promise.all([
        checkedFetch("/api/setup").then((res) => res.json()),
        checkedFetch("/api/stats").then((res) => res.json()),
        checkedFetch("/api/status").then((res) => res.json()),
        checkedFetch("/api/analysis?min_risk=70&limit=12").then((res) => res.json()),
    ]);

    renderSetup(setup);
    renderStats(stats);
    renderServiceStatus(status);
    renderNetworkSummary(status);
    renderAnalysis(highRisk, "overview-high-risk");
    renderSettings(status);
    document.getElementById("updated").textContent =
        new Date().toLocaleTimeString();
}

async function loadSettings() {
    const payload = await checkedFetch("/api/settings").then((res) => res.json());
    renderSettingsControls(payload);
}

async function loadMetrics() {
    const [metrics, status, intelSources] = await Promise.all([
        checkedFetch("/api/metrics/decisions").then((res) => res.json()),
        checkedFetch("/api/status").then((res) => res.json()),
        checkedFetch("/api/intel/sources").then((res) => res.json()),
    ]);
    renderDecisionMetrics(metrics);
    renderIntelligence(metrics, status, intelSources);
}

async function loadReliability() {
    const payload = await checkedFetch("/api/reliability?window=all").then((res) => res.json());
    renderReliability(payload);
}

async function loadTables() {
    const suffix = paramsForTables();
    const [analysis, devices] = await Promise.all([
        checkedFetch(`/api/analysis${suffix}`).then((res) => res.json()),
        checkedFetch(`/api/devices${suffix}`).then((res) => res.json()),
    ]);

    renderAnalysis(analysis);
    renderDevices(devices);
}

async function loadActivity() {
    const suffix = paramsForTables();
    const [events, analysis, actions] = await Promise.all([
        checkedFetch(`/api/events${suffix}`).then((res) => res.json()),
        checkedFetch(`/api/analysis${suffix}`).then((res) => res.json()),
        checkedFetch(`/api/actions${suffix}`).then((res) => res.json()),
    ]);

    renderActivity(events, analysis, actions);
}

async function loadRules() {
    const rules = await checkedFetch(`/api/rules${paramsForTables()}`).then((res) => res.json());
    renderRules(rules);
}

async function loadReputations() {
    const reputations = await checkedFetch(`/api/reputations${paramsForTables()}`).then((res) => res.json());
    renderReputations(reputations);
}

async function loadAll() {
    await Promise.all([
        loadOverview(),
        loadMetrics(),
        loadTables(),
        loadActivity(),
        loadRules(),
        loadReputations(),
        loadSettings(),
        loadReliability(),
    ]);
}

function activatePage(name) {
    document.querySelectorAll(".nav-link").forEach((link) => {
        link.classList.toggle("active", link.dataset.page === name);
    });
    document.querySelectorAll(".tab-panel").forEach((panel) => {
        panel.classList.toggle("active", panel.id === `page-${name}`);
    });
    document.getElementById("page-title").textContent =
        name.charAt(0).toUpperCase() + name.slice(1);
}

document.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", () => activatePage(link.dataset.page));
});
document.getElementById("refresh").addEventListener("click", loadAll);
document.getElementById("search").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        loadAll();
    }
});
document.getElementById("min-risk").addEventListener("change", loadAll);
document.getElementById("limit").addEventListener("change", loadAll);
document.getElementById("save-settings").addEventListener("click", async () => {
    const response = await checkedFetch("/api/settings", {
        method: "POST",
        headers: csrfHeaders({"Content-Type": "application/json"}),
        body: JSON.stringify(settingPayload()),
    }).then((res) => res.json());

    settingsMessage(response.restart_required
        ? "Settings saved. Restart required."
        : "Settings saved.");
});
document.getElementById("restart-required").addEventListener("click", () => serviceAction("restart"));
document.getElementById("service-status-button").addEventListener("click", async () => {
    const status = await checkedFetch("/api/status").then((res) => res.json());
    settingsMessage(`Status loaded. Events: ${status.database?.events ?? 0}, processed: ${status.database?.processed ?? 0}.`);
});
document.querySelectorAll("[data-service-action]").forEach((item) => {
    item.addEventListener("click", () => serviceAction(item.dataset.serviceAction));
});

async function serviceAction(action) {
    const response = await checkedFetch(`/api/services/${action}`, {
        method: "POST",
        headers: csrfHeaders(),
    }).then((res) => res.json());

    if (response.ok) {
        settingsMessage(response.message);
    } else {
        settingsMessage(response.message || `Run: ${response.command}`);
    }
}
document.getElementById("logout").addEventListener("click", async () => {
    await checkedFetch("/logout", {
        method: "POST",
        headers: csrfHeaders(),
    });
    window.location.href = "/login";
});
setInterval(loadOverview, __OVERVIEW_POLL_INTERVAL_MS__);
setInterval(loadMetrics, __METRICS_POLL_INTERVAL_MS__);
setInterval(() => Promise.all([loadTables(), loadActivity()]), __TABLES_POLL_INTERVAL_MS__);
setInterval(() => Promise.all([loadRules(), loadReputations(), loadReliability()]), __SLOW_POLL_INTERVAL_MS__);
loadAll();
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

    rows = query_all_readonly(
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

    rows = query_all_readonly(
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

    rows = query_all_readonly(
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

    with readonly_database():
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

    with readonly_database():
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

    with readonly_database():
        return load_reputations(
            limit=limit,
            search=search,
            min_score=min_score,
        )


def get_decision_metrics() -> dict[str, Any]:
    """
    Return aggregate decision metrics for the dashboard/API.
    """

    with readonly_database():
        return db_decision_metrics()


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default

    return value.lower() in {"1", "true", "yes", "on"}


def _read_env_values(
    path: Path | None = None,
) -> dict[str, str]:
    """
    Read KEY=value pairs while ignoring comments and malformed lines.
    """

    env_path = Path(path or SETTINGS_ENV_PATH)

    if not env_path.exists():
        return {}

    values: dict[str, str] = {}

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")

    return values


def _merged_settings() -> dict[str, Any]:
    """
    Return current dashboard-editable settings.
    """

    env = _read_env_values()

    return {
        "config_path": str(SETTINGS_ENV_PATH),
        "ai": {
            "enabled": _parse_bool(
                env.get("AI_ENABLED"),
                settings.ai_enabled,
            ),
            "max_calls_per_minute": int(
                env.get(
                    "AI_MAX_CALLS_PER_MINUTE",
                    settings.ai_max_calls_per_minute,
                )
            ),
            "cooldown_seconds": int(
                env.get(
                    "AI_COOLDOWN_SECONDS",
                    settings.ai_cooldown_seconds,
                )
            ),
            "timeout_seconds": int(
                env.get(
                    "AI_TIMEOUT_SECONDS",
                    settings.ai_timeout_seconds,
                )
            ),
        },
        "dashboard": {
            "refresh_interval_ms": int(
                env.get(
                    "PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS",
                    settings.dashboard_overview_poll_interval_ms,
                )
            ),
            "dev_access_logs": _parse_bool(
                env.get("DEV_ACCESS_LOGS"),
                settings.dev_access_logs,
            ),
        },
    }


def _update_env_lines(
    lines: list[str],
    updates: dict[str, str],
) -> list[str]:
    """
    Update known env keys while preserving comments and unknown lines.
    """

    remaining = dict(updates)
    output: list[str] = []

    for line in lines:
        stripped = line.strip()

        if not stripped or stripped.startswith("#") or "=" not in line:
            output.append(line)
            continue

        key, _value = line.split("=", 1)
        normalized = key.strip()

        if normalized in remaining:
            output.append(f"{normalized}={remaining.pop(normalized)}")
        else:
            output.append(line)

    for key, value in remaining.items():
        output.append(f"{key}={value}")

    return output


def _write_settings_env(
    payload: dict[str, Any],
    path: Path | None = None,
) -> dict[str, Any]:
    """
    Persist dashboard-editable settings to the runtime env file.
    """

    env_path = Path(path or SETTINGS_ENV_PATH)
    ai = payload.get("ai", {})
    dashboard = payload.get("dashboard", {})
    updates = {
        "AI_ENABLED": _bool_text(bool(ai.get("enabled", settings.ai_enabled))),
        "AI_MAX_CALLS_PER_MINUTE": str(
            int(ai.get("max_calls_per_minute", settings.ai_max_calls_per_minute))
        ),
        "AI_COOLDOWN_SECONDS": str(
            int(ai.get("cooldown_seconds", settings.ai_cooldown_seconds))
        ),
        "AI_TIMEOUT_SECONDS": str(
            int(ai.get("timeout_seconds", settings.ai_timeout_seconds))
        ),
        "PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS": str(
            int(
                dashboard.get(
                    "refresh_interval_ms",
                    settings.dashboard_overview_poll_interval_ms,
                )
            )
        ),
        "DEV_ACCESS_LOGS": _bool_text(
            bool(dashboard.get("dev_access_logs", settings.dev_access_logs))
        ),
    }

    lines: list[str] = []

    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()

    updated = _update_env_lines(
        lines=lines,
        updates=updates,
    )

    env_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    env_path.write_text(
        "\n".join(updated).rstrip() + "\n",
        encoding="utf-8",
    )

    return _merged_settings() | {
        "restart_required": True,
    }


def _sudo_command(
    action: str,
) -> str:
    return f"sudo pihole-ai {action}"


def _needs_sudo() -> bool:
    get_euid = getattr(os, "geteuid", None)
    return get_euid is not None and get_euid() != 0


def auth_is_enabled() -> bool:
    if current_app.config.get("PIHOLE_AI_DISABLE_AUTH_FOR_TESTS"):
        return False
    return bool(settings.dashboard_auth_enabled)


def csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return str(token)


def rotate_csrf() -> str:
    token = secrets.token_urlsafe(32)
    session[CSRF_SESSION_KEY] = token
    return token


def is_authenticated() -> bool:
    return bool(session.get(AUTH_SESSION_KEY))


def is_api_request() -> bool:
    return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json"


def local_redirect_target(value: str | None) -> str:
    if not value:
        return url_for("home")
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or not value.startswith("/"):
        return url_for("home")
    if value.startswith("//"):
        return url_for("home")
    return value


def remote_identity() -> str:
    return request.remote_addr or "unknown"


def login_key(username: str) -> tuple[str, str]:
    return (remote_identity(), username.strip().lower())


def login_is_throttled(username: str, now: float | None = None) -> bool:
    current = now if now is not None else time.time()
    key = login_key(username)
    attempts = [
        stamp
        for stamp in LOGIN_FAILURES.get(key, [])
        if current - stamp <= LOGIN_FAILURE_WINDOW_SECONDS + LOGIN_LOCKOUT_SECONDS
    ]
    LOGIN_FAILURES[key] = attempts
    recent = [
        stamp
        for stamp in attempts
        if current - stamp <= LOGIN_FAILURE_WINDOW_SECONDS
    ]
    return len(recent) >= LOGIN_FAILURE_LIMIT


def record_login_failure(username: str, now: float | None = None) -> None:
    current = now if now is not None else time.time()
    _prune_login_failures(current)
    key = login_key(username)
    LOGIN_FAILURES.setdefault(key, []).append(current)


def clear_login_failures(username: str) -> None:
    LOGIN_FAILURES.pop(login_key(username), None)


def _prune_login_failures(current: float) -> None:
    expired_before = current - LOGIN_FAILURE_WINDOW_SECONDS - LOGIN_LOCKOUT_SECONDS
    for key in list(LOGIN_FAILURES):
        values = [
            stamp
            for stamp in LOGIN_FAILURES[key]
            if stamp >= expired_before
        ]
        if values:
            LOGIN_FAILURES[key] = values
        else:
            LOGIN_FAILURES.pop(key, None)
    while len(LOGIN_FAILURES) > MAX_LOGIN_FAILURE_RECORDS:
        oldest_key = min(
            LOGIN_FAILURES,
            key=lambda item: LOGIN_FAILURES[item][0] if LOGIN_FAILURES[item] else 0,
        )
        LOGIN_FAILURES.pop(oldest_key, None)


def require_csrf() -> bool:
    submitted = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    expected = session.get(CSRF_SESSION_KEY)
    return bool(submitted and expected and secrets.compare_digest(str(submitted), str(expected)))


def json_error(status: int, code: str, message: str):
    response = jsonify({"error": code, "message": message})
    response.status_code = status
    return response


def render_error_page(status: int, message: str):
    return (
        render_template_string(
            "<!doctype html><title>PiHole-AI</title><h1>PiHole-AI</h1><p>{{ message }}</p>",
            message=message,
        ),
        status,
    )


def _render_login_failure(message: str) -> str:
    html = LOGIN_HTML
    replacements = {
        "__CSP_NONCE__": getattr(g, "csp_nonce", ""),
        "__CSRF_TOKEN__": csrf_token(),
        "__NEXT__": local_redirect_target(request.form.get("next")),
        "__ERROR__": message,
    }
    for placeholder, value in replacements.items():
        html = html.replace(placeholder, str(value))
    return render_template_string(html)


def create_app() -> Flask:
    """
    Create the Flask dashboard application.
    """

    app = Flask(__name__)
    app.secret_key = settings.dashboard_secret_key or secrets.token_urlsafe(48)
    app.config.update(
        MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
        PERMANENT_SESSION_LIFETIME=timedelta(
            minutes=max(1, settings.dashboard_session_lifetime_minutes)
        ),
        SESSION_REFRESH_EACH_REQUEST=True,
    )

    if settings.dashboard_trust_proxy:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @app.before_request
    def security_gate():
        g.csp_nonce = secrets.token_urlsafe(16)
        if request.is_secure:
            current_app.config["SESSION_COOKIE_SECURE"] = True

        if request.endpoint in {"login", "login_submit", "live", "static", "branding_asset"}:
            return None

        if not auth_is_enabled():
            return None

        if not is_authenticated():
            if is_api_request():
                return json_error(401, "authentication_required", "Authentication required.")
            return redirect(url_for("login", next=request.full_path.rstrip("?")))

        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not require_csrf():
            if is_api_request():
                return json_error(403, "csrf_failed", "Security token expired. Refresh and try again.")
            abort(403)

        return None

    @app.after_request
    def security_headers(response):
        nonce = getattr(g, "csp_nonce", "")
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if request.path != "/live":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    @app.errorhandler(429)
    @app.errorhandler(500)
    def safe_error(error):
        status = getattr(error, "code", 500)
        messages = {
            400: "Bad request.",
            401: "Authentication required.",
            403: "Request not permitted.",
            404: "Not found.",
            405: "Method not allowed.",
            413: "Request too large.",
            429: "Too many requests.",
            500: "Internal error.",
        }
        code = {
            400: "bad_request",
            401: "authentication_required",
            403: "forbidden",
            404: "not_found",
            405: "method_not_allowed",
            413: "request_too_large",
            429: "too_many_requests",
            500: "internal_error",
        }.get(status, "error")
        if is_api_request():
            return json_error(status, code, messages.get(status, "Error."))
        return render_error_page(status, messages.get(status, "Error."))

    @app.get("/live")
    def live():
        return jsonify({"status": "alive"})

    @app.get("/branding/<path:filename>")
    def branding_asset(filename: str):
        return send_from_directory(BRANDING_DIR, filename)

    @app.get("/login")
    def login():
        if auth_is_enabled() and is_authenticated():
            return redirect(local_redirect_target(request.args.get("next")))
        html = LOGIN_HTML
        replacements = {
            "__CSP_NONCE__": getattr(g, "csp_nonce", ""),
            "__CSRF_TOKEN__": csrf_token(),
            "__NEXT__": local_redirect_target(request.args.get("next")),
            "__ERROR__": "",
        }
        for placeholder, value in replacements.items():
            html = html.replace(placeholder, str(value))
        return render_template_string(html)

    @app.post("/login")
    def login_submit():
        if auth_is_enabled() and not require_csrf():
            abort(403)

        username = str(request.form.get("username", ""))[:128]
        password = str(request.form.get("password", ""))
        failure = "Invalid username or password."
        if login_is_throttled(username):
            return _render_login_failure(failure), 429

        ok = (
            username == settings.dashboard_username
            and bool(settings.dashboard_password_hash.strip())
            and check_password_hash(settings.dashboard_password_hash, password)
        )
        if not ok:
            record_login_failure(username)
            return _render_login_failure(failure), 401

        session.clear()
        session.permanent = True
        session[AUTH_SESSION_KEY] = True
        session["username"] = settings.dashboard_username
        session["login_at"] = int(time.time())
        rotate_csrf()
        clear_login_failures(username)
        return redirect(local_redirect_target(request.form.get("next")))

    @app.post("/logout")
    def logout():
        session.clear()
        rotate_csrf()
        if is_api_request():
            return jsonify({"ok": True})
        return redirect(url_for("login"))

    @app.get("/")
    def home():
        html = HTML
        replacements = {
            "__OVERVIEW_POLL_INTERVAL_MS__": settings.dashboard_overview_poll_interval_ms,
            "__METRICS_POLL_INTERVAL_MS__": settings.dashboard_metrics_poll_interval_ms,
            "__TABLES_POLL_INTERVAL_MS__": settings.dashboard_tables_poll_interval_ms,
            "__SLOW_POLL_INTERVAL_MS__": settings.dashboard_slow_poll_interval_ms,
            "__CSP_NONCE__": getattr(g, "csp_nonce", ""),
            "__CSRF_TOKEN__": csrf_token(),
            "__USERNAME__": session.get("username", settings.dashboard_username),
        }

        for placeholder, value in replacements.items():
            html = html.replace(
                placeholder,
                str(value),
            )

        return render_template_string(html)

    @app.get("/api/stats")
    def stats():
        return jsonify(database_stats())

    @app.get("/api/polling")
    def polling():
        return jsonify(
            {
                "overview_ms": settings.dashboard_overview_poll_interval_ms,
                "metrics_ms": settings.dashboard_metrics_poll_interval_ms,
                "tables_ms": settings.dashboard_tables_poll_interval_ms,
                "rules_reputation_ms": settings.dashboard_slow_poll_interval_ms,
            }
        )

    @app.get("/api/settings")
    def current_settings():
        return jsonify(_merged_settings())

    @app.get("/api/setup")
    def setup_status():
        return jsonify(evaluate_setup().to_dict())

    @app.post("/api/settings")
    def update_settings():
        payload = request.get_json(silent=True) or {}

        try:
            updated = _write_settings_env(payload)

        except OSError as exc:
            return jsonify(
                {
                    "error": "settings file is not writable",
                    "message": str(exc),
                    "command": "sudo pihole-ai restart",
                }
            ), 500

        return jsonify(updated)

    @app.post("/api/services/<action>")
    def service_control(action: str):
        if action not in {"start", "stop", "restart"}:
            return jsonify({"error": "unsupported service action"}), 400

        command = _sudo_command(action)

        if _needs_sudo():
            return jsonify(
                {
                    "ok": False,
                    "error": "sudo_required",
                    "message": f"Dashboard is not permitted to run systemd. Run: {command}",
                    "command": command,
                }
            ), 403

        try:
            from pihole_ai.service import ServiceError, service_action

            service_action(action)

        except ServiceError as exc:
            return jsonify(
                {
                    "ok": False,
                    "error": "service_failed",
                    "message": str(exc),
                    "command": command,
                }
            ), 500

        return jsonify(
            {
                "ok": True,
                "action": action,
                "message": f"Service action completed: {action}",
            }
        )

    @app.get("/api/metrics/decisions")
    def decision_metric_summary():
        return jsonify(get_decision_metrics())

    @app.get("/api/reliability")
    def reliability_summary():
        window = request.args.get("window", "all")
        if window not in {"24h", "7d", "30d", "all"}:
            window = "all"
        response = jsonify(reliability_metrics(window=window))
        response.headers["Cache-Control"] = "no-store"
        return response

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

    @app.get("/api/intel/sources")
    def intel_sources():
        sources = []
        stats = {}
        diagnostics = []
        with readonly_database():
            stats = threat_intel_stats(settings.events_db)
            diagnostics = threat_intel_diagnostics(settings.events_db)
            for row in list_intel_source_status():
                sources.append(
                    {
                        "source_id": row.get("source_id"),
                        "name": row.get("name"),
                        "enabled": bool(row.get("enabled")),
                        "category": row.get("category") or "",
                        "confidence": row.get("confidence") or 0,
                        "status": row.get("status") or "unknown",
                        "entry_count": row.get("entry_count") or 0,
                        "active_generation": row.get("active_generation") or "",
                        "last_http_status": row.get("last_http_status"),
                        "last_downloaded_bytes": row.get("last_downloaded_bytes") or 0,
                        "last_parsed_entries": row.get("last_parsed_entries") or 0,
                        "last_accepted_entries": row.get("last_accepted_entries") or 0,
                        "last_rejected_entries": row.get("last_rejected_entries") or 0,
                        "last_duplicate_entries": row.get("last_duplicate_entries") or 0,
                        "last_update_duration_ms": row.get("last_update_duration_ms") or 0,
                        "last_success_at": row.get("last_success_at"),
                        "last_attempt_at": row.get("last_attempt_at"),
                        "last_error_code": row.get("last_error_code") or "",
                        "last_error_summary": row.get("last_error_summary") or "",
                        "consecutive_failures": row.get("consecutive_failures") or 0,
                    }
                )
        response = jsonify(
            {
                "sources": sources,
                "stats": stats,
                "diagnostics": diagnostics,
            }
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/intel/stats")
    def intel_stats_api():
        with readonly_database():
            payload = {
                "stats": threat_intel_stats(settings.events_db),
                "diagnostics": threat_intel_diagnostics(settings.events_db),
            }
        response = jsonify(payload)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/explain/<path:domain>")
    def explain(domain: str):
        if not is_valid_domain_query(domain):
            return jsonify({"error": "invalid domain"}), 400

        try:
            with readonly_database():
                explanation = explain_domain(domain)
        except ValueError:
            return jsonify({"error": "invalid domain"}), 400

        if (
            explanation.get("decision") is None
            and explanation.get("rule") is None
            and explanation.get("threat_intel") is None
            and explanation.get("reputation") is None
            and not explanation.get("actions", [])
            and explanation.get("metadata", {}).get("query_count", 0) == 0
        ):
            return jsonify(
                {
                    "error": "domain not found",
                    "domain": explanation["domain"],
                    "decision": None,
                    "legacy": False,
                }
            ), 404

        response = jsonify(explanation)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/explain/<path:domain>/history")
    def explain_history(domain: str):
        if not is_valid_domain_query(domain):
            return jsonify({"error": "invalid domain"}), 400

        try:
            limit = parse_limit(request.args.get("limit"), default=20, maximum=100)
            before_raw = request.args.get("before")
            before = float(before_raw) if before_raw else None
            with readonly_database():
                payload = decision_history(domain, limit=limit, before=before)
        except ValueError:
            return jsonify({"error": "invalid request"}), 400

        response = jsonify(payload)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/explain/<path:domain>/decision/<decision_id>")
    def explain_decision(domain: str, decision_id: str):
        if not is_valid_domain_query(domain):
            return jsonify({"error": "invalid domain"}), 400

        try:
            with readonly_database():
                explanation = explain_domain(domain, decision_id=decision_id)
        except ValueError:
            return jsonify({"error": "invalid decision id"}), 400
        except LookupError:
            return jsonify({"error": "decision not found"}), 404

        response = jsonify(explanation)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/explain/<path:domain>/compare")
    def explain_compare(domain: str):
        older = request.args.get("older", "")
        newer = request.args.get("newer", "")
        if not is_valid_domain_query(domain):
            return jsonify({"error": "invalid domain"}), 400

        try:
            with readonly_database():
                payload = compare_domain_decisions(domain, older, newer)
        except ValueError:
            return jsonify({"error": "invalid decision id"}), 400
        except LookupError:
            return jsonify({"error": "decision not found"}), 404

        response = jsonify(payload)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/api/feedback")
    def create_feedback():
        payload = request.get_json(silent=True) or {}
        domain = str(payload.get("domain", "")).strip()
        verdict = str(payload.get("verdict", "")).strip()
        reason = str(payload.get("reason", "")).strip()
        promote = bool(payload.get("promote", False))
        apply_block = bool(payload.get("apply", False))

        if not domain:
            return jsonify({"error": "domain is required"}), 400

        if verdict not in FEEDBACK_VERDICTS:
            return jsonify({"error": "invalid feedback verdict"}), 400

        result = record_feedback(
            domain=domain,
            verdict=verdict,
            reason=reason,
            promote=promote,
            apply_block=apply_block,
        )

        return jsonify(
            {
                "domain": result.domain,
                "verdict": result.verdict,
                "promoted": result.promoted,
                "status": "saved",
            }
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

    @app.get("/api/status")
    def status():
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

    @app.get("/api/health")
    def health():
        try:
            from pihole_ai.health import (
                http_status_for_report,
                report_to_dict,
                run_health_checks,
            )
            from pihole_ai.version import get_version

            report = run_health_checks()

        except Exception as exc:
            logger.exception("Unable to run health checks.")
            return jsonify(
                {
                    "overall_status": "unknown",
                    "checks": [],
                    "version": get_version(),
                    "error": exc.__class__.__name__,
                }
            ), 500

        return jsonify(report_to_dict(report)), http_status_for_report(report)

    @app.get("/data")
    def legacy_data():
        return jsonify(
            get_device_summary(
                limit=parse_limit(request.args.get("limit")),
                search=request.args.get("q", "").strip(),
            )
        )

    return app


class LazyDashboardApp:
    """
    Lazy WSGI proxy preserving ui.dashboard:app without constructing Flask at import.
    """

    _app: Flask | None = None

    def _get_app(self) -> Flask:
        if self._app is None:
            self._app = create_app()
        return self._app

    def __call__(self, environ: Any, start_response: Any) -> Any:
        return self._get_app()(environ, start_response)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._get_app().run(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._get_app(), name)


app = LazyDashboardApp()


def main(
    host: str = "0.0.0.0",
    port: int | None = None,
) -> None:
    """
    Run the dashboard development server.
    """

    selected_port = port if port is not None else settings.dashboard_port

    if settings.dev_access_logs:
        logging.getLogger("werkzeug").setLevel(logging.INFO)

    else:
        logging.getLogger("werkzeug").setLevel(logging.WARNING)

    logger.info(
        "Starting dashboard on port %d.",
        selected_port,
    )

    app.run(
        host=host,
        port=selected_port,
    )


if __name__ == "__main__":
    main()
