from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template_string, request

from core.config import settings
from core.db import (
    database_stats,
    decision_metrics as db_decision_metrics,
    get_recent_actions as db_get_recent_actions,
    query_all,
)
from core.logger import get_logger
from pihole_ai.explain import explain_domain
from pihole_ai.feedback import FEEDBACK_VERDICTS, record_feedback
from pihole_ai.learn import get_reputations as load_reputations
from pihole_ai.rules import (
    add_rule,
    get_rules as load_domain_rules,
    remove_rule,
)
from pihole_ai.status import collect_status


logger = get_logger(__name__)

SETTINGS_ENV_PATH = settings.config_file

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
    display: grid;
    gap: 4px;
    padding: 4px 4px 10px;
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
        <strong>PiHole-AI</strong>
        <span>Companion appliance</span>
    </div>
    <nav class="side-nav" aria-label="Dashboard sections">
        <button class="nav-link active" type="button" data-page="overview">Overview</button>
        <button class="nav-link" type="button" data-page="activity">Activity</button>
        <button class="nav-link" type="button" data-page="domains">Domains</button>
        <button class="nav-link" type="button" data-page="devices">Devices</button>
        <button class="nav-link" type="button" data-page="intelligence">Intelligence</button>
        <button class="nav-link" type="button" data-page="rules">Rules</button>
        <button class="nav-link" type="button" data-page="settings">Settings</button>
    </nav>
</aside>
<div class="workspace">
<header>
    <h1 id="page-title">Overview</h1>
    <span class="muted" id="updated">-</span>
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

        <section class="tab-panel active" id="page-overview">
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
<script>
const text = (value) => String(value ?? "-");

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

function objectRows(values) {
    const entries = Object.entries(values ?? {});

    if (!entries.length) {
        return [["None", 0]];
    }

    return entries;
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

function renderIntelligence(metrics, status) {
    const target = document.getElementById("intelligence-cards");
    clear(target);
    const database = status.database ?? {};
    const ai = status.ai ?? {};
    const config = status.config ?? {};

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
        ["Indicators", database.threat_intel ?? 0],
        ["High Risk", metrics.analysis.high_risk],
        ["Unknown", metrics.categories?.unknown ?? 0],
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

    [
        ["Domain", explanation.domain],
        ["Summary", explanation.summary],
        ["Rule", explanation.rule],
        ["Threat Intel", explanation.threat_intel],
        ["Reputation", explanation.reputation],
        ["Analysis", explanation.analysis],
        ["Metadata", explanation.metadata],
        ["Actions", explanation.actions],
    ].forEach(([label, value]) => {
        const item = document.createElement("div");
        item.className = "explain-item";

        const heading = document.createElement("strong");
        heading.textContent = label;

        const body = document.createElement("pre");
        body.textContent = typeof value === "string"
            ? value
            : JSON.stringify(value ?? "none", null, 2);

        item.append(heading, body);
        target.appendChild(item);
    });
}

async function explainDomain(domain) {
    const explanation = await fetch(
        `/api/explain/${encodeURIComponent(domain)}`
    ).then((res) => res.json());
    renderExplanation(explanation);
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
    await Promise.all([
        loadRules(),
        loadActivity(),
    ]);
}

async function removeRule(domain) {
    await fetch(`/api/rules/${encodeURIComponent(domain)}`, {
        method: "DELETE",
    });
    await loadRules();
}

async function saveFeedback(domain, verdict, promote) {
    await fetch("/api/feedback", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
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
    const [stats, status, highRisk] = await Promise.all([
        fetch("/api/stats").then((res) => res.json()),
        fetch("/api/status").then((res) => res.json()),
        fetch("/api/analysis?min_risk=70&limit=12").then((res) => res.json()),
    ]);

    renderStats(stats);
    renderServiceStatus(status);
    renderNetworkSummary(status);
    renderAnalysis(highRisk, "overview-high-risk");
    renderSettings(status);
    document.getElementById("updated").textContent =
        new Date().toLocaleTimeString();
}

async function loadSettings() {
    const payload = await fetch("/api/settings").then((res) => res.json());
    renderSettingsControls(payload);
}

async function loadMetrics() {
    const [metrics, status] = await Promise.all([
        fetch("/api/metrics/decisions").then((res) => res.json()),
        fetch("/api/status").then((res) => res.json()),
    ]);
    renderDecisionMetrics(metrics);
    renderIntelligence(metrics, status);
}

async function loadTables() {
    const suffix = paramsForTables();
    const [analysis, devices] = await Promise.all([
        fetch(`/api/analysis${suffix}`).then((res) => res.json()),
        fetch(`/api/devices${suffix}`).then((res) => res.json()),
    ]);

    renderAnalysis(analysis);
    renderDevices(devices);
}

async function loadActivity() {
    const suffix = paramsForTables();
    const [events, analysis, actions] = await Promise.all([
        fetch(`/api/events${suffix}`).then((res) => res.json()),
        fetch(`/api/analysis${suffix}`).then((res) => res.json()),
        fetch(`/api/actions${suffix}`).then((res) => res.json()),
    ]);

    renderActivity(events, analysis, actions);
}

async function loadRules() {
    const rules = await fetch(`/api/rules${paramsForTables()}`).then((res) => res.json());
    renderRules(rules);
}

async function loadReputations() {
    const reputations = await fetch(`/api/reputations${paramsForTables()}`).then((res) => res.json());
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
    const response = await fetch("/api/settings", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(settingPayload()),
    }).then((res) => res.json());

    settingsMessage(response.restart_required
        ? "Settings saved. Restart required."
        : "Settings saved.");
});
document.getElementById("restart-required").addEventListener("click", () => serviceAction("restart"));
document.getElementById("service-status-button").addEventListener("click", async () => {
    const status = await fetch("/api/status").then((res) => res.json());
    settingsMessage(`Status loaded. Events: ${status.database?.events ?? 0}, processed: ${status.database?.processed ?? 0}.`);
});
document.querySelectorAll("[data-service-action]").forEach((item) => {
    item.addEventListener("click", () => serviceAction(item.dataset.serviceAction));
});

async function serviceAction(action) {
    const response = await fetch(`/api/services/${action}`, {
        method: "POST",
    }).then((res) => res.json());

    if (response.ok) {
        settingsMessage(response.message);
    } else {
        settingsMessage(response.message || `Run: ${response.command}`);
    }
}
setInterval(loadOverview, __OVERVIEW_POLL_INTERVAL_MS__);
setInterval(loadMetrics, __METRICS_POLL_INTERVAL_MS__);
setInterval(() => Promise.all([loadTables(), loadActivity()]), __TABLES_POLL_INTERVAL_MS__);
setInterval(() => Promise.all([loadRules(), loadReputations()]), __SLOW_POLL_INTERVAL_MS__);
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


def get_decision_metrics() -> dict[str, Any]:
    """
    Return aggregate decision metrics for the dashboard/API.
    """

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


def create_app() -> Flask:
    """
    Create the Flask dashboard application.
    """

    app = Flask(__name__)

    @app.get("/")
    def home():
        html = HTML
        replacements = {
            "__OVERVIEW_POLL_INTERVAL_MS__": settings.dashboard_overview_poll_interval_ms,
            "__METRICS_POLL_INTERVAL_MS__": settings.dashboard_metrics_poll_interval_ms,
            "__TABLES_POLL_INTERVAL_MS__": settings.dashboard_tables_poll_interval_ms,
            "__SLOW_POLL_INTERVAL_MS__": settings.dashboard_slow_poll_interval_ms,
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

    @app.get("/api/explain/<path:domain>")
    def explain(domain: str):
        return jsonify(
            explain_domain(
                domain,
            )
        )

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

            report = run_health_checks()

        except Exception as exc:
            logger.exception("Unable to run health checks.")
            return jsonify(
                {
                    "overall_status": "unknown",
                    "checks": [],
                    "version": "0.4",
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


app = create_app()


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
