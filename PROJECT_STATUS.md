# PiHole-AI Project Status

**Last Updated:** 2026-07-08

## Overview

PiHole-AI is a local AI-powered analysis engine for Pi-hole that automatically classifies queried domains and stores the results for future use.

The project is designed around a modular architecture with deterministic classifiers first and a local LLM as a fallback.

Current classifier order:

```
Rule Engine
      ↓
Reputation Classifier
      ↓
Threat Intel Classifier
      ↓
Heuristics Engine
      ↓
AI Classifier (Ollama)
```

Only unknown domains reach the AI model, minimizing inference time and hardware usage.

---

# Current Architecture

```
collector/
    scan.py

core/
    config.py
    db.py
    logger.py

engine/
    analyzer.py
    engine.py
    models.py
    ollama_client.py
    prompts.py

    classifiers/
        __init__.py
        pipeline.py
        rule_engine.py
        heuristics.py
        ai_classifier.py
```

---

# Components

## Collector

Responsible for reading Pi-hole's FTL database.

Current behaviour:

* Reads new rows from `queries`
* Tracks the last processed Pi-hole query ID
* Inserts events into the local SQLite database
* Runs continuously

Status:

* ✅ Working

---

## Database

Stores:

* events
* analysis cache

Implemented:

* database initialization
* insert_event()
* get_unprocessed_events()
* save_analysis()
* get_analysis()
* analysis_exists()
* mark_processed_by_domain()
* database_stats()

Status:

* ✅ Working

---

## Ollama Client

Responsibilities:

* communicate with local Ollama server
* health checks
* model discovery
* validation
* inference

Features:

* server validation
* model validation
* latency measurement
* structured logging

Status:

* ✅ Working

---

## Analyzer

High-level coordinator.

Current responsibility:

```
AnalysisRequest
        ↓
ClassifierPipeline
        ↓
AnalysisResult
```

Contains almost no business logic.

Status:

* ✅ Working

---

## Classifier Pipeline

Runs classifiers in order until one returns an AnalysisResult.

Current order:

1. RuleEngine
2. HeuristicsEngine
3. AIClassifier

Designed to be easily extended.

Status:

* ✅ Working

---

## Rule Engine

Fast deterministic classifier.

Current rules include:

* localhost
* reverse DNS (.arpa)
* RFC1918 reverse lookup
* common local infrastructure

Returns an AnalysisResult immediately.

Status:

* ✅ Working

---

## Heuristics Engine

Performs lightweight analysis before AI.

Current implementation:

* placeholder framework

Future ideas:

* entropy detection
* suspicious TLDs
* long/random domains
* DGAs
* punycode detection
* excessive subdomains

Status:

* 🚧 Basic implementation

---

## AI Classifier

Uses Ollama when deterministic methods cannot classify a domain.

Features:

* JSON prompt
* structured output
* response validation
* fallback handling
* logging

Returns:

* AnalysisResult

Status:

* ✅ Working

---

## Prompt System

Provides:

* SYSTEM_PROMPT
* build_domain_prompt()
* build_health_check_prompt()

Prompt requests strict JSON output.

Status:

* ✅ Working

---

# Processing Flow

```
Pi-hole
    ↓
Collector
    ↓
events table
    ↓
Analysis Engine
    ↓
Unique domains
    ↓
Classifier Pipeline
    ↓
Analysis cache
    ↓
Mark all matching events processed
```

Duplicate events for the same domain are processed only once.

---

# Performance Optimizations

Implemented:

* unique domain processing
* analysis cache
* mark_processed_by_domain()
* batched processing
* modular pipeline

Future improvements:

* asynchronous inference
* parallel rule evaluation
* configurable worker threads
* automatic cache expiration
* queue prioritization

---

# Current Milestone

Version:

**v0.2.0**

Completed:

* Modular architecture
* Local AI integration
* Analysis caching
* Classifier pipeline
* Database layer
* Event ingestion
* Logging
* Health checks

---

# Next Milestones

## v0.3

* BaseClassifier abstract class
* Category constants or Enum
* Improved AI validation
* Metadata-aware prompts
* Unit tests

---

## v0.4

REST API

Possible endpoints:

* GET /analysis
* GET /events
* GET /stats
* GET /health

---

## v0.5

Web dashboard

Potential features:

* live event stream
* risk visualization
* domain search
* cache browser
* AI explanations
* system health

---

## v0.6

Local learning and threat intelligence

Implemented first slice:

* `domain_reputation` table built from observed DNS history
* `pihole-ai learn` command for periodic reputation updates
* `ReputationClassifier` that uses local behavior before Ollama
* `threat_intel` table for known-bad feed indicators
* `pihole-ai intel import-hosts` for local hosts-style feeds
* `ThreatIntelClassifier` that uses imported feed indicators before Ollama
* learned alert/suggest-block audit records
* manual allow/block rules influence learned scores

Planned features:

* remote feed downloading for URLhaus, curated hosts files, or similar sources
* manual allow rules override learned and feed-based suspicion
* learned results start as alert/suggest-block decisions, not automatic blocks

Initial learning signals:

* sudden query spikes
* repeated beacon-like timing
* suspicious domains seen across multiple devices
* previous heuristic or AI warnings
* repeated action audit suggestions
* manual allow/block feedback

---

## Long-Term Goals

* Threat intelligence integration
* Local reputation learning
* Reputation providers
* Scheduled re-analysis
* Domain clustering
* Device behaviour analysis
* Whitelist/blacklist management
* Plugin architecture
* Multi-model AI support
* Export and reporting
* Docker deployment

---

# Development Principles

* Prefer readability over cleverness.
* Keep modules focused on a single responsibility.
* Use dataclasses instead of dictionaries where practical.
* Keep deterministic logic separate from AI logic.
* Avoid unnecessary dependencies.
* Make components independently testable.
* Optimize for Raspberry Pi hardware.

---

# Current Status

The project is in a stable state.

The analysis pipeline, database layer, and AI integration are functional and committed to Git.

The next phase is focused on hardening the architecture, expanding the classifier framework, and building user-facing services (API and dashboard).
