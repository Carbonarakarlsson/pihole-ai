# Epic 3.4: AI Reliability, Evaluation, and Explainability

## Objective

Make AI-assisted decisions measurable, reproducible, benchmarkable, and
explainable without changing existing runtime decision outcomes.

Epic 3.4 should add observability and evaluation surfaces around the existing
evidence-based classifier pipeline. It must not change the default classifier
order, decision thresholds, rule precedence, cache policy, or final decision
semantics.

## Current Architecture

Inspected implementation files:

- `engine/classifiers/pipeline.py`
- `engine/classifiers/ai_classifier.py`
- `engine/classifiers/reputation.py`
- `engine/classifiers/threat_intel.py`
- `engine/classifiers/heuristics.py`
- `engine/models.py`
- `engine/prompts.py`
- `engine/ollama_client.py`
- `engine/decision_engine.py`
- `engine/evidence.py`
- `engine/engine.py`
- `pihole_ai/evaluate.py`
- `pihole_ai/explain.py`
- `pihole_ai/feedback.py`
- `pihole_ai/cli.py`
- `core/db.py`
- `core/migrations.py`
- `core/sqlite_policy.py`
- `core/config.py`
- `ui/dashboard.py`
- `tests/test_classifiers.py`
- `tests/test_evaluate.py`
- `tests/test_explain.py`
- `tests/test_dashboard.py`
- `tests/test_db.py`

### Runtime Flow

`AnalysisEngine.process_once()` reads pending domains, checks the latest cached
analysis, and only invokes the analyzer when no usable cache entry exists.
Cache usability currently depends on:

- an existing analysis row
- confidence greater than zero
- `PIHOLE_AI_CACHE_TTL`
- the analysis timestamp

On a cache hit, the engine marks matching domain events processed and does not
create a new immutable decision history row. On a stale or missing cache entry,
it builds an `AnalysisRequest` with `DomainMetadata`, runs the analyzer, saves
the compatible `analysis` projection plus immutable decision history, updates
learned reputation, applies action policy, and marks events processed.

### Classifier Execution Order

`ClassifierPipeline` runs classifiers in this order:

1. `RuleEngine`
2. `ReputationClassifier`
3. `ThreatIntelClassifier`
4. `HeuristicsEngine`
5. `AIClassifier`

The pipeline accumulates structured `EvidenceItem` records, then sends an
`EvidenceCollection` to `DecisionEngine`.

### Stop And Skip Behavior

The pipeline already records a compact in-memory classifier trace with:

- classifier name
- status: `consulted`, `skipped`, or `failed`
- evidence count
- latency in milliseconds
- skip or failure reason

AI may be skipped before invocation when `DecisionEngine.should_skip_ai()` sees
decisive deterministic evidence or sufficiently confident deterministic
evidence. If decisive evidence appears before the end of the pipeline, remaining
classifiers are marked skipped and the pipeline stops.

### Decision Policy

`DecisionEngine` owns final verdict calculation:

- decisive evidence wins by precedence
- otherwise evidence is aggregated by signed score and confidence
- repeated evidence from the same classifier/type has diminishing influence
- AI-only decisions have a confidence ceiling
- final compatible `AnalysisResult` uses the decision result

The decision engine already records:

- final verdict
- risk score
- confidence as a normalized float
- category
- source
- explanation
- decisive evidence IDs
- classifier trace
- conflicts
- policy version
- application version

### AI Invocation Rules

`AIClassifier` uses local Ollama through `OllamaClient`.

AI is not called when:

- `AI_ENABLED=false`
- the per-minute call limit is exhausted
- the classifier is in cooldown
- deterministic evidence made AI unnecessary before the AI stage

Safe unknown results are returned for disabled, rate-limited, cooldown, timeout,
and parse-error paths. These paths preserve compatibility with the rest of the
pipeline by returning evidence or an `AnalysisResult` rather than raising.

Current AI settings:

- `AI_ENABLED`
- `AI_MAX_CALLS_PER_MINUTE`
- `AI_COOLDOWN_SECONDS`
- `AI_TIMEOUT_SECONDS`
- `PIHOLE_AI_OLLAMA_URL`
- `PIHOLE_AI_OLLAMA_MODEL`

### Retry Behavior

There is no explicit AI retry loop today. `OllamaClient.generate()` performs one
chat request. Epic 3.4 telemetry should record retry count as zero unless a
future implementation adds retries behind a compatibility-preserving option.

### Timeout Behavior

`OllamaClient` is constructed with `settings.ai_timeout_seconds`. Timeout
exceptions are classified into the safe unknown `ai_timeout` result, recorded in
AI metrics, and trigger cooldown.

Slow responses whose elapsed time reaches the configured timeout threshold also
trigger cooldown.

### Confidence Handling

There are two confidence scales:

- AI model responses use integer `0..100`.
- Evidence and decisions use normalized floats `0.0..1.0`.

Current benchmark rows report integer confidence from `AnalysisResult`.
Decision records store normalized confidence. There is no persisted calibrated
confidence band.

### Prompt And Model Metadata

The AI prompt is built by `engine/prompts.py`.

Existing behavior:

- `SYSTEM_PROMPT` is a static instruction string.
- `build_domain_prompt()` serializes domain metadata as JSON.
- dataclass metadata is converted with `dataclasses.asdict()`.
- dict metadata is preserved.
- null metadata becomes `{}`.

There is no explicit prompt version, prompt hash, prompt template ID, or prompt
comparison framework today.

### Explain Capabilities

`pihole-ai explain <domain>` and `/api/explain/<domain>` already expose:

- rule match
- threat-intel hit
- reputation
- latest analysis
- final decision
- decisive evidence
- risk evidence
- safety evidence
- neutral evidence
- compact classifier trace
- conflicts
- recent actions
- immutable decision history
- decision selection by ID
- decision comparison

The dashboard Explain panel uses the same API and keeps feedback buttons in the
details panel.

### Feedback Storage

Feedback is stored as `action_audit` rows with action `feedback`. When a current
decision exists, feedback records the decision ID in `decision_ref`. Feedback
can optionally promote safe or bad labels into manual allow/block rules.

Historical decision evidence is never rewritten by feedback.

### Evaluation Tooling

`pihole_ai/evaluate.py` supports fixture-based benchmark runs from JSON or CSV.
It can:

- load labeled cases
- run the classifier pipeline
- optionally include AI
- compare expected and actual category
- compare expected and actual risk within a tolerance
- print text or JSON results

Phase 3 adds persisted benchmark runs, fixture digests, per-sample results, and
baseline regression comparison through the `benchmark` command namespace. Model
matrix runs, prompt matrix runs, classifier-order experiments, and dashboard
benchmark pages remain future work.

### Dashboard AI Metrics

The dashboard currently surfaces operational AI counters from database metrics,
including:

- enabled state
- calls
- skipped calls
- parse errors
- timeouts
- rate-limit skips
- cooldown skips
- disabled skips

It now has a Reliability page for accuracy, calibrated confidence, benchmark
history, classifier utilization, cache efficiency, latency summaries, and
telemetry volume diagnostics.

### Database State

Current schema version is 13 after the Phase 4 confidence-calibration
migration.

Relevant existing tables:

- `analysis`: latest compatible analysis projection
- `decision_records`: latest structured decision projection per domain
- `decision_history`: immutable append-only decision records
- `decision_history_evidence`: bounded evidence items for each immutable
  decision
- `action_audit`: actions and feedback with optional `decision_ref`
- `app_state`: counters and small runtime state
- `pipeline_telemetry_runs` and `pipeline_telemetry_stages`: Phase 1/2
  pipeline timing and explainability sidecar data
- `benchmark_runs` and `benchmark_results`: Phase 3 persisted benchmark runs,
  fixture digests, metrics, and per-sample results
- `calibration_profiles` and `calibration_bins`: Phase 4 reporting-only
  confidence calibration profiles built from completed benchmark runs
- threat-intelligence source, state, generation, entry, and audit tables

SQLite access is centralized through `core/sqlite_policy.py`, `core/db.py`, and
`core/migrations.py`. Runtime reads should remain read-only where possible, and
only migration mode may establish persistent journal settings.

## Identified Gaps

1. Cache hits are not recorded as explainable pipeline events.
2. The classifier trace is compact and lossy; it omits stage start/end times,
   result summaries, confidence evolution, cache state, AI invocation details,
   prompt version, model version, retry count, timeout state, and benchmark
   linkage.
3. AI model and prompt identity are not versioned in persisted telemetry.
4. No prompt hash or prompt template version exists.
5. AI retry count is not modeled, even as an explicit zero.
6. Confidence is stored as raw score/normalized float, not calibrated into
   documented bands.
7. Model/prompt/threshold/classifier-order matrix execution is not yet
   automated.
8. Benchmark retention, dashboard views, and CI policy integration are not yet
   implemented.
9. Explain output lacks dashboard-specific benchmark context.
11. Dashboard AI visibility is operational rather than evaluative.
12. Feedback is linked to decisions but not summarized by benchmark/calibration
    tooling.
13. No first-class telemetry retention policy exists.

## Design Principles

- Preserve existing runtime outcomes.
- Treat telemetry as sidecar data linked to existing decisions.
- Keep deterministic classifiers ahead of AI by default.
- Never make dashboard GET routes mutate state.
- Keep benchmark experiments separate from runtime appliance policy.
- Avoid storing raw prompts, raw model responses, credentials, or feed URLs.
- Sanitize metadata using the existing evidence metadata principles.
- Keep all SQLite access behind the established policy layer.
- Make telemetry optional enough that a recording failure cannot block
  classification unless explicitly configured for tests.

## Proposed Schema

Recommended migration: **version 11**,
`ai_reliability_pipeline_telemetry`.

Migration 11 should be additive, idempotent, and data-preserving.

### `pipeline_runs`

One row per non-cache classification run, and optionally one row per cache hit
when cache telemetry is enabled.

```sql
CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    started_at REAL NOT NULL,
    completed_at REAL,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    trigger TEXT NOT NULL DEFAULT 'unknown',
    cache_status TEXT NOT NULL DEFAULT 'unknown',
    force_refresh INTEGER NOT NULL DEFAULT 0,
    stop_reason TEXT NOT NULL DEFAULT '',
    final_decision_id TEXT,
    final_verdict TEXT NOT NULL DEFAULT '',
    final_risk_score INTEGER,
    final_category TEXT NOT NULL DEFAULT '',
    final_confidence REAL,
    final_confidence_band TEXT NOT NULL DEFAULT '',
    contributing_classifiers_json TEXT NOT NULL DEFAULT '[]',
    benchmark_run_id TEXT,
    request_metadata_json TEXT NOT NULL DEFAULT '{}',
    application_version TEXT NOT NULL DEFAULT '',
    schema_version INTEGER,
    created_at REAL NOT NULL,
    FOREIGN KEY (final_decision_id)
        REFERENCES decision_history(decision_id)
        ON DELETE SET NULL
);
```

Recommended indexes:

```sql
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_domain_created
ON pipeline_runs(domain, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_pipeline_runs_decision
ON pipeline_runs(final_decision_id);

CREATE INDEX IF NOT EXISTS idx_pipeline_runs_benchmark
ON pipeline_runs(benchmark_run_id);
```

### `pipeline_stage_runs`

One row per classifier stage.

```sql
CREATE TABLE IF NOT EXISTS pipeline_stage_runs (
    stage_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    classifier TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at REAL,
    completed_at REAL,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    result_category TEXT NOT NULL DEFAULT '',
    result_risk_score INTEGER,
    result_confidence REAL,
    confidence_before REAL,
    confidence_after REAL,
    skip_reason TEXT NOT NULL DEFAULT '',
    stop_reason TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    timeout INTEGER NOT NULL DEFAULT 0,
    retry_count INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    FOREIGN KEY (run_id)
        REFERENCES pipeline_runs(run_id)
        ON DELETE CASCADE
);
```

Recommended indexes:

```sql
CREATE INDEX IF NOT EXISTS idx_pipeline_stage_runs_run_ordinal
ON pipeline_stage_runs(run_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_pipeline_stage_runs_classifier_status
ON pipeline_stage_runs(classifier, status, created_at DESC);
```

### `ai_invocations`

One row per AI stage attempt or AI skip. This table stores safe operational
metadata, not raw prompts or raw model responses.

```sql
CREATE TABLE IF NOT EXISTS ai_invocations (
    invocation_id TEXT PRIMARY KEY,
    run_id TEXT,
    stage_id TEXT,
    domain TEXT NOT NULL,
    status TEXT NOT NULL,
    skip_reason TEXT NOT NULL DEFAULT '',
    invocation_reason TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT 'ollama',
    model TEXT NOT NULL DEFAULT '',
    prompt_version TEXT NOT NULL DEFAULT '',
    prompt_hash TEXT NOT NULL DEFAULT '',
    temperature REAL,
    timeout_seconds INTEGER,
    started_at REAL,
    completed_at REAL,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    retry_count INTEGER NOT NULL DEFAULT 0,
    response_schema_valid INTEGER,
    response_size_bytes INTEGER NOT NULL DEFAULT 0,
    response_hash TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    cooldown_started INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    FOREIGN KEY (run_id)
        REFERENCES pipeline_runs(run_id)
        ON DELETE SET NULL,
    FOREIGN KEY (stage_id)
        REFERENCES pipeline_stage_runs(stage_id)
        ON DELETE SET NULL
);
```

Recommended indexes:

```sql
CREATE INDEX IF NOT EXISTS idx_ai_invocations_domain_created
ON ai_invocations(domain, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_invocations_model_status
ON ai_invocations(model, status, created_at DESC);
```

### `confidence_calibration_profiles`

Calibration profiles describe how normalized confidence maps to product-facing
bands. They should not change risk or verdict calculation.

```sql
CREATE TABLE IF NOT EXISTS confidence_calibration_profiles (
    profile_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scope TEXT NOT NULL,
    version TEXT NOT NULL,
    bands_json TEXT NOT NULL,
    source_benchmark_run_id TEXT,
    sample_count INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    active INTEGER NOT NULL DEFAULT 0
);
```

Example band vocabulary:

- `very_low`
- `low`
- `medium`
- `high`
- `very_high`

The first implementation may ship a static default profile and add empirical
profile generation later.

### `benchmark_runs`

```sql
CREATE TABLE IF NOT EXISTS benchmark_runs (
    benchmark_run_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    fixture_path TEXT NOT NULL DEFAULT '',
    fixture_hash TEXT NOT NULL,
    started_at REAL NOT NULL,
    completed_at REAL,
    total_cases INTEGER NOT NULL DEFAULT 0,
    category_accuracy REAL NOT NULL DEFAULT 0,
    risk_accuracy REAL NOT NULL DEFAULT 0,
    average_risk_error REAL NOT NULL DEFAULT 0,
    regression_status TEXT NOT NULL DEFAULT 'unknown',
    baseline_run_id TEXT,
    config_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    FOREIGN KEY (baseline_run_id)
        REFERENCES benchmark_runs(benchmark_run_id)
        ON DELETE SET NULL
);
```

### `benchmark_case_results`

```sql
CREATE TABLE IF NOT EXISTS benchmark_case_results (
    case_result_id TEXT PRIMARY KEY,
    benchmark_run_id TEXT NOT NULL,
    pipeline_run_id TEXT,
    domain TEXT NOT NULL,
    expected_category TEXT NOT NULL,
    actual_category TEXT NOT NULL,
    expected_risk INTEGER NOT NULL,
    actual_risk INTEGER NOT NULL,
    risk_error INTEGER NOT NULL,
    category_match INTEGER NOT NULL,
    risk_within_tolerance INTEGER NOT NULL,
    confidence REAL,
    confidence_band TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    prompt_version TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    latency_ms INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    FOREIGN KEY (benchmark_run_id)
        REFERENCES benchmark_runs(benchmark_run_id)
        ON DELETE CASCADE,
    FOREIGN KEY (pipeline_run_id)
        REFERENCES pipeline_runs(run_id)
        ON DELETE SET NULL
);
```

## Migration Strategy

1. Add migration 11 after the existing migration 10.
2. Use only additive `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT
   EXISTS` statements.
3. Do not rewrite existing `analysis`, `decision_records`, `decision_history`,
   `decision_history_evidence`, `action_audit`, or threat-intelligence rows.
4. Do not backfill historical telemetry. Historical decisions should remain
   explainable through existing decision history, with telemetry shown as
   unavailable.
5. Keep migration execution under `core.migrations.migrate_connection()`.
6. Use `core/sqlite_policy.py` migration mode only.
7. Add migration tests proving idempotence, preservation of existing decisions,
   preservation of existing threat-intelligence data, and successful upgrade
   from schema 10.

## Telemetry Design

### Runtime Models

Add internal dataclasses in a new module such as `engine/telemetry.py`:

- `PipelineRunTelemetry`
- `ClassifierStageTelemetry`
- `AIInvocationTelemetry`
- `ConfidenceSnapshot`

These models should be plain data carriers with JSON-safe serialization. They
should not own decision policy.

### Pipeline Recording

The pipeline should create one `PipelineRunTelemetry` per analyzer invocation.
Each classifier stage should record:

- ordinal
- classifier name
- status
- start/end/duration
- evidence count
- result category/risk/confidence when available
- confidence before and after decision aggregation, if computed
- skip reason
- stop reason
- error code
- timeout flag
- retry count

To avoid changing outcomes, stage telemetry should wrap existing calls and
observe returned evidence/results. It should not alter evidence order, decision
inputs, or exception handling behavior.

### Cache Recording

Cache telemetry belongs in `AnalysisEngine`, because cache hits bypass
`Analyzer` and `ClassifierPipeline`.

Recommended cache statuses:

- `hit`
- `miss`
- `stale`
- `disabled`
- `bypass`
- `unknown`

For cache hits, record either:

- a lightweight `pipeline_runs` row with `cache_status='hit'` and no stage rows,
  or
- an app-state metric plus dashboard aggregate only

The preferred design is the lightweight row because it allows explain and cache
efficiency dashboards to show why a fresh pipeline timeline is absent.

### AI Invocation Recording

`AIClassifier` should record an `ai_invocations` row for both calls and skips:

- `status='success'`
- `status='disabled'`
- `status='rate_limited'`
- `status='cooldown'`
- `status='timeout'`
- `status='parse_error'`
- `status='backend_error'`
- `status='skipped_by_pipeline'`

Prompt telemetry should store:

- prompt version
- prompt hash
- model
- temperature
- timeout seconds
- response size/hash

Do not persist raw prompt text or raw model response by default.

### Prompt Versioning

Add a prompt identifier next to `SYSTEM_PROMPT`, for example:

```python
PROMPT_VERSION = "domain-classification-v1"
```

Also compute a stable SHA-256 hash of the system prompt plus user prompt
template. Store the hash in telemetry and benchmark configuration.

Prompt versioning is metadata only in Epic 3.4. It must not change the prompt
contents unless a benchmark experiment explicitly opts into a different prompt.

### Stop Reasons

Use a bounded vocabulary:

- `cache_hit`
- `decisive_evidence`
- `deterministic_evidence_sufficient`
- `pipeline_exhausted`
- `classifier_error`
- `ai_disabled`
- `ai_rate_limited`
- `ai_cooldown`
- `ai_timeout`
- `ai_parse_error`

The existing free-text reasons can still be stored in metadata or details.

### Metrics

Add aggregate helpers in `core/db.py` for:

- classifier utilization
- classifier latency percentiles
- AI status counts
- cache hit/miss/stale counts
- confidence-band distribution
- benchmark summary history
- feedback-linked decision outcomes

Dashboard GET routes must use read-only database helpers and must not trigger
migrations implicitly.

## Decision Telemetry

Persist sidecar decision telemetry by linking `pipeline_runs.final_decision_id`
to `decision_history.decision_id`.

Decision telemetry should include:

- final verdict
- risk score
- category
- normalized confidence
- calibrated confidence band
- contributing classifiers
- latency
- benchmark run ID when classification was part of a benchmark
- feedback linkage through existing `action_audit.decision_ref`

The existing immutable decision row remains the source of truth for final
decision content. Pipeline telemetry explains how the system got there.

## Confidence Calibration

Calibration should be classifier-agnostic and model-agnostic by default.

Recommended first step:

1. Define product-facing confidence bands over normalized confidence:
   - `very_low`: `0.00 <= confidence < 0.20`
   - `low`: `0.20 <= confidence < 0.40`
   - `medium`: `0.40 <= confidence < 0.70`
   - `high`: `0.70 <= confidence < 0.90`
   - `very_high`: `0.90 <= confidence <= 1.00`
2. Persist the band assigned at decision time.
3. Report empirical accuracy per band from labeled benchmark results and
   feedback-linked decisions.
4. Later calibration profiles may adjust band boundaries using benchmark data,
   but runtime verdict calculation should not use calibrated bands until a
   separate policy epic explicitly changes decision behavior.

This avoids model-specific assumptions while still making confidence auditable.

## Benchmark Design

Extend `pihole_ai/evaluate.py` without breaking the current command:

```bash
pihole-ai evaluate PATH [--risk-tolerance N] [--include-ai] [--json]
```

### New Capabilities

Add benchmark-run configuration for:

- model list
- prompt version list
- threshold list
- classifier order list
- include/exclude AI
- cache disabled for benchmark repeatability
- output persistence
- baseline comparison

Implemented Phase 3 commands:

```bash
pihole-ai benchmark run PATH [--include-ai] [--json]
pihole-ai benchmark list [--json]
pihole-ai benchmark show RUN_ID [--json]
pihole-ai benchmark compare BASELINE_RUN_ID CANDIDATE_RUN_ID [--json]
```

Backward compatibility requirement:

- Existing `pihole-ai evaluate PATH` behavior must continue to work.
- The `benchmark` namespace is additive and does not change the legacy
  positional `evaluate PATH` form.

### Regression Detection

Regression detection should compare a candidate run to a selected baseline:

- category accuracy delta
- risk accuracy delta
- average risk error delta
- high-risk false negative count
- benign false positive count
- p95 latency delta
- AI timeout/parse-error increase

Initial default thresholds:

- fail on any increase in high-risk false negatives
- fail when category accuracy drops by more than 2 percentage points
- fail when p95 latency increases by more than 25 percent

These should be configurable in benchmark metadata, not hardcoded into runtime
classification.

### Reproducibility

Benchmark records should persist:

- fixture hash
- application version
- schema version
- classifier order
- model
- prompt version/hash
- thresholds
- AI settings
- cache policy
- run timestamp

## Explainability Design

Enhance `pihole-ai explain <domain>` and `/api/explain/<domain>` with telemetry
when available.

Recommended explain additions:

- `pipeline_timeline`
- `classifier_tree`
- `skipped_stages`
- `timing`
- `confidence_evolution`
- `cache`
- `ai_invocation`
- `benchmark`
- `feedback_history`

Example JSON shape:

```json
{
  "telemetry": {
    "run_id": "run_...",
    "cache": {
      "status": "miss",
      "ttl_seconds": 86400
    },
    "pipeline_timeline": [
      {
        "ordinal": 1,
        "classifier": "rule-engine",
        "status": "consulted",
        "latency_ms": 2,
        "evidence_count": 0
      }
    ],
    "confidence_evolution": [
      {
        "stage": "threat-intel",
        "confidence_before": 0.0,
        "confidence_after": 0.92,
        "band": "very_high"
      }
    ],
    "ai_invocation": {
      "status": "skipped_by_pipeline",
      "reason": "decisive_evidence",
      "model": "llama3.2:1b",
      "prompt_version": "domain-classification-v1"
    }
  }
}
```

Historical explain should load telemetry by decision ID when a pipeline run is
linked to that decision. For older decisions, explain should display the
existing decision data and mark telemetry as unavailable.

## Dashboard Changes

Keep the existing Flask/plain HTML/CSS/JS stack.

Add AI Reliability views under the existing Intelligence area:

### Accuracy

- latest benchmark summary
- baseline comparison
- category accuracy
- risk accuracy
- false positives
- false negatives
- feedback-linked corrections

### Latency

- pipeline p50/p95/p99 latency
- per-classifier latency
- AI latency
- timeout counts

### Confidence

- confidence-band distribution
- empirical accuracy per band from benchmark data
- recent low-confidence decisions

### Cache

- hit/miss/stale counts
- cache hit ratio
- cache age distribution
- domains reprocessed because cache was stale

### Classifier Utilization

- consulted/skipped/failed counts per classifier
- stop reasons
- decisive evidence sources
- AI skip reasons

### Benchmark History

- saved benchmark runs
- baseline marker
- regression status
- model/prompt comparison summary

Dashboard APIs should be read-only:

```text
GET /api/ai/telemetry
GET /api/ai/latency
GET /api/ai/confidence
GET /api/ai/cache
GET /api/ai/benchmarks
GET /api/ai/benchmarks/<run_id>
```

No raw prompts, raw responses, secrets, or full credential-bearing URLs should
be returned.

## CLI Changes

Preserve existing commands:

```bash
pihole-ai explain DOMAIN
pihole-ai explain DOMAIN --json
pihole-ai explain DOMAIN --history
pihole-ai explain DOMAIN --decision DECISION_ID
pihole-ai explain DOMAIN --compare OLDER_ID NEWER_ID
pihole-ai evaluate PATH
```

Proposed additive options:

```bash
pihole-ai explain DOMAIN --timeline
pihole-ai explain DOMAIN --telemetry
pihole-ai explain DOMAIN --feedback
pihole-ai evaluate run PATH --save
pihole-ai evaluate history
pihole-ai evaluate show RUN_ID
pihole-ai evaluate compare RUN_ID BASELINE_RUN_ID
pihole-ai evaluate matrix PATH --models MODEL[,MODEL...] --prompts PROMPT[,PROMPT...]
```

If argparse compatibility with the legacy positional `evaluate PATH` becomes
awkward, prefer keeping `evaluate PATH` as the default path and adding optional
flags before introducing nested subcommands.

## Connection And Transaction Strategy

- All new database access must use `core/sqlite_policy.py`.
- Runtime writes should go through `core/db.py` helpers.
- Read-only CLI and dashboard routes should use read-only helpers.
- Benchmark persistence should use short explicit write transactions.
- Network calls to Ollama must occur outside write transactions.
- Prompt rendering and response parsing must occur outside write transactions.
- Telemetry writes should happen after classification completes, using a short
  transaction.
- If telemetry persistence fails, log the failure and keep the classification
  result unless strict test mode is explicitly enabled.

## Security And Privacy

- Do not persist raw prompts by default.
- Do not persist raw model responses by default.
- Store hashes and sizes for correlation.
- Reuse metadata sanitization rules for telemetry metadata.
- Redact or omit credential-bearing URLs.
- Bound free-text error summaries.
- Cap stored telemetry payload sizes.
- Add retention cleanup for high-volume telemetry.

## Retention

Add a retention command or maintenance helper in a later phase:

```bash
pihole-ai telemetry prune --days N --dry-run
```

Initial retention policy:

- keep decision history according to existing decision retention
- keep benchmark runs until manually removed
- keep detailed pipeline telemetry for a configurable number of days
- keep aggregates longer than raw stage rows if needed later

Retention can be deferred from the first implementation if storage growth is
documented and dashboard queries remain bounded.

## Test Strategy

### Unit Tests

- pipeline telemetry records all classifiers in order
- decisive evidence records skipped remaining classifiers
- deterministic AI skip records stop/skip reason
- cache hit records cache telemetry and no classifier stages
- AI disabled/rate-limited/cooldown/timeout/parse-error paths record invocation
  status
- prompt version/hash are stable
- raw prompt and raw response are not persisted
- confidence band assignment is deterministic at boundaries
- telemetry persistence failure does not change returned analysis

### Database And Migration Tests

- migration 11 is additive and idempotent
- existing analysis rows are preserved
- existing decision history is preserved
- existing threat-intelligence data is preserved
- new indexes exist
- read-only telemetry queries do not migrate
- dashboard GET routes do not mutate

### Evaluation Tests

- legacy `evaluate PATH` still works
- saved benchmark run persists summary and case rows
- model comparison records separate runs
- prompt comparison records prompt version/hash
- threshold comparison records config
- baseline comparison detects regressions
- JSON output remains serializable

### Explain Tests

- explain includes telemetry when linked run exists
- explain degrades cleanly for older decisions without telemetry
- historical decision explain resolves telemetry by decision ID
- compare output includes telemetry availability for both decisions
- feedback history remains linked by existing `decision_ref`

### Dashboard Tests

- AI Reliability panels render
- telemetry APIs require authentication
- telemetry APIs are read-only
- confidence chart data is bounded and JSON-safe
- benchmark history renders empty state
- explain panel still works without telemetry

### ResourceWarning And Concurrency Tests

- all telemetry connections close deterministically
- telemetry writes do not hold locks during AI calls
- read-only dashboard polling does not open write connections
- busy database failures produce clean degraded telemetry behavior

## Phased Implementation Plan

Implementation status for `0.5.0b5`:

- Phase 1 complete: telemetry schema, models, persistence helpers, and stats.
- Phase 2 complete: classifier, AI, and cache instrumentation with unchanged
  runtime decisions.
- Phase 3 complete: explain timeline and telemetry integration.
- Phase 4 complete: benchmark persistence, benchmark comparison, confidence
  calibration, reliability metrics, dashboard/API views, and doctor
  diagnostics.
- Deferred: automatic telemetry/calibration retention, feedback-based
  calibration, and dashboard-triggered benchmark/calibration execution.

### Phase 1: Prompt And Telemetry Foundations

- Add prompt version/hash helpers.
- Add telemetry dataclasses.
- Add migration 11 with sidecar tables.
- Add `core/db.py` insert/query helpers.
- Add confidence-band helper.
- Add focused migration and serialization tests.

### Phase 2: Pipeline And AI Recording

- Instrument `ClassifierPipeline` stages.
- Instrument `AIClassifier` calls and skip paths.
- Instrument `AnalysisEngine` cache hits/misses/stale paths.
- Link pipeline runs to saved decision IDs.
- Preserve existing outcomes exactly.

### Phase 3: Explain Surfaces

- Extend `pihole_ai.explain` with optional telemetry sections.
- Extend CLI explain JSON and text output.
- Extend dashboard Explain panel with a compact timeline.
- Add fallback behavior for old decisions without telemetry.

### Phase 4: Benchmark Persistence And Comparison

- Extend evaluation models with run metadata.
- Persist benchmark runs and case results.
- Add model/prompt/threshold/order comparison support.
- Add baseline comparison and regression status.
- Keep legacy `evaluate PATH` compatible.

### Phase 5: Confidence Calibration And Reliability Dashboard

- Add migration 13 for reporting-only calibration profiles and bins.
- Build calibration profiles from completed benchmark runs.
- Reject feedback-based calibration until linked labeled samples are available.
- Add `calibration` and `reliability metrics` CLI commands.
- Add raw and calibrated confidence to explain output.
- Add AI Accuracy, Latency, Confidence, Cache, Classifier Utilization, and
  Benchmark History dashboard views.
- Add bounded read-only APIs.
- Add empty states for no telemetry and no benchmark runs.

### Phase 6: Retention And Operational Hardening

- Add retention/prune support if telemetry volume warrants it.
- Add doctor/status summaries for telemetry health.
- Add field-test checklist for appliance benchmark and dashboard validation.

## Acceptance Criteria

- Existing classifier outcomes remain unchanged for the same inputs and config.
- Existing `pihole-ai explain` and `pihole-ai evaluate PATH` commands remain
  backward compatible.
- Migration 11 is additive, idempotent, and preserves existing runtime data.
- Migration 12 is additive, idempotent, and preserves existing benchmark and
  threat-intelligence data.
- Migration 13 is additive, idempotent, and preserves existing benchmark,
  telemetry, decision, and threat-intelligence data.
- No direct production `sqlite3.connect()` calls bypass `core/sqlite_policy.py`.
- Network and Ollama calls never happen inside write transactions.
- Cache hits, misses, stale cache, AI skips, AI calls, timeouts, parse errors,
  and classifier stops are measurable.
- Prompt version and model identity are persisted for AI attempts without
  storing raw prompts or responses.
- Benchmark runs can be persisted, compared, and checked against a baseline.
- Explain output can show a pipeline timeline when telemetry exists.
- Dashboard can show AI accuracy, latency, raw and calibrated confidence
  distribution, cache efficiency, classifier utilization, and benchmark
  history.
- Dashboard GET routes remain read-only.
- Full normal and ResourceWarning test suites pass.

Status: acceptance criteria for Phases 1-4 are met for `0.5.0b5`. Retention
and feedback-calibration criteria remain intentionally deferred.

## Risks

- Telemetry volume could grow quickly on busy appliances.
- Adding too much data to explain responses could make the dashboard noisy.
- Prompt comparison can accidentally look like runtime policy if CLI wording is
  not clear.
- Confidence calibration can be misunderstood as a decision policy change.
- Persisting model metadata must avoid leaking sensitive prompt or response
  content.
- Benchmarking with local Ollama may be slow and nondeterministic unless model,
  prompt, temperature, and environment are recorded.

## Unresolved Decisions

1. Should cache hits create `pipeline_runs` rows by default, or only aggregate
   cache metrics?
2. What is the default telemetry retention period for an appliance?
3. Should benchmark persistence be opt-in with `--save`, or automatic for all
   benchmark runs?
4. Should prompt alternatives live in code, fixtures, or configuration?
5. Should model comparison execute sequentially only, or allow bounded
   parallelism on non-Raspberry Pi hosts?
6. Feedback-based calibration remains deferred until feedback rows have
   trustworthy labeled-sample linkage.
7. Should dashboard benchmark execution be supported later, or remain CLI-only
   for appliance safety?
