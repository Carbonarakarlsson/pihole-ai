# PiHole-AI v0.5.0b5 Release Notes

`v0.5.0b5` prepares the Epic 3.4 AI reliability, evaluation, and
explainability work for appliance testing.

## Highlights

- Added observational AI pipeline telemetry for classifier order, timing,
  cache hits, skipped stages, stop reasons, AI invocation state, timeout state,
  parse-failure state, model identity, and prompt version.
- Extended explain output with pipeline timelines and AI invocation
  diagnostics while preserving existing decision output.
- Added persisted benchmark runs with per-sample results, fixture digests,
  model/prompt metadata, latency metrics, classifier-source counts, and JSON
  output.
- Added deterministic benchmark comparison with configurable regression
  tolerances and fixture-digest protection.
- Added reporting-only confidence calibration profiles from completed
  benchmark runs.
- Added reliability CLI metrics and dashboard/API views for accuracy,
  confidence distributions, calibrated confidence, false-positive and
  false-negative counts, latency, AI/cache utilization, benchmark history, and
  telemetry volume diagnostics.
- Added doctor diagnostics for stale calibration profiles and incomplete
  telemetry runs.

## Database Migrations

This beta adds additive, idempotent migrations:

- `11` - `ai_reliability_pipeline_telemetry`
- `12` - `ai_benchmark_history`
- `13` - `ai_confidence_calibration`

The migrations preserve existing decisions, evidence, threat-intelligence
generations, rules, reputation, feedback, and benchmark data.

## Upgrade Notes

Upgrade the appliance wheel in the stable virtual environment, then run:

```bash
sudo /usr/local/bin/pihole-ai upgrade
sudo /usr/local/bin/pihole-ai restart
```

Run diagnostics after upgrade:

```bash
pihole-ai db status
pihole-ai doctor
pihole-ai telemetry stats
pihole-ai reliability metrics
```

## Calibration Safety

Confidence calibration is reporting-only. It does not change classifier order,
thresholds, AI retry behavior, AI timeout behavior, cooldowns, rate limits,
cache behavior, blocking, allowing, or any enforcement action. Raw confidence
remains visible and authoritative for runtime decisions.

## Known Limitations

- Feedback-based calibration is intentionally disabled until feedback rows have
  trustworthy labeled-sample linkage.
- Telemetry and calibration retention is not yet automatic.
- Benchmark and calibration execution remain CLI-only; the dashboard is
  read-only for reliability data.
- Calibration quality depends on the size and representativeness of benchmark
  fixtures. Different classifiers may use confidence values with different
  semantics, so scoped profiles should be preferred where enough samples exist.
