# ADR 0001: Evidence-Based Decisions

## Status

Accepted for v0.5 development.

## Context

The original classifier pipeline returned the first matching `AnalysisResult`.
That made fast decisions simple, but it hid supporting evidence, made
contradictions hard to explain, and forced the dashboard/CLI to reconstruct
decision context from current database state.

## Decision

PiHole-AI uses structured evidence as the classifier contract. Classifiers emit
bounded `EvidenceItem` records with polarity, score, confidence, summary,
metadata, and optional decisive precedence. The central `DecisionEngine` creates
one final decision using policy version `evidence-policy-v1`.

Decisive evidence wins by precedence. Current decisive evidence includes:

- manual block rules
- manual allow rules
- local infrastructure rules
- high-confidence threat-intelligence hits

Non-decisive evidence is aggregated centrally. Positive scores increase risk.
Negative scores reduce risk. Neutral evidence provides context without changing
the risk score.

## Persistence

Fresh decisions are persisted in two parts:

- `decision_records`: final verdict, risk, confidence, category, source,
  explanation, classifier trace, conflicts, policy version, application version,
  schema version, and timestamps.
- `decision_evidence`: ordered supporting evidence items.

Legacy rows in `analysis` remain readable. If no structured decision record
exists, explain output sets `legacy: true` and shows:

```text
This decision predates structured evidence storage.
```

Feedback audit rows store `decision_ref` when a structured decision exists at
feedback time. This links human feedback to the decision being reviewed without
rewriting the decision or evidence rows.

## API And UI Contract

Explain consumers use the same grouped contract:

- `decision`
- `decisive_evidence`
- `risk_evidence`
- `safety_evidence`
- `neutral_evidence`
- `classifier_trace`
- `conflicts`
- `legacy`

Evidence is sorted deterministically:

1. decisive first
2. absolute score descending
3. confidence descending
4. classifier and evidence ID tie-breakers

## Security And Bounds

Metadata is JSON-sanitized before serialization and persistence. Secret-bearing
keys such as tokens, cookies, passwords, CSRF values, raw prompts, and raw model
payloads are redacted. Evidence summaries, details, metadata, item count, and
classifier trace length are bounded for Raspberry Pi-safe storage and rendering.

Malformed persisted evidence must degrade safely and must not break CLI,
dashboard, or API explain rendering.

## Consequences

The dashboard and CLI can render a stored decision without rerunning classifiers.
Historical structured evidence is preserved for the latest decision per domain.
Future work may add immutable per-decision history, but v0.5 does not rewrite
historical analyses or add new classifiers.
