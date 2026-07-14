# ADR 0002: Immutable Decision History

## Status

Accepted for v0.5 development.

## Context

Latest-only decision storage made the dashboard and CLI easy to query, but it
lost the evidence that explained earlier classifications. That made feedback,
action auditing, and policy-change debugging weaker because a later decision
could overwrite the context a human had reviewed.

## Decision

PiHole-AI stores every fresh completed classification as an append-only immutable
decision in `decision_history`, with evidence in `decision_history_evidence`.
Each row receives an opaque `dec_<uuid4hex>` identifier. The latest
`decision_records` and `decision_evidence` tables remain compatibility
projections for existing callers.

History rows are created only when the engine completes a fresh classification
or an explicit reanalysis path does so in the future. Cache hits, dashboard
loads, explain reads, status, setup, doctor, and health checks do not create
history rows.

## Feedback And Actions

Feedback and action audit rows record the exact immutable decision ID visible or
used at that moment. Future classifications may include feedback as new evidence
without rewriting the older decision.

## Retention

Decision-history retention is explicit maintenance. Defaults are conservative:
365 days and 100 decisions per domain. Retention never deletes the latest
decision for a domain or a decision referenced by feedback. When deleting an
eligible middle decision, retention relinks direct supersedes pointers to keep
the chain internally consistent.

## Compatibility

`pihole-ai explain <domain>` and `GET /api/explain/<domain>` continue to return
the latest decision. New CLI/API/dashboard paths can request bounded history,
select a historical decision, or compare two decision IDs.

## Consequences

Storage grows with genuine reclassification events. This is bounded by explicit
maintenance rather than automatic cleanup during classification so fresh
decisions remain simple and predictable on Raspberry Pi hosts.
