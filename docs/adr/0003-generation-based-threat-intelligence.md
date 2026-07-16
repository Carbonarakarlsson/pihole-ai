# ADR 0003: Generation-Based Threat Intelligence

## Status

Accepted.

## Context

Threat-intelligence feeds can fail, shrink unexpectedly, grow explosively, or
return malformed content. Replacing the active indicator set directly during an
update would make classification fragile and hard to explain.

## Decision

PiHole-AI stores each successful feed import as an immutable generation. A new
generation becomes active only after fetch, parse, and quality checks succeed.
Classifiers read enabled sources through their active generation. Failed updates
record audit/state details and leave the previous generation active. Rollback
reactivates the previous generation for that source.

Update outcomes are evaluated relative to the currently active generation:
active content unchanged records a no-change result; downloaded content matching
a valid inactive generation for the same source reactivates that existing
generation atomically; new content creates and activates a new generation. The
`previous_generation` column is the current rollback pointer and may be updated
during reactivation; it is not immutable creation provenance.

Manual `intel import-hosts` remains supported through a managed legacy source
and generation so existing workflows keep working.

## Consequences

- Failed or partial downloads do not replace known-good indicators.
- Explain evidence can cite the source and generation that produced a match.
- Feed updates have an audit trail and safe rollback path.
- A/B field-test cycles can reactivate stored generations without duplicating
  generation or entry rows.
- Storage grows with generations until a future retention policy is added.
