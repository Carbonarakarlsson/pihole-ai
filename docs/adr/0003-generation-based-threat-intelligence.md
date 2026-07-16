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

HTTP validators describe the remote representation, not necessarily the
classifier-active generation. Source state keeps `remote_generation_id` beside
the validators and content hash. Rollback preserves that remote-generation
identity while changing `active_generation`, allowing an HTTP 304 after rollback
to reactivate the unchanged remote generation. Legacy repair uses the latest
successful HTTP 200 update audit as the strongest source of remote-generation
identity, then falls back to stored remote content hash. Active generation alone
is not authoritative after rollback.

Manual `intel import-hosts` remains supported through a managed legacy source
and generation so existing workflows keep working.

## Consequences

- Failed or partial downloads do not replace known-good indicators.
- Explain evidence can cite the source and generation that produced a match.
- Feed updates have an audit trail and safe rollback path.
- A/B field-test cycles can reactivate stored generations without duplicating
  generation or entry rows.
- Conditional HTTP 304 responses can reactivate the stored remote generation
  after rollback without fetching or creating duplicate rows.
- Storage grows with generations until a future retention policy is added.
