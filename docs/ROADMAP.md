# Roadmap

## v0.5 Milestone State

Epic 1, the evidence-based decision engine, is complete. Epic 2, managed
threat-intelligence feed lifecycle, is complete and physically field-validated
on a Raspberry Pi-class appliance.

Recommended milestone tag after final artifact validation: `v0.5.0-beta1`.

## Epic 3: Domain And Device Behavioral Intelligence

Goal: add local behavioral context that improves explanations and anomaly
evidence without aggressive blocking or automatic mass reclassification.

Scope:

- domain behavior aggregates: query cadence, recurrence, burstiness, and
  first-seen/last-seen windows
- device identity and naming: stable client keys, friendly names, and local
  alias metadata
- client-to-domain relationships: which devices query which domains and how
  often
- normal-behavior baselines: lightweight rolling summaries suited to Raspberry
  Pi storage and CPU limits
- anomaly evidence: deterministic evidence items for unusual domain/device
  patterns
- privacy boundaries: local-only storage, redacted exports, and clear retention
  controls
- retention: bounded history for per-device and per-domain aggregates
- explain integration: show why a behavior signal mattered without exposing
  unnecessary raw query history
- dashboard summaries: compact domain/device summaries, not a heavy analytics
  UI
- immutable decision integration: decisions cite the behavior snapshot used at
  classification time
- appliance performance: avoid background jobs that compete with Pi-hole or
  Ollama on small Raspberry Pi hosts

Non-goals for Epic 3:

- automatic broad blocking based only on anomaly scores
- cloud synchronization
- multi-user administration
- large-scale SIEM replacement
