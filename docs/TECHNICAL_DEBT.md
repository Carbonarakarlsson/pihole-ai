# Technical Debt

## Resolved In v0.5 Epic 1-2

- Immutable decision history and decision comparison.
- Feedback audit linkage to stored decisions.
- Managed threat-intelligence source lifecycle.
- Generation-based feed activation and rollback.
- Remote-generation identity across rollback and HTTP 304.
- Read-only threat-intelligence CLI paths for list/status/audit/show.

## High Priority

### Threat-Intelligence Generation And Audit Retention

Impact: bounded disk use on Raspberry Pi appliances.  
Need: retention policy for old generations and audit rows that preserves
rollback safety and explain history.  
Suggested milestone: v0.5.x.

### Source Metadata Configuration Audit

Impact: clearer operator traceability for source URL/metadata edits.  
Need: dedicated metadata-edit audit rather than overloading update audit rows.  
Suggested milestone: v0.5.x.

### Broader Feed-Format Validation

Impact: safer onboarding of real-world feeds beyond controlled hosts/domain
fixtures.  
Need: expanded parser validation and fixture coverage.  
Suggested milestone: v0.5.x.

### Health/Doctor Generation-Chain Integrity Checks

Impact: easier field diagnosis of manual database corruption or interrupted
maintenance.  
Need: wire `check_threat_intel_integrity()` into doctor/setup guidance.  
Suggested milestone: v0.5.x.

### Database Backup And Restore Command

Impact: safer upgrades and field support.  
Need: first-class backup/restore commands around `/var/lib/pihole-ai/events.db`.  
Suggested milestone: v0.5.x.

### Long-Term Database Retention

Impact: predictable storage over long-running appliance installs.  
Need: policy covering events, decisions, generations, audit rows, and logs.  
Suggested milestone: v0.5.x.

## Medium Priority

### Curated Feed Presets And Licensing Review

Impact: easier safe adoption of external threat-intel feeds.  
Need: reviewed feed presets, source licensing notes, and conservative defaults.  
Suggested milestone: v0.5.x.

### Bounded Reanalysis Of Affected Domains

Impact: faster convergence after source/rule changes without mass
reclassification.  
Need: bounded queueing policy and Raspberry Pi performance limits.  
Suggested milestone: v0.6.

### Static Frontend Assets

Impact: easier dashboard maintenance and browser caching.  
Deferred to keep the current lightweight Flask/plain HTML stack.  
Suggested milestone: v0.6.

### Reverse-Proxy Deployment Guidance

Impact: safer LAN and homelab deployments.  
Need: documented headers, TLS expectations, and proxy trust guidance.  
Suggested milestone: v0.5.x.

### Module Decomposition

Impact: easier review and lower regression risk.  
Natural boundaries include service lifecycle, feed management, dashboard routes,
configuration, and database integrity helpers.  
Suggested milestone: v0.6.

### Namespace Consolidation

Impact: clearer package ownership.  
Deferred because top-level packages are intentionally packaged today.  
Suggested milestone: v0.6.

## Low Priority

### Multi-User Dashboard

Impact: better shared administration.  
Deferred because the appliance model targets one trusted administrator.  
Suggested milestone: post-v0.6.

### Additional Metrics Export

Impact: integration with external monitoring.  
Deferred because status/health JSON already covers local diagnostics.  
Suggested milestone: post-v0.6.

### Optional Richer Feed-Management UI

Impact: easier source management from the dashboard.  
Deferred to keep privileged feed mutation CLI-first.  
Suggested milestone: post-v0.6.
