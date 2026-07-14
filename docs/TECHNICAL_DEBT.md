# Technical Debt

## High Priority

### Immutable Per-Decision History And Feedback Linkage

Impact: richer audits and better feedback accountability.  
Deferred because v0.5 first stores the latest structured decision per domain.  
Suggested milestone: v0.5.x.

### Database Backup And Restore Command

Impact: safer upgrades and field support.  
Deferred to keep lifecycle scope small.  
Suggested milestone: v0.5.x.

### Long-Term Retention Policy

Impact: predictable disk use on Raspberry Pi hosts.  
Deferred until real-world event volumes are measured.  
Suggested milestone: v0.5.x.

### Firewall Diagnostics

Impact: clearer warning guidance for LAN-exposed dashboards.  
Deferred because current checks avoid network mutation.  
Suggested milestone: v0.5.x.

### Oversized Module Decomposition

Impact: easier review and lower regression risk.  
Deferred to avoid broad refactors during release cleanup.  
Suggested milestone: v0.6.

Natural boundaries:

- `core/config.py`: models, loading, validation, redaction
- `pihole_ai/setup.py`: models, state detection, CLI output, config writer
- `pihole_ai/service.py`: systemd files, identity, lifecycle, preflight
- `ui/dashboard.py`: app setup, auth/security, API routes, rendering
- `pihole_ai/health.py`: models, individual checks, orchestration

## Medium Priority

### Namespace Consolidation

Impact: clearer package ownership.  
Deferred because top-level packages are intentionally packaged today.  
Suggested milestone: v0.6.

### Static Frontend Assets

Impact: easier dashboard maintenance and caching.  
Deferred to keep the lightweight Flask/plain HTML stack.  
Suggested milestone: v0.6.

### Reverse-Proxy Deployment Guidance

Impact: safer remote LAN deployments.  
Deferred until more field configurations are known.  
Suggested milestone: v0.5.x.

### Scheduled Threat-Intelligence Management

Impact: easier feed maintenance.  
Deferred because import is local/manual today.  
Suggested milestone: v0.6.

## Low Priority

### Multi-User Dashboard Support

Impact: better shared administration.  
Deferred because appliance model targets one trusted administrator.  
Suggested milestone: post-v0.6.

### Optional Metrics Export

Impact: integration with external monitoring.  
Deferred because status/health JSON already covers local diagnostics.  
Suggested milestone: post-v0.6.

### Additional Development Tooling

Impact: formatting and lint consistency.  
Deferred to avoid adding dependencies in this cleanup.  
Suggested milestone: when contributor volume increases.
