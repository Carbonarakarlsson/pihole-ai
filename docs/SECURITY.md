# Security

PiHole-AI is designed as a local appliance companion for a trusted Pi-hole
administrator, not as an internet-facing multi-user service.

## Service Identity

Production services run as `pihole-ai:pihole-ai`. Runtime data and logs are
owned by that identity. Protected configuration is root-owned and group-readable
only by the service group.

## Protected Configuration

```text
/etc/pihole-ai                  root:pihole-ai 0750
/etc/pihole-ai/pihole-ai.env    root:pihole-ai 0640
```

The installer and upgrader reject symlink substitution for managed protected
paths and repair metadata only on verified managed paths.

## Dashboard Authentication

The dashboard has one administrator account. Default username is `admin`.
There is no default password. Set one with:

```bash
sudo pihole-ai dashboard auth set-password
```

Passwords are stored as Werkzeug password hashes. The plaintext password is
never written to docs, logs, or JSON status output.

## Sessions, CSRF, And Headers

The dashboard uses signed Flask sessions, CSRF tokens for mutating requests,
login throttling, security headers, and route protection. Detailed setup,
health, status, explain, feedback, settings, rules, and service APIs require an
authenticated session. `/live` remains intentionally public and minimal.

## Proxy Trust And Exposure

Reverse-proxy trust is disabled by default. Only enable
`PIHOLE_AI_DASHBOARD_TRUST_PROXY=true` behind a trusted local proxy. A dashboard
bound outside loopback is operational with warnings when authentication is
enabled; restrict firewall/network access.

## Pi-hole Database Relationship

PiHole-AI reads the Pi-hole FTL database but does not own it. The installer may
help the service identity join an existing readable group, but it should not
weaken Pi-hole database ownership or permissions.

## Threat Model And Limitations

PiHole-AI protects local appliance secrets against ordinary users on the host
and protects dashboard writes from unauthenticated or cross-site requests. It
does not provide multi-user authorization, internet-facing hardening, malware
containment, or comprehensive secret scanning.
