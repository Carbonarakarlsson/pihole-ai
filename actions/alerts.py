from __future__ import annotations

from core.db import record_action


def alert(msg):
    print(f"\n🚨 ALERT: {msg}")

    with open("alerts.log", "a") as f:
        f.write(msg + "\n")

    record_action(
        domain="system",
        action="alert",
        source="actions.alerts",
        status="logged",
        reason=msg,
    )
