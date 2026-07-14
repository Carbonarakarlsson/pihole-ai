from __future__ import annotations

from core.config import settings
from core.db import record_action


def alert(msg):
    print(f"\n🚨 ALERT: {msg}")

    alert_log = settings.alert_log
    alert_log.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    with alert_log.open("a", encoding="utf-8") as f:
        f.write(msg + "\n")

    record_action(
        domain="system",
        action="alert",
        source="actions.alerts",
        status="logged",
        reason=msg,
    )
