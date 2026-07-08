from __future__ import annotations

from core.db import record_action


def block(domain):
    with open("blocklist.txt", "a") as f:
        f.write(domain + "\n")

    record_action(
        domain=domain,
        action="block",
        source="actions.blocklist",
        status="written",
        reason="Added domain to blocklist.txt.",
    )
