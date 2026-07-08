"""
Legacy in-memory anomaly helpers.

The active analysis path uses AnalysisEngine and ClassifierPipeline. Beacon
detection should be reintroduced as a database-backed classifier or processor.
"""

from collections import defaultdict

history = defaultdict(list)

def update(device, domain):
    history[device].append(domain)


def detect_beaconing(device):
    domains = history[device][-20:]

    if len(domains) < 10:
        return False

    if len(set(domains)) < 3:
        return True

    return False
