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
