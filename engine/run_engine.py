from core.db import get_events
from engine.scoring import score_domain
from engine.anomaly import update, detect_beaconing
from actions.alerts import alert

def run():
    rows = get_events()

    for device, domain, _ in rows:

        score, reasons = score_domain(domain)
        update(device, domain)

        if detect_beaconing(device):
            alert(f"Beaconing detected: {device}")

        if score > 70:
            alert(f"High risk domain: {domain}")

        print(device, domain, score)


if __name__ == "__main__":
    run()
