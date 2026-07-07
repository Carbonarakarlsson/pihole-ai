from dataclasses import dataclass
import time

@dataclass
class DNSEvent:
    device: str
    domain: str
    timestamp: float = time.time()
