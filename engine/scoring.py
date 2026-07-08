"""
Legacy scoring helpers.

The active analysis path uses engine.classifiers.heuristics.HeuristicsEngine.
Keep this module only as historical reference until it is removed.
"""

import math


SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".loan",
    ".work"
]


def entropy(value):

    freq = {}

    for c in value:
        freq[c] = freq.get(c, 0) + 1


    length = len(value)

    return -sum(
        (count / length) *
        math.log2(count / length)
        for count in freq.values()
    )



def score_domain(domain, query_count=0):

    score = 0
    reasons = []


    hostname = domain.split(".")[0]


    # entropy
    ent = entropy(hostname)

    if ent > 3.5:
        score += 30
        reasons.append(
            "High entropy hostname"
        )


    # deep subdomains
    if domain.count(".") > 3:
        score += 15
        reasons.append(
            "Deep subdomain structure"
        )


    # suspicious TLD
    for tld in SUSPICIOUS_TLDS:

        if domain.endswith(tld):
            score += 20
            reasons.append(
                f"Suspicious TLD {tld}"
            )


    # lots of numbers
    numbers = sum(
        c.isdigit()
        for c in hostname
    )


    if len(hostname) > 0:

        ratio = numbers / len(hostname)

        if ratio > 0.3:
            score += 20
            reasons.append(
                "Many numbers in hostname"
            )


    # frequency
    if query_count > 500:
        score += 15
        reasons.append(
            "High query frequency"
        )


    return score, reasons
