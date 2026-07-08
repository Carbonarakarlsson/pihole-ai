"""
Compatibility entrypoint for running the current analysis engine.

Older versions of PiHole-AI had a separate scoring/anomaly loop here.
The active architecture now runs through AnalysisEngine and the
ClassifierPipeline.
"""

from __future__ import annotations

from engine.engine import AnalysisEngine


def run() -> int:
    """
    Process one batch of pending domains.

    Returns the number of domains processed.
    """

    engine = AnalysisEngine()

    return engine.process_once()


def main() -> None:
    """
    Run one analysis cycle.
    """

    run()


if __name__ == "__main__":
    main()
