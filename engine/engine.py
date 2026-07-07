"""
PiHole-AI Analysis Engine

Continuously processes new Pi-hole events.

Workflow
--------

events
   │
   ▼
get_unprocessed_domains()
   │
   ▼
Cache lookup
   │
   ├── Cached
   │      │
   │      ▼
   │ mark_processed_by_domain()
   │
   └── Not cached
          │
          ▼
      Analyzer
          │
          ▼
    save_analysis()
          │
          ▼
mark_processed_by_domain()
"""

from __future__ import annotations

from core.config import settings
from core.db import (
    get_analysis,
    get_unprocessed_domains,
    mark_processed_by_domain,
    save_analysis,
)
from core.logger import get_logger

from engine.analyzer import Analyzer
from engine.models import AnalysisRequest

logger = get_logger(__name__)


class AnalysisEngine:
    """
    Main AI processing engine.
    """

    def __init__(self) -> None:
        self.analyzer = Analyzer()

    # ------------------------------------------------------------------
    # Processing
    # ------------------------------------------------------------------

    def process_once(self) -> int:
        """
        Process one batch of unique domains.

        Returns
        -------
        int
            Number of domains processed.
        """

        domains = get_unprocessed_domains(
            settings.engine_batch_size,
        )

        if not domains:
            logger.info(
                "No pending domains."
            )
            return 0

        logger.info(
            "Processing %d unique domain(s)...",
            len(domains),
        )

        processed = 0

        for event in domains:

            domain = event["domain"]

            try:

                #
                # Cache
                #

                analysis = get_analysis(
                    domain,
                )

                if analysis is not None:

                    logger.info(
                        "Cache hit: %s",
                        domain,
                    )

                    mark_processed_by_domain(
                        domain,
                    )

                    processed += 1
                    continue

                #
                # AI Analysis
                #

                request = AnalysisRequest(
                    domain=domain,
                )

                result = self.analyzer.analyze(
                    request,
                )

                save_analysis(
                    domain=result.domain,
                    risk=result.risk,
                    category=result.category,
                    reason=result.reason,
                    model=result.model,
                    analyzed_at=result.analyzed_at,
                )

                mark_processed_by_domain(
                    domain,
                )

                processed += 1

                logger.info(
                    "✓ %s (risk=%d)",
                    result.domain,
                    result.risk,
                )

            except Exception:

                logger.exception(
                    "Failed analyzing '%s'",
                    domain,
                )

        logger.info(
            "Finished processing %d domain(s).",
            processed,
        )

        return processed


def main() -> None:
    """
    Run one processing cycle.
    """

    engine = AnalysisEngine()

    engine.process_once()


if __name__ == "__main__":
    main()