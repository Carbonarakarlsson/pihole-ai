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

import time
from typing import Any

from core.config import settings
from core.db import (
    get_analysis,
    get_domain_metadata,
    get_unprocessed_domains,
    mark_processed_by_domain,
    record_action,
    save_analysis_with_decision,
)
from core.logger import get_logger

from actions.policy import apply_action_policy
from engine.analyzer import Analyzer
from engine.models import AnalysisRequest, DomainMetadata
from pihole_ai.learn import update_reputation_from_analysis

logger = get_logger(__name__)


def is_cache_usable(
    analysis: Any,
    now: float | None = None,
    cache_ttl: int | None = None,
) -> bool:
    """
    Return True if a cached analysis can be reused.
    """

    if analysis is None:
        return False

    if analysis["confidence"] <= 0:
        return False

    if cache_ttl is None:
        cache_ttl = settings.cache_ttl

    if cache_ttl <= 0:
        return True

    analyzed_at = analysis["analyzed_at"] or 0

    if now is None:
        now = time.time()

    return now - analyzed_at <= cache_ttl


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
            logger.debug(
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

                if is_cache_usable(analysis):

                    logger.debug(
                        "Cache hit: %s",
                        domain,
                    )

                    mark_processed_by_domain(
                        domain,
                    )

                    processed += 1
                    continue

                if analysis is not None:

                    logger.debug(
                        "Retrying stale cached analysis: %s",
                        domain,
                    )

                #
                # AI Analysis
                #

                request = AnalysisRequest(
                    domain=domain,
                    metadata=DomainMetadata.from_mapping(
                        get_domain_metadata(domain),
                    ),
                )

                result = self.analyzer.analyze(
                    request,
                )

                decision_id = save_analysis_with_decision(
                    domain=result.domain,
                    risk=result.risk,
                    confidence=result.confidence,
                    category=result.category,
                    reason=result.reason,
                    model=result.model,
                    analyzed_at=result.analyzed_at,
                    decision=result.decision,
                    trigger="cache_expired" if analysis is not None else "first_seen",
                )

                if _is_ai_parse_error(result):
                    record_action(
                        domain=result.domain,
                        action="review",
                        source="ai",
                        status="parse_error",
                        reason=result.reason,
                        risk=result.risk,
                        decision_ref=decision_id,
                    )

                try:
                    update_reputation_from_analysis(
                        result,
                    )

                except Exception:
                    logger.exception(
                        "Failed updating reputation for '%s'",
                        result.domain,
                    )

                apply_action_policy(
                    result,
                    decision_ref=decision_id,
                )

                mark_processed_by_domain(
                    domain,
                )

                processed += 1

                logger.debug(
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

    def run_loop(
        self,
        interval: int | None = None,
        max_cycles: int | None = None,
    ) -> None:
        """
        Continuously process pending domains.
        """

        if interval is None:
            interval = settings.engine_interval

        cycles = 0

        logger.info(
            "Analysis engine running (interval=%d).",
            interval,
        )

        while True:

            self.process_once()

            cycles += 1

            if max_cycles is not None and cycles >= max_cycles:
                return

            time.sleep(interval)


def main() -> None:
    """
    Run the continuous analysis worker.
    """

    engine = AnalysisEngine()

    engine.run_loop()


def _is_ai_parse_error(
    result: Any,
) -> bool:
    """
    Return True when the AI returned an invalid response.
    """

    return (
        result.model == "ai"
        and result.category == "unknown"
        and result.risk == 0
        and result.reason == "AI returned invalid response"
    )


if __name__ == "__main__":
    main()
