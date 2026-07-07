"""
PiHole-AI Ollama Client

Centralized interface for communicating with a local Ollama server.

Features
--------
- Server availability checks
- Model discovery
- Model validation
- Structured logging
- Centralized configuration

All communication with Ollama should go through this class.
"""
from __future__ import annotations


from dataclasses import dataclass
from time import perf_counter
from typing import List, Optional

import ollama

from core.config import settings
from core.logger import get_logger


class OllamaClient:
    """
    Wrapper around the official Ollama Python client.
    """

    def __init__(self) -> None:
        self.logger = get_logger(__name__)

        self.host = settings.ollama_url
        self.model = settings.ollama_model

        self.client = ollama.Client(
            host=self.host,
        )

        self.logger.info(
            "Initialized Ollama client (host=%s, model=%s)",
            self.host,
            self.model,
        )

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Return True if the Ollama server is reachable.
        """

        try:
            self.client.ps()
            return True

        except Exception as exc:
            self.logger.error(
                "Unable to reach Ollama server: %s",
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # Models
    # ------------------------------------------------------------------

    def list_models(self) -> List[str]:
        """
        Return installed model names.
        """

        try:
            response = self.client.list()

            models = []

            for model in response.models:
                models.append(model.model)

            self.logger.info(
                "Discovered %d installed model(s).",
                len(models),
            )

            return sorted(models)

        except Exception as exc:
            self.logger.exception(
                "Failed to retrieve installed models."
            )
            raise RuntimeError(
                "Unable to retrieve installed Ollama models."
            ) from exc

    def model_exists(self, model: str | None = None) -> bool:
        """
        Check whether a model exists locally.
        """

        if model is None:
            model = self.model

        return model in self.list_models()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        """
        Validate server connectivity and configured model.
        """

        if not self.is_available():
            self.logger.error(
                "Ollama server is unavailable."
            )
            return False

        if not self.model_exists():
            self.logger.error(
                "Configured model '%s' is not installed.",
                self.model,
            )
            return False

        self.logger.info(
            "Ollama validation successful."
        )

        return True

    # ------------------------------------------------------------------
    # Information
    # ------------------------------------------------------------------

    def current_model(self) -> str:
        """
        Return the configured model.
        """

        return self.model

    def current_host(self) -> str:
        """
        Return the configured Ollama host.
        """

        return self.host
