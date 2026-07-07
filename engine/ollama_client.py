"""
PiHole-AI Ollama Client

Centralized interface for communicating with a local Ollama server.

All AI communication should pass through this class.

Responsibilities
----------------
- Server availability
- Installed model discovery
- Model validation
- Text generation
- Structured logging
"""

from __future__ import annotations

from typing import Any

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
    # Text Generation
    # ------------------------------------------------------------------

    def generate(
        self,
        system: str,
        prompt: str,
        temperature: float = 0.2,
    ) -> str:
        """
        Generate a response from the configured model.
        """

        self.logger.info(
            "Generating response using '%s'.",
            self.model,
        )

        try:

            response: Any = self.client.chat(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": system,
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                options={
                    "temperature": temperature,
                },
            )

            content = response["message"]["content"]

            self.logger.info(
                "Generation completed successfully."
            )

            return content

        except Exception:

            self.logger.exception(
                "Generation failed."
            )

            raise

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

    def list_models(self) -> list[str]:
        """
        Return a sorted list of installed model names.
        """

        try:

            response = self.client.list()

            models: list[str] = []

            #
            # Compatible with current Ollama Python client.
            #
            for model in response.models:
                models.append(model.model)

            models.sort()

            self.logger.info(
                "Discovered %d installed model(s).",
                len(models),
            )

            return models

        except Exception as exc:

            self.logger.exception(
                "Failed to retrieve installed models."
            )

            raise RuntimeError(
                "Unable to retrieve installed Ollama models."
            ) from exc

    def model_exists(
        self,
        model: str | None = None,
    ) -> bool:
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
        Validate the configured Ollama installation.

        Checks:
            - server reachable
            - configured model installed
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

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def health(self) -> dict[str, object]:
        """
        Return health information for the Ollama server.
        """

        import time

        start = time.perf_counter()

        available = self.is_available()

        latency_ms = round(
            (time.perf_counter() - start) * 1000,
            2,
        )

        return {
            "available": available,
            "host": self.host,
            "model": self.model,
            "latency_ms": latency_ms,
        }

    def __repr__(self) -> str:
        return (
            f"OllamaClient("
            f"host='{self.host}', "
            f"model='{self.model}')"
        )