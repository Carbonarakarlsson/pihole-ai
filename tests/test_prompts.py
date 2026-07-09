import json
import unittest

from engine.models import DomainMetadata
from engine.prompts import build_domain_prompt


class PromptTests(unittest.TestCase):
    def test_build_domain_prompt_serializes_domain_metadata_dataclass(self) -> None:
        prompt = build_domain_prompt(
            domain="it",
            metadata=DomainMetadata(
                domain="it",
                query_count=3,
                device_count=2,
                recent_queries=1,
                tags=[
                    "test",
                ],
            ),
        )

        payload = json.loads(prompt)

        self.assertEqual(payload["domain"], "it")
        self.assertEqual(
            payload["metadata"],
            {
                "domain": "it",
                "query_count": 3,
                "first_seen": 0.0,
                "last_seen": 0.0,
                "device_count": 2,
                "recent_queries": 1,
                "tags": [
                    "test",
                ],
            },
        )

    def test_build_domain_prompt_uses_empty_metadata_for_none(self) -> None:
        payload = json.loads(
            build_domain_prompt(
                domain="example.com",
                metadata=None,
            )
        )

        self.assertEqual(payload["metadata"], {})

    def test_build_domain_prompt_keeps_dict_metadata(self) -> None:
        payload = json.loads(
            build_domain_prompt(
                domain="example.com",
                metadata={
                    "query_count": 2,
                },
            )
        )

        self.assertEqual(
            payload["metadata"],
            {
                "query_count": 2,
            },
        )


if __name__ == "__main__":
    unittest.main()
