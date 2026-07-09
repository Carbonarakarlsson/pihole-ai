import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.config import Settings, load_env_file


class ConfigTests(unittest.TestCase):
    def test_load_env_file_sets_log_level_without_overriding_existing_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / ".env"
            path.write_text(
                "LOG_LEVEL=DEBUG\nPIHOLE_AI_LOG_LEVEL=WARNING\n",
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                {
                    "PIHOLE_AI_LOG_LEVEL": "ERROR",
                },
                clear=True,
            ):
                load_env_file(path)

                self.assertEqual(os.environ["LOG_LEVEL"], "DEBUG")
                self.assertEqual(os.environ["PIHOLE_AI_LOG_LEVEL"], "ERROR")

    def test_settings_respects_log_level_from_environment(self) -> None:
        with patch.dict(
            os.environ,
            {
                "LOG_LEVEL": "debug",
            },
            clear=True,
        ):
            self.assertEqual(Settings().log_level, "DEBUG")

    def test_specific_pihole_log_level_overrides_generic_log_level(self) -> None:
        with patch.dict(
            os.environ,
            {
                "LOG_LEVEL": "debug",
                "PIHOLE_AI_LOG_LEVEL": "warning",
            },
            clear=True,
        ):
            self.assertEqual(Settings().log_level, "WARNING")


if __name__ == "__main__":
    unittest.main()
