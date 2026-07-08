import unittest
from unittest.mock import patch

from engine import run_engine


class RunEngineTests(unittest.TestCase):
    def test_run_uses_current_analysis_engine(self) -> None:
        with patch("engine.run_engine.AnalysisEngine") as analysis_engine:
            analysis_engine.return_value.process_once.return_value = 7

            result = run_engine.run()

        analysis_engine.assert_called_once_with()
        analysis_engine.return_value.process_once.assert_called_once_with()
        self.assertEqual(result, 7)

    def test_main_runs_one_analysis_cycle(self) -> None:
        with patch("engine.run_engine.run") as run:
            run_engine.main()

        run.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
