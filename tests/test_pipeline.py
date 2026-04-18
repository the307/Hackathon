import time
import unittest
from unittest.mock import patch

from analysis.pipeline import analyze_text


class PipelineConcurrencyTests(unittest.TestCase):
    def test_analysis_branches_run_concurrently(self):
        def slow_regex(text: str):
            time.sleep(0.2)
            return {"обычные": 1, "государственные": 0, "платежные": 0, "биометрические": 0, "специальные": 0}

        def slow_ner(text: str):
            time.sleep(0.2)
            return {"обычные": 1, "государственные": 0, "платежные": 0, "биометрические": 0, "специальные": 0}

        def slow_classifier(text: str):
            time.sleep(0.2)
            return {"обычные": 0, "государственные": 0, "платежные": 0, "биометрические": 0, "специальные": 1}

        start = time.perf_counter()
        with patch("analysis.pipeline.run_regex_branch", side_effect=slow_regex), patch(
            "analysis.pipeline.run_ner_branch", side_effect=slow_ner
        ), patch("analysis.pipeline.run_classifier_branch", side_effect=slow_classifier):
            categories, uz, _ = analyze_text("sample", workers=3)
        elapsed = time.perf_counter() - start

        self.assertLess(elapsed, 0.45)
        self.assertEqual(categories["обычные"], 2)
        self.assertEqual(categories["специальные"], 1)
        self.assertEqual(uz, "УЗ-1")


if __name__ == "__main__":
    unittest.main()
