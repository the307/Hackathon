import csv
import tempfile
import unittest
from pathlib import Path

from models import ScanResult
from reporting import write_report


class ReportingTests(unittest.TestCase):
    def test_csv_report_uses_competition_schema(self):
        result = ScanResult(
            path="C:/data/sample.txt",
            name="sample.txt",
            size=128,
            time="sep 26 18:31",
            file_format="txt",
            categories={"обычные": 2, "государственные": 0, "платежные": 0, "биометрические": 0, "специальные": 0},
            uz="УЗ-4",
            findings_count=2,
            extractor="plain_text",
            recommendations=[],
            warnings=[],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "result.csv"
            write_report([result], output, "csv")

            with output.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(rows, [{"size": "128", "time": "sep 26 18:31", "name": "sample.txt"}])


if __name__ == "__main__":
    unittest.main()
