import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from models import ScanConfig, ScanResult
from scanner import scan_root


class ScannerDebugTests(unittest.TestCase):
    def test_debug_progress_prints_counter_extension_and_time(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_path = Path(temp_dir)
            first = tmp_path / "one.txt"
            second = tmp_path / "two.csv"
            first.write_text("sample", encoding="utf-8")
            second.write_text("sample", encoding="utf-8")

            config = ScanConfig(
                root=tmp_path,
                output=tmp_path / "out.csv",
                include_extensions={"txt", "csv"},
                include_empty_results=True,
                debug_progress=True,
            )

            def fake_scan_file(path: Path, _config: ScanConfig) -> ScanResult:
                return ScanResult(
                    path=str(path),
                    name=path.name,
                    size=path.stat().st_size,
                    time="apr 19 00:00",
                    file_format=path.suffix.lower().lstrip(".") or "unknown",
                    categories={},
                    uz="нет признаков",
                    findings_count=0,
                    extractor="fake",
                    recommendations=[],
                    warnings=[],
                )

            buffer = io.StringIO()
            with patch("scanner.scan_file", side_effect=fake_scan_file), redirect_stdout(buffer):
                scan_root(config)

            output = buffer.getvalue()
            self.assertIn("[debug] 1/2 txt ", output)
            self.assertIn(" one.txt ok", output)
            self.assertIn("[debug] 2/2 csv ", output)
            self.assertIn(" two.csv ok", output)


if __name__ == "__main__":
    unittest.main()
