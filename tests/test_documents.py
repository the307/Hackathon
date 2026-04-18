import csv
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from documents import extract_csv, extract_docx, extract_html, extract_json
from models import ScanConfig


class DocumentExtractionTests(unittest.TestCase):
    def test_extract_json_flattens_nested_payload(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_path = Path(temp_dir)
            payload = {"user": {"name": "Иван Иванов", "email": "ivan@example.test"}}
            path = tmp_path / "sample.json"
            path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

            result = extract_json(path, ScanConfig(root=tmp_path, output=tmp_path / "out.csv"))

            self.assertIn("user.name: Иван Иванов", result.text)
            self.assertIn("user.email: ivan@example.test", result.text)

    def test_extract_html_strips_tags(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_path = Path(temp_dir)
            path = tmp_path / "page.html"
            path.write_text("<html><body><h1>Контакты</h1><p>test@example.test</p></body></html>", encoding="utf-8")

            result = extract_html(path, ScanConfig(root=tmp_path, output=tmp_path / "out.csv"))

            self.assertIn("Контакты", result.text)
            self.assertIn("test@example.test", result.text)

    def test_extract_docx_from_zip_xml_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_path = Path(temp_dir)
            path = tmp_path / "sample.docx"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(
                    "word/document.xml",
                    """<?xml version="1.0" encoding="UTF-8"?>
                    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
                      <w:body><w:p><w:r><w:t>Паспорт 52 17 118903</w:t></w:r></w:p></w:body>
                    </w:document>""",
                )

            result = extract_docx(path, ScanConfig(root=tmp_path, output=tmp_path / "out.csv"))

            self.assertIn("Паспорт 52 17 118903", result.text)

    def test_extract_csv_keeps_utf8_content(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_path = Path(temp_dir)
            path = tmp_path / "sample.csv"
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["id", "customer_name"])
                writer.writerow(["1", "Филипп Елизарович Воробьев"])

            result = extract_csv(path, ScanConfig(root=tmp_path, output=tmp_path / "out.csv"))

            self.assertIn("Филипп Елизарович Воробьев", result.text)

    def test_extract_csv_repairs_mojibake_cells(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_path = Path(temp_dir)
            path = tmp_path / "sample.csv"
            path.write_text("id,name\n1,Ð¤Ð¸Ð»Ð¸Ð¿Ð¿ ÐÐ»Ð¸Ð·Ð°ÑÐ¾Ð²Ð¸Ñ ÐÐ¾ÑÐ¾Ð±ÑÐµÐ²\n", encoding="utf-8")

            result = extract_csv(path, ScanConfig(root=tmp_path, output=tmp_path / "out.csv"))

            self.assertIn("Филипп Елизарович Воробьев", result.text)

    def test_extract_docx_html_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_path = Path(temp_dir)
            path = tmp_path / "fake.docx"
            path.write_text("<html><body><p>Иван Иванов</p></body></html>", encoding="utf-8")

            result = extract_docx(path, ScanConfig(root=tmp_path, output=tmp_path / "out.csv"))

            self.assertIn("Иван Иванов", result.text)


if __name__ == "__main__":
    unittest.main()
