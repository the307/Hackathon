from __future__ import annotations

import csv
import sys
from pathlib import Path

from models import ExtractedContent, ScanConfig

from .common import detect_file_encoding, finalize_text, repair_mojibake


csv.field_size_limit(min(sys.maxsize, 1_000_000_000))


def extract_csv(path: Path, config: ScanConfig) -> ExtractedContent:
    rows: list[str] = []
    truncated = False
    with path.open("r", encoding=detect_file_encoding(path), errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        for index, row in enumerate(reader):
            rows.append(" | ".join(repair_mojibake(cell.strip()) for cell in row))
            if index + 1 >= config.max_structured_rows:
                truncated = True
                break
    result = finalize_text("\n".join(rows), "csv", config.max_text_chars)
    result.truncated = result.truncated or truncated
    if truncated:
        result.warnings.append("CSV ограничен по числу строк.")
    return result
