from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

from models import ExtractedContent, ScanConfig

from .common import detect_file_encoding, finalize_text, repair_mojibake


csv.field_size_limit(min(sys.maxsize, 1_000_000_000))


HEADER_CONTEXT_HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(phone|tel|моб|телефон|номер.?тел)"), "телефон"),
    (re.compile(r"(?i)(e[-_]?mail|почт|mail\b)"), "e-mail"),
    (re.compile(r"(?i)(\bfio\b|фио|name\b|full.?name|имя|фамил|отчеств)"), "ФИО"),
    (re.compile(r"(?i)(snils|снилс)"), "СНИЛС"),
    (re.compile(r"(?i)(\binn\b|инн)"), "ИНН"),
    (re.compile(r"(?i)(passport|паспорт)"), "паспорт серия номер"),
    (re.compile(r"(?i)(birth|дата.?рожд|др\b)"), "дата рождения"),
    (re.compile(r"(?i)(address|адрес|город|улиц|регистрац|прожив)"), "адрес регистрации"),
    (re.compile(r"(?i)(card|карт)"), "карта"),
    (re.compile(r"(?i)(account|счет|р/?с)"), "р/с банк реквизиты"),
    (re.compile(r"(?i)(bik|бик)"), "БИК банк"),
    (re.compile(r"(?i)(cvv|cvc)"), "CVV"),
    (re.compile(r"(?i)(driver|водител|ву\b)"), "водительское удостоверение"),
)


def _column_hint(header: str) -> str:
    if not header:
        return ""
    for pattern, hint in HEADER_CONTEXT_HINTS:
        if pattern.search(header):
            return hint
    return ""


def extract_csv(path: Path, config: ScanConfig) -> ExtractedContent:
    rows_text: list[str] = []
    truncated = False
    header: list[str] = []
    column_hints: list[str] = []
    with path.open("r", encoding=detect_file_encoding(path), errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        for index, row in enumerate(reader):
            cells = [repair_mojibake(cell.strip()) for cell in row]
            if index == 0:
                header = cells
                column_hints = [_column_hint(name) for name in header]
                rows_text.append(" | ".join(cells))
                continue

            if column_hints and any(column_hints):
                annotated_cells: list[str] = []
                for column_index, cell in enumerate(cells):
                    if not cell:
                        continue
                    hint = column_hints[column_index] if column_index < len(column_hints) else ""
                    if hint:
                        annotated_cells.append(f"{hint}: {cell}")
                    else:
                        annotated_cells.append(cell)
                rows_text.append(" | ".join(annotated_cells))
            else:
                rows_text.append(" | ".join(cells))

            if index + 1 >= config.max_structured_rows:
                truncated = True
                break

    result = finalize_text("\n".join(rows_text), "csv", config.max_text_chars)
    result.truncated = result.truncated or truncated
    if truncated:
        result.warnings.append("CSV ограничен по числу строк.")
    return result
