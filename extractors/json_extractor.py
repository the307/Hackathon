from __future__ import annotations

import json
from pathlib import Path

from models import ExtractedContent, ScanConfig

from .common import detect_file_encoding, finalize_text


def extract_json(path: Path, config: ScanConfig) -> ExtractedContent:
    raw = path.read_text(encoding=detect_file_encoding(path), errors="replace")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return finalize_text(raw, "json_text_fallback", config.max_text_chars)

    chunks: list[str] = []
    truncated = False

    def visit(value, prefix: str = "root") -> None:
        nonlocal truncated
        if truncated:
            return
        if len(chunks) >= config.max_structured_rows:
            truncated = True
            return
        if isinstance(value, dict):
            for key, item in value.items():
                visit(item, f"{prefix}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{prefix}[{index}]")
        else:
            chunks.append(f"{prefix}: {value}")

    visit(payload)
    result = finalize_text("\n".join(chunks), "json", config.max_text_chars)
    result.truncated = result.truncated or truncated
    if truncated:
        result.warnings.append("JSON ограничен по числу элементов.")
    return result
