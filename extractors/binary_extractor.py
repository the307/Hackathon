from __future__ import annotations

from pathlib import Path

from models import ExtractedContent, ScanConfig

from .common import extract_strings_from_bytes, finalize_text


def extract_binary_strings(path: Path, config: ScanConfig) -> ExtractedContent:
    with path.open("rb") as handle:
        raw = handle.read(config.max_binary_read_bytes)
    text = extract_strings_from_bytes(raw)
    result = finalize_text(text, "binary_strings", config.max_text_chars)
    if path.stat().st_size > config.max_binary_read_bytes:
        result.warnings.append("Binary fallback ограничен по числу прочитанных байт.")
    return result
