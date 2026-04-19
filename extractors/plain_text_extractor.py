from __future__ import annotations

from pathlib import Path

from models import ExtractedContent, ScanConfig

from .common import decode_bytes, finalize_text


def extract_text_plain(path: Path, config: ScanConfig) -> ExtractedContent:
    raw = path.read_bytes()
    text = decode_bytes(raw)
    return finalize_text(text, "plain_text", config.max_text_chars)
