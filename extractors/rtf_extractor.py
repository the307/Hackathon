from __future__ import annotations

import re
from pathlib import Path

from models import ExtractedContent, ScanConfig

from .common import detect_file_encoding, finalize_text, safe_import


STRIPRTF = safe_import("striprtf")


def extract_rtf(path: Path, config: ScanConfig) -> ExtractedContent:
    raw = path.read_text(encoding=detect_file_encoding(path), errors="replace")
    if STRIPRTF is not None:
        try:
            from striprtf.striprtf import rtf_to_text

            return finalize_text(rtf_to_text(raw), "rtf_striprtf", config.max_text_chars)
        except Exception:
            pass
    text = re.sub(r"\\'[0-9a-fA-F]{2}", " ", raw)
    text = re.sub(r"\\[a-zA-Z]+\d* ?", " ", text)
    text = re.sub(r"[{}]", " ", text)
    return finalize_text(text, "rtf_regex", config.max_text_chars)
