from __future__ import annotations

import html
import re
from pathlib import Path

from models import ExtractedContent, ScanConfig

from .common import detect_file_encoding, finalize_text, safe_import


BS4 = safe_import("bs4")


def extract_html(path: Path, config: ScanConfig) -> ExtractedContent:
    raw = path.read_text(encoding=detect_file_encoding(path), errors="replace")
    if BS4 is not None:
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(raw, "html.parser")
            return finalize_text(soup.get_text(" ", strip=True), "html_bs4", config.max_text_chars)
        except Exception:
            pass
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", raw)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return finalize_text(html.unescape(text), "html_regex", config.max_text_chars)
