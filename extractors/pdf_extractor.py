from __future__ import annotations

from pathlib import Path

from models import ExtractedContent, ScanConfig

from .binary_extractor import extract_binary_strings
from .common import extract_pdf_strings, finalize_text, safe_import


PYPDF = safe_import("pypdf")
PYPDF2 = safe_import("PyPDF2")
PDFMINER = safe_import("pdfminer")


def extract_pdf(path: Path, config: ScanConfig) -> ExtractedContent:
    warnings: list[str] = []

    if PYPDF is not None:
        try:
            from pypdf import PdfReader

            reader = PdfReader(str(path))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            return finalize_text(text, "pdf_pypdf", config.max_text_chars)
        except Exception:
            warnings.append("Pypdf недоступен или не смог извлечь текст.")

    if PYPDF2 is not None:
        try:
            from PyPDF2 import PdfReader

            reader = PdfReader(str(path))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            result = finalize_text(text, "pdf_pypdf2", config.max_text_chars)
            result.warnings.extend(warnings)
            return result
        except Exception:
            warnings.append("PyPDF2 недоступен или не смог извлечь текст.")

    if PDFMINER is not None:
        try:
            from pdfminer.high_level import extract_text as pdfminer_extract_text

            text = pdfminer_extract_text(str(path)) or ""
            result = finalize_text(text, "pdf_pdfminer", config.max_text_chars)
            result.warnings.extend(warnings)
            return result
        except Exception:
            warnings.append("pdfminer.six недоступен или не смог извлечь текст.")

    with path.open("rb") as handle:
        raw = handle.read(config.max_binary_read_bytes)
    extracted = extract_pdf_strings(raw)
    if extracted.strip():
        result = finalize_text(extracted, "pdf_stream_fallback", config.max_text_chars)
        if path.stat().st_size > config.max_binary_read_bytes:
            result.warnings.append("PDF fallback ограничен по числу прочитанных байт.")
        result.warnings.extend(warnings)
        return result

    result = extract_binary_strings(path, config)
    result.method = "pdf_binary_fallback"
    result.warnings.extend(warnings)
    result.warnings.append("PDF обработан fallback-режимом, точность может быть снижена.")
    return result
