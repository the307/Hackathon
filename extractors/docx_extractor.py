from __future__ import annotations

import zipfile
from pathlib import Path
from xml.etree import ElementTree

from models import ExtractedContent, ScanConfig

from .binary_extractor import extract_binary_strings
from .common import decode_bytes, finalize_text, safe_import


DOCX = safe_import("docx")


def extract_docx(path: Path, config: ScanConfig) -> ExtractedContent:
    header = path.read_bytes()[:256]
    lowered_header = header.lower()
    if lowered_header.startswith(b"<html") or b"<html" in lowered_header:
        text = decode_bytes(path.read_bytes())
        return finalize_text(text, "docx_html_fallback", config.max_text_chars)

    if DOCX is not None:
        try:
            from docx import Document

            document = Document(str(path))
            text = "\n".join(paragraph.text for paragraph in document.paragraphs)
            return finalize_text(text, "docx_python_docx", config.max_text_chars)
        except Exception:
            pass

    warnings: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            xml_payload = archive.read("word/document.xml")
        root = ElementTree.fromstring(xml_payload)
        text = " ".join(node.text for node in root.iter() if node.text)
        return finalize_text(text, "docx_zip_xml", config.max_text_chars)
    except Exception:
        warnings.append("DOCX не удалось прочитать как zip/xml, использован binary fallback.")
        result = extract_binary_strings(path, config)
        result.method = "docx_binary_fallback"
        result.warnings.extend(warnings)
        return result
