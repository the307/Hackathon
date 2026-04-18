from __future__ import annotations

from pathlib import Path
from typing import Callable

from models import ExtractedContent, ScanConfig

from .binary_extractor import extract_binary_strings
from .csv_extractor import extract_csv
from .docx_extractor import extract_docx
from .html_extractor import extract_html
from .image_extractor import extract_image
from .json_extractor import extract_json
from .pdf_extractor import extract_pdf
from .plain_text_extractor import extract_text_plain
from .rtf_extractor import extract_rtf
from .spreadsheet_extractor import extract_xls


EXTRACTORS: dict[str, Callable[[Path, ScanConfig], ExtractedContent]] = {
    "csv": extract_csv,
    "doc": extract_binary_strings,
    "docx": extract_docx,
    "gif": extract_image,
    "htm": extract_html,
    "html": extract_html,
    "jpeg": extract_image,
    "jpg": extract_image,
    "json": extract_json,
    "pdf": extract_pdf,
    "png": extract_image,
    "rtf": extract_rtf,
    "tif": extract_image,
    "tiff": extract_image,
    "txt": extract_text_plain,
    "xls": extract_xls,
    "xlsx": extract_xls,
}


def extract_text(path: Path, config: ScanConfig) -> ExtractedContent:
    extension = path.suffix.lower().lstrip(".")
    extractor = EXTRACTORS.get(extension, extract_text_plain)
    return extractor(path, config)
