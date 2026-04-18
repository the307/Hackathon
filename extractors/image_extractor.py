from __future__ import annotations

from pathlib import Path

from models import ExtractedContent, ScanConfig

from .binary_extractor import extract_binary_strings
from .common import finalize_text, safe_import


PYTESSERACT = safe_import("pytesseract")
PIL = safe_import("PIL")
EASYOCR = safe_import("easyocr")


def extract_image(path: Path, config: ScanConfig) -> ExtractedContent:
    warnings: list[str] = []
    if config.enable_ocr and EASYOCR is not None:
        try:
            import easyocr

            reader = easyocr.Reader(["ru", "en"], gpu=False)
            fragments = reader.readtext(str(path), detail=0, paragraph=True)
            return finalize_text("\n".join(fragments), "image_easyocr", config.max_text_chars)
        except Exception:
            warnings.append("EasyOCR не смог распознать изображение.")

    if config.enable_ocr and PIL is not None and PYTESSERACT is not None:
        try:
            from PIL import Image

            image = Image.open(str(path))
            text = PYTESSERACT.image_to_string(image, lang="rus+eng")
            result = finalize_text(text, "image_tesseract", config.max_text_chars)
            result.warnings.extend(warnings)
            return result
        except Exception:
            warnings.append("Tesseract не смог распознать изображение.")
    elif config.enable_ocr:
        warnings.append("OCR включен, но easyocr/pillow/pytesseract не установлены.")

    result = extract_binary_strings(path, config)
    result.method = "image_binary_fallback"
    result.warnings.extend(warnings)
    if not config.enable_ocr:
        result.warnings.append("OCR отключен, изображение обработано без распознавания текста.")
    return result
