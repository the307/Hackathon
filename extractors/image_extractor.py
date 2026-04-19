from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable

from models import ExtractedContent, ScanConfig

from .common import finalize_text, safe_import


PYTESSERACT = safe_import("pytesseract")
PIL = safe_import("PIL")
EASYOCR = safe_import("easyocr")


@lru_cache(maxsize=1)
def _tesseract_available() -> bool:
    if PYTESSERACT is None:
        return False
    try:
        PYTESSERACT.get_tesseract_version()
        return True
    except Exception:
        return False


@lru_cache(maxsize=1)
def _available_languages() -> tuple[str, ...]:
    if not _tesseract_available():
        return ()
    try:
        return tuple(PYTESSERACT.get_languages(config=""))
    except Exception:
        return ()


def _pick_languages(available: Iterable[str]) -> str:
    avail = set(available)
    preferred = [lang for lang in ("rus", "eng") if lang in avail]
    if preferred:
        return "+".join(preferred)
    if avail:
        return next(iter(avail))
    return "eng"


def _ocr_with_tesseract(path: Path) -> tuple[str, str | None]:
    try:
        from PIL import Image, ImageSequence, UnidentifiedImageError
    except Exception:
        return "", "Pillow недоступен."

    languages = _pick_languages(_available_languages())
    fragments: list[str] = []
    try:
        with Image.open(str(path)) as img:
            for frame in ImageSequence.Iterator(img):
                try:
                    grayscale = frame.convert("L")
                    text = PYTESSERACT.image_to_string(grayscale, lang=languages)
                except Exception:
                    continue
                if text and text.strip():
                    fragments.append(text)
    except (UnidentifiedImageError, OSError, ValueError):
        return "", "Не удалось открыть изображение (повреждено или неподдерживаемый формат)."
    except Exception:
        return "", "Tesseract не смог распознать изображение."

    return "\n".join(fragments), None


def extract_image(path: Path, config: ScanConfig) -> ExtractedContent:
    warnings: list[str] = []
    if not config.enable_ocr:
        return ExtractedContent(
            text="",
            method="image_skipped_no_ocr",
            warnings=["Изображение пропущено: OCR отключен."],
        )

    if EASYOCR is not None:
        try:
            import easyocr

            reader = easyocr.Reader(["ru", "en"], gpu=False)
            fragments = reader.readtext(str(path), detail=0, paragraph=True)
            return finalize_text("\n".join(fragments), "image_easyocr", config.max_text_chars)
        except Exception:
            warnings.append("EasyOCR не смог распознать изображение.")

    if PIL is not None and _tesseract_available():
        text, error = _ocr_with_tesseract(path)
        if text.strip():
            result = finalize_text(text, "image_tesseract", config.max_text_chars)
            result.warnings.extend(warnings)
            return result
        if error:
            warnings.append(error)
        else:
            warnings.append("Tesseract не нашел текста в изображении.")
        return ExtractedContent(text="", method="image_tesseract_empty", warnings=warnings)

    warnings.append("OCR включен, но easyocr/pillow/системный Tesseract не доступны.")
    return ExtractedContent(text="", method="image_ocr_unavailable", warnings=warnings)
