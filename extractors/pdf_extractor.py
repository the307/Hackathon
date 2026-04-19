from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

from models import ExtractedContent, ScanConfig

from .common import extract_pdf_strings, finalize_text, safe_import


PYPDF = safe_import("pypdf")
PYPDF2 = safe_import("PyPDF2")
PDFMINER = safe_import("pdfminer")
PDF2IMAGE = safe_import("pdf2image")
PYTESSERACT = safe_import("pytesseract")
EASYOCR = safe_import("easyocr")
NUMPY = safe_import("numpy")

_MEANINGFUL_RE = re.compile(r"[A-Za-zА-Яа-яЁё0-9]")
_CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")
_LATIN_RE = re.compile(r"[A-Za-z]")
_MIN_MEANINGFUL_CHARS = 50
_MAX_PDF_PAGES = 60
_OCR_DPI = 200
_OCR_SAMPLE_RATIO = 5
_OCR_SAMPLE_MIN = 2
_OCR_SAMPLE_MAX = 6
_OCR_FULL_PAGE_LIMIT = 15
_OCR_MIN_MEANINGFUL_PER_PAGE = 30


_LATIN_TO_CYRILLIC = str.maketrans({
    "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н", "K": "К", "M": "М",
    "O": "О", "P": "Р", "T": "Т", "X": "Х", "Y": "У", "I": "І",
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у",
    "u": "и", "n": "п", "m": "м", "h": "н", "k": "к", "t": "т", "r": "г",
    "i": "і", "g": "д", "b": "ь", "B": "В",
    "4": "ч",
})


def _looks_mixed_script(token: str) -> bool:
    has_cyr = bool(_CYRILLIC_RE.search(token))
    has_lat = bool(_LATIN_RE.search(token))
    return has_cyr and has_lat


def _normalize_mixed_script(text: str) -> str:
    """Чиним частный OCR-артефакт: tesseract в русских словах оставляет
    одиночные латинские глифы похожих форм (H, B, T, K, E, ...). Маппим только
    слова, где уже есть и латиница, и кириллица — это безопасно."""
    if not text:
        return text
    out: list[str] = []
    for token in re.split(r"(\s+)", text):
        if token.strip() and _looks_mixed_script(token):
            out.append(token.translate(_LATIN_TO_CYRILLIC))
        else:
            out.append(token)
    return "".join(out)


def _cyrillic_share(text: str) -> float:
    if not text:
        return 0.0
    cyr = len(_CYRILLIC_RE.findall(text))
    lat = len(_LATIN_RE.findall(text))
    total = cyr + lat
    if total == 0:
        return 0.0
    return cyr / total


_DEFAULT_TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
_DEFAULT_POPPLER_BIN = r"C:\Program Files\poppler-25.12.0\Library\bin"


def _configure_native_ocr() -> None:
    if PYTESSERACT is not None and os.path.exists(_DEFAULT_TESSERACT_PATH):
        try:
            PYTESSERACT.pytesseract.tesseract_cmd = _DEFAULT_TESSERACT_PATH
        except Exception:
            pass


_configure_native_ocr()


@lru_cache(maxsize=1)
def _ocr_languages() -> str:
    if PYTESSERACT is None:
        return "eng"
    try:
        available = set(PYTESSERACT.get_languages(config=""))
    except Exception:
        return "eng"
    preferred = [lang for lang in ("rus", "eng") if lang in available]
    if preferred:
        return "+".join(preferred)
    if available:
        return next(iter(available))
    return "eng"


@lru_cache(maxsize=1)
def _ocr_language_variants() -> tuple[str, ...]:
    """Возвращает 1-2 варианта языков для двойного прохода:
    сначала только rus (точнее на чистой кириллице), затем rus+eng."""
    if PYTESSERACT is None:
        return ("eng",)
    try:
        available = set(PYTESSERACT.get_languages(config=""))
    except Exception:
        return ("eng",)
    combined = "+".join(lang for lang in ("rus", "eng") if lang in available)
    if combined:
        return (combined,)
    if "rus" in available:
        return ("rus",)
    if available:
        return (next(iter(available)),)
    return ("eng",)


def _has_meaningful_text(text: str) -> bool:
    return len(_MEANINGFUL_RE.findall(text)) >= _MIN_MEANINGFUL_CHARS


def _page_looks_like_scan(page) -> bool:
    """Эвристика по объекту страницы pypdf: есть картинки и нет шрифтов = скан."""
    try:
        resources = page.get("/Resources")
        if resources is None:
            return False
        try:
            resources = resources.get_object()
        except Exception:
            pass
        fonts = resources.get("/Font") if hasattr(resources, "get") else None
        xobject = resources.get("/XObject") if hasattr(resources, "get") else None
        try:
            xobject = xobject.get_object() if xobject is not None else None
        except Exception:
            pass
        has_image = False
        if xobject is not None and hasattr(xobject, "values"):
            for value in xobject.values():
                try:
                    obj = value.get_object()
                    if obj.get("/Subtype") == "/Image":
                        has_image = True
                        break
                except Exception:
                    continue
        has_fonts = bool(fonts)
        return has_image and not has_fonts
    except Exception:
        return False


def _looks_like_scanned_pdf_via_pypdf(path: Path) -> bool:
    if PYPDF is None:
        return False
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        pages = reader.pages
        if not pages:
            return False
        sample = min(len(pages), 3)
        scan_hits = sum(1 for index in range(sample) if _page_looks_like_scan(pages[index]))
        return scan_hits == sample
    except Exception:
        return False


def _select_sample_pages(page_count: int) -> list[int]:
    sample_size = max(_OCR_SAMPLE_MIN, min(_OCR_SAMPLE_MAX, page_count // _OCR_SAMPLE_RATIO or _OCR_SAMPLE_MIN))
    sample_size = min(sample_size, page_count)
    if sample_size <= 0:
        return []
    if sample_size >= page_count:
        return list(range(1, page_count + 1))
    step = max(1, page_count // sample_size)
    pages = list(range(1, page_count + 1, step))[:sample_size]
    if pages[-1] != page_count:
        pages[-1] = page_count
    return sorted(set(pages))


def _ocr_page(path: Path, page_number: int, poppler_path: str | None) -> str:
    easyocr_text = _ocr_page_easyocr(path, page_number, poppler_path)
    if easyocr_text and len(_MEANINGFUL_RE.findall(easyocr_text)) >= _OCR_MIN_MEANINGFUL_PER_PAGE:
        return easyocr_text

    if PDF2IMAGE is None or PYTESSERACT is None:
        return ""
    try:
        from pdf2image import convert_from_path

        kwargs = {
            "dpi": _OCR_DPI,
            "first_page": page_number,
            "last_page": page_number,
        }
        if poppler_path:
            kwargs["poppler_path"] = poppler_path
        images = convert_from_path(str(path), **kwargs)
    except Exception:
        return ""
    if not images:
        return ""

    grayscale = images[0].convert("L")
    variants = _ocr_language_variants()
    best_text = ""
    best_score = -1.0
    for lang in variants:
        try:
            text = PYTESSERACT.image_to_string(grayscale, lang=lang)
        except Exception:
            continue
        if not text:
            continue
        cyr_share = _cyrillic_share(text)
        meaningful = len(_MEANINGFUL_RE.findall(text))
        score = cyr_share * 1000 + meaningful * 0.01
        if score > best_score:
            best_score = score
            best_text = text

    if not best_text:
        return ""
    return _normalize_mixed_script(best_text)


def _resolve_poppler_path() -> str | None:
    if os.path.isdir(_DEFAULT_POPPLER_BIN):
        return _DEFAULT_POPPLER_BIN
    return None


@lru_cache(maxsize=1)
def _easyocr_reader():
    if EASYOCR is None:
        return None
    try:
        import torch

        gpu = bool(torch.cuda.is_available())
    except Exception:
        gpu = False
    try:
        return EASYOCR.Reader(["ru", "en"], gpu=gpu, verbose=False)
    except Exception:
        return None


def _ocr_page_easyocr(path: Path, page_number: int, poppler_path: str | None) -> str:
    if PDF2IMAGE is None or EASYOCR is None or NUMPY is None:
        return ""
    reader = _easyocr_reader()
    if reader is None:
        return ""
    try:
        from pdf2image import convert_from_path

        kwargs = {
            "dpi": _OCR_DPI,
            "first_page": page_number,
            "last_page": page_number,
        }
        if poppler_path:
            kwargs["poppler_path"] = poppler_path
        images = convert_from_path(str(path), **kwargs)
    except Exception:
        return ""
    if not images:
        return ""
    try:
        lines = reader.readtext(NUMPY.array(images[0]), detail=0, paragraph=True)
    except Exception:
        return ""
    if not lines:
        return ""
    return _normalize_mixed_script("\n".join(str(line) for line in lines if str(line).strip()))


def _ocr_scanned_pdf(path: Path, page_count: int) -> tuple[str, list[str]]:
    """Сначала OCR-им сэмпл (~1/5 страниц). Если на нем есть осмысленный текст,
    дочитываем оставшиеся страницы до _OCR_FULL_PAGE_LIMIT."""
    if PDF2IMAGE is None or PYTESSERACT is None:
        return "", ["pdf2image/pytesseract недоступны для OCR PDF."]

    poppler_path = _resolve_poppler_path()
    sample_pages = _select_sample_pages(page_count)
    if not sample_pages:
        return "", []

    notes: list[str] = []
    sample_fragments: dict[int, str] = {}
    sample_meaningful = 0
    for page_number in sample_pages:
        text = _ocr_page(path, page_number, poppler_path)
        sample_fragments[page_number] = text
        if text and len(_MEANINGFUL_RE.findall(text)) >= _OCR_MIN_MEANINGFUL_PER_PAGE:
            sample_meaningful += 1

    if sample_meaningful == 0:
        notes.append(
            f"PDF-скан из {page_count} страниц: на сэмпле {len(sample_pages)} страниц текст не найден, документ пропущен."
        )
        return "", notes

    full_limit = min(page_count, _OCR_FULL_PAGE_LIMIT)
    fragments: list[str] = []
    for page_number in range(1, full_limit + 1):
        text = sample_fragments.get(page_number)
        if text is None:
            text = _ocr_page(path, page_number, poppler_path)
        if text and text.strip():
            fragments.append(text)

    if page_count > _OCR_FULL_PAGE_LIMIT:
        notes.append(
            f"PDF-скан из {page_count} страниц, OCR применен к первым {_OCR_FULL_PAGE_LIMIT}."
        )
    return "\n".join(fragments), notes


def extract_pdf(path: Path, config: ScanConfig) -> ExtractedContent:
    warnings: list[str] = []

    if PYPDF is not None:
        try:
            from pypdf import PdfReader

            reader = PdfReader(str(path))
            pages = reader.pages
            page_count = len(pages)

            sample = min(page_count, 3)
            scan_hits = sum(1 for index in range(sample) if _page_looks_like_scan(pages[index]))
            looks_scanned = sample > 0 and scan_hits == sample
            if looks_scanned:
                ocr_text, ocr_notes = _ocr_scanned_pdf(path, page_count)
                if ocr_text.strip():
                    result = finalize_text(ocr_text, "pdf_ocr", config.max_text_chars)
                    result.warnings.extend(warnings + ocr_notes)
                    return result
                return ExtractedContent(
                    text="",
                    method="pdf_scanned_no_text",
                    warnings=warnings + ocr_notes
                    + [f"PDF из {page_count} страниц: сканированный, текст не найден."],
                )

            limit = min(page_count, _MAX_PDF_PAGES)
            extracted_chunks: list[str] = []
            for index in range(limit):
                try:
                    extracted_chunks.append(pages[index].extract_text() or "")
                except Exception:
                    continue
            text = "\n".join(extracted_chunks)
            if page_count > _MAX_PDF_PAGES:
                warnings.append(f"PDF содержит {page_count} страниц, обработано первые {_MAX_PDF_PAGES}.")
            if _has_meaningful_text(text):
                result = finalize_text(text, "pdf_pypdf", config.max_text_chars)
                result.warnings.extend(warnings)
                return result
        except Exception:
            warnings.append("Pypdf недоступен или не смог извлечь текст.")

    if PYPDF2 is not None:
        try:
            from PyPDF2 import PdfReader

            reader = PdfReader(str(path))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            if _has_meaningful_text(text):
                result = finalize_text(text, "pdf_pypdf2", config.max_text_chars)
                result.warnings.extend(warnings)
                return result
        except Exception:
            warnings.append("PyPDF2 недоступен или не смог извлечь текст.")

    if PDFMINER is not None:
        try:
            from pdfminer.high_level import extract_text as pdfminer_extract_text

            text = pdfminer_extract_text(str(path)) or ""
            if _has_meaningful_text(text):
                result = finalize_text(text, "pdf_pdfminer", config.max_text_chars)
                result.warnings.extend(warnings)
                return result
        except Exception:
            warnings.append("pdfminer.six недоступен или не смог извлечь текст.")

    if _looks_like_scanned_pdf_via_pypdf(path):
        try:
            from pypdf import PdfReader

            page_count = len(PdfReader(str(path)).pages)
        except Exception:
            page_count = 0
        if page_count > 0:
            ocr_text, ocr_notes = _ocr_scanned_pdf(path, page_count)
            if ocr_text.strip():
                result = finalize_text(ocr_text, "pdf_ocr", config.max_text_chars)
                result.warnings.extend(warnings + ocr_notes)
                return result
            return ExtractedContent(
                text="",
                method="pdf_scanned_no_text",
                warnings=warnings + ocr_notes,
            )

    try:
        if path.stat().st_size > 10 * config.max_binary_read_bytes:
            return ExtractedContent(
                text="",
                method="pdf_too_large",
                warnings=warnings + ["PDF слишком большой для бинарного fallback, пропущен."],
            )
    except OSError:
        pass

    with path.open("rb") as handle:
        raw = handle.read(config.max_binary_read_bytes)
    extracted = extract_pdf_strings(raw)
    if extracted.strip() and _has_meaningful_text(extracted):
        result = finalize_text(extracted, "pdf_stream_fallback", config.max_text_chars)
        if path.stat().st_size > config.max_binary_read_bytes:
            result.warnings.append("PDF fallback ограничен по числу прочитанных байт.")
        result.warnings.extend(warnings)
        return result

    return ExtractedContent(
        text="",
        method="pdf_no_text",
        warnings=warnings + ["PDF не содержит извлекаемого текста."],
    )
