"""
Обработчик для категории 'image': JPG/JPEG/PNG/GIF/TIF/TIFF/BMP.

Контракт (общий с document_handlers.py):
    extract_image(path: Path) -> Iterator[TextChunk]

Принципы:
- OCR через pytesseract (обёртка над системным бинарником Tesseract).
  Источник: https://github.com/madmaze/pytesseract
- Многостраничные TIFF/GIF итерируются через PIL.ImageSequence
  (yield по кадру - каждый кадр становится отдельным TextChunk c meta.page).
- Перед OCR кадр переводится в градации серого ('L') - это повышает
  качество распознавания, рекомендация Tesseract: https://tesseract-ocr.github.io/tessdoc/ImproveQuality.html
- meta.via_ocr=True - сигнал классификатору снижать уверенность
  (OCR ошибается на сканах, размытии, рукописном тексте).
- OCR - ОПЦИОНАЛЬНО по ТЗ. Если Tesseract не установлен или недоступен
  нужный язык, extract_image() возвращает пустой генератор + диспетчер
  запишет осмысленный status/note. Программа не падает.

Требования к окружению (для полноценной работы OCR):
- pytesseract (pip install)
- Pillow (pip install; уже транзитивная зависимость pytesseract)
- Системный Tesseract OCR:
    - Windows: https://github.com/UB-Mannheim/tesseract/wiki
    - Linux: пакет 'tesseract-ocr' + 'tesseract-ocr-rus'
- Языковые данные rus.traineddata + eng.traineddata в TESSDATA_PREFIX:
    https://github.com/tesseract-ocr/tessdata
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, List

from document_handlers import TextChunk


# ---------------------------------------------------------------------------
# Проверка доступности Tesseract без исключений наружу.
# ---------------------------------------------------------------------------
def _tesseract_available() -> bool:
    try:
        import pytesseract  # noqa: F401
    except ImportError:
        return False
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def _pick_languages(available: List[str]) -> str:
    """Выбираем 'rus+eng' если оба установлены, иначе что есть, по умолчанию 'eng'."""
    preferred = [lang for lang in ("rus", "eng") if lang in available]
    if preferred:
        return "+".join(preferred)
    if available:
        return available[0]
    return "eng"


# ---------------------------------------------------------------------------
# Основной экстрактор.
# ---------------------------------------------------------------------------
def extract_image(path: Path) -> Iterator[TextChunk]:
    try:
        import pytesseract
        from PIL import Image, ImageSequence, UnidentifiedImageError
    except ImportError:
        # Библиотеки не установлены - деликатно выходим. Диспетчер поставит note.
        return

    if not _tesseract_available():
        return

    try:
        available_langs = list(pytesseract.get_languages(config=""))
    except Exception:
        available_langs = ["eng"]
    languages = _pick_languages(available_langs)

    try:
        img_ctx = Image.open(str(path))
    except (UnidentifiedImageError, OSError, ValueError):
        return

    with img_ctx as img:
        frames_iter = ImageSequence.Iterator(img)
        page_idx = 0
        for frame in frames_iter:
            page_idx += 1
            try:
                ocr_frame = frame.convert("L")
                text = pytesseract.image_to_string(ocr_frame, lang=languages)
            except Exception:
                continue

            if not text or not text.strip():
                continue

            yield TextChunk(
                text=text,
                source=f"{path.name}#page={page_idx}",
                meta={
                    "page": page_idx,
                    "via_ocr": True,
                    "ocr_lang": languages,
                    "width": getattr(frame, "width", None),
                    "height": getattr(frame, "height", None),
                },
            )


# ---------------------------------------------------------------------------
# Карта: расширение -> экстрактор (использует main.py).
# Покрывает все расширения-изображения из датасета (.jpg, .png, .tif, .gif)
# плюс родственные (.jpeg, .tiff, .bmp) - общее требование ТЗ.
# ---------------------------------------------------------------------------
IMAGE_EXTRACTORS = {
    "jpg":  extract_image,
    "jpeg": extract_image,
    "png":  extract_image,
    "gif":  extract_image,
    "tif":  extract_image,
    "tiff": extract_image,
    "bmp":  extract_image,
}
