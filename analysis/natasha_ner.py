"""Тонкая обёртка над Natasha NER для подтверждения ФИО.

Используется как фильтр поверх regex-кандидатов: regex даёт быстрый список
вероятных ФИО, Natasha подтверждает / опровергает по тегу PER. Также
извлекает PER, которые regex упустил, чтобы не потерять recall.
"""

from __future__ import annotations

import os
import threading
from typing import List, Set, Tuple


_LOCK = threading.Lock()
_PIPELINE = None
_LOAD_FAILED = False

_MAX_TEXT_CHARS = 200_000


def _is_disabled() -> bool:
    return os.environ.get("DISABLE_NATASHA", "").strip() in ("1", "true", "yes")


def _load_pipeline():
    """Ленивая инициализация Natasha. Один раз на процесс."""
    global _PIPELINE, _LOAD_FAILED
    if _is_disabled():
        return None
    if _PIPELINE is not None or _LOAD_FAILED:
        return _PIPELINE
    with _LOCK:
        if _PIPELINE is not None or _LOAD_FAILED:
            return _PIPELINE
        try:
            from natasha import (
                Segmenter,
                NewsEmbedding,
                NewsNERTagger,
                Doc,
            )

            segmenter = Segmenter()
            emb = NewsEmbedding()
            ner_tagger = NewsNERTagger(emb)
            _PIPELINE = (segmenter, ner_tagger, Doc)
        except Exception:
            _LOAD_FAILED = True
            _PIPELINE = None
    return _PIPELINE


def warmup() -> bool:
    """Прогрев модели (вызывается из CLI при --warmup-model)."""
    return _load_pipeline() is not None


def _normalize_person(span_text: str) -> str:
    return " ".join(span_text.split()).lower()


def analyze(text: str) -> Tuple[List[Tuple[int, int, str]], List[Tuple[int, int]]]:
    """Возвращает (PER-спаны со start/end/normalized, LOC/ORG-спаны) одним проходом.
    На больших текстах урезаем до _MAX_TEXT_CHARS, чтобы не проседать по скорости.
    """
    empty: Tuple[List[Tuple[int, int, str]], List[Tuple[int, int]]] = ([], [])
    if not text:
        return empty
    pipeline = _load_pipeline()
    if pipeline is None:
        return empty

    snippet = text[:_MAX_TEXT_CHARS]
    segmenter, ner_tagger, Doc = pipeline
    try:
        doc = Doc(snippet)
        doc.segment(segmenter)
        doc.tag_ner(ner_tagger)
    except Exception:
        return empty

    persons: List[Tuple[int, int, str]] = []
    non_person: List[Tuple[int, int]] = []
    for span in doc.spans:
        if span.type == "PER":
            normalized = _normalize_person(span.text)
            if normalized and len(normalized) >= 3:
                persons.append((span.start, span.stop, normalized))
        elif span.type in ("LOC", "ORG"):
            non_person.append((span.start, span.stop))
    return persons, non_person


def is_available() -> bool:
    return _load_pipeline() is not None
