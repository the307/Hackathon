from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Dict

from detectors import BIOMETRIC_KEYWORDS, SPECIAL_KEYWORDS


MODEL_DIR = Path(__file__).resolve().parents[1] / "model_artifacts" / "special_pii_classifier"
MODEL_LABELS = {
    0: "health",
    1: "beliefs",
    2: "race",
    3: "other",
}
DEFAULT_THRESHOLD = 0.45
POLICY_NOISE_KEYWORDS = (
    "privacy policy",
    "cookie policy",
    "cookies",
    "политика конфиденциальности",
    "условия использования",
    "terms of use",
    "website",
    "site map",
    "copyright",
    "all rights reserved",
    "livejournal",
    "follow us",
    "choose language",
    "log in",
    "user agreement",
    "университет",
    "рейтинг нпр",
)
LABEL_EVIDENCE_KEYWORDS = {
    "health": (
        "диагноз",
        "пациент",
        "инвалид",
        "аллерг",
        "лечени",
        "медосмотр",
        "заболев",
        "medical record",
    ),
    "beliefs": (
        "вероисповед",
        "религи",
        "политическ",
        "партии",
        "митинг",
        "убеждени",
        "членом",
    ),
    "race": (
        "национальн",
        "этническ",
        "раса",
        "происхожд",
        "коренному народу",
        "этнос",
    ),
    "other": (
        "отпечат",
        "радужной оболоч",
        "радужк",
        "голосовой образец",
        "биометр",
        "судим",
        "дактилоскоп",
        "распознавание лица",
    ),
}


def split_text_for_classification(text: str, chunk_size: int = 800) -> list[str]:
    normalized = re.sub(r"\s+", " ", text or "").strip()
    if not normalized:
        return []
    parts = re.split(r"(?<=[.!?])\s+|\n+", normalized)
    chunks: list[str] = []
    current = ""
    for part in parts:
        if not part:
            continue
        candidate = f"{current} {part}".strip() if current else part
        if len(candidate) <= chunk_size:
            current = candidate
        else:
            if current:
                chunks.append(current)
            current = part[:chunk_size]
    if current:
        chunks.append(current)
    return chunks or [normalized[:chunk_size]]


@lru_cache(maxsize=1)
def _load_model_bundle():
    if not MODEL_DIR.exists():
        return None
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
        model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR))
    except Exception:
        return None
    model.eval()
    return torch, tokenizer, model


def predict_special_labels(text: str, threshold: float = DEFAULT_THRESHOLD) -> Dict[str, int]:
    bundle = _load_model_bundle()
    if bundle is None:
        return {}

    torch, tokenizer, model = bundle
    chunks = split_text_for_classification(text)
    if not chunks:
        return {}

    probabilities = torch.zeros(len(MODEL_LABELS), dtype=torch.float32)
    with torch.no_grad():
        for chunk in chunks[:8]:
            encoded = tokenizer(
                chunk,
                truncation=True,
                padding=True,
                max_length=512,
                return_tensors="pt",
            )
            outputs = model(**encoded)
            logits = outputs.logits.squeeze(0)
            probs = torch.sigmoid(logits).cpu()
            probabilities = torch.maximum(probabilities, probs)

    return {
        MODEL_LABELS[index]: 1
        for index, probability in enumerate(probabilities.tolist())
        if probability >= threshold
    }


def is_policy_noise(text: str) -> bool:
    lowered = (text or "").lower()
    return any(keyword in lowered for keyword in POLICY_NOISE_KEYWORDS)


def has_label_evidence(text: str, label: str) -> bool:
    lowered = (text or "").lower()
    return any(keyword in lowered for keyword in LABEL_EVIDENCE_KEYWORDS.get(label, ()))


def has_any_label_evidence(text: str) -> bool:
    return any(has_label_evidence(text, label) for label in LABEL_EVIDENCE_KEYWORDS)


def should_run_model(text: str) -> bool:
    lowered = (text or "").lower()
    if not lowered:
        return False
    if is_policy_noise(lowered) and not has_any_label_evidence(lowered):
        return False
    trigger_keywords = {keyword for keywords in LABEL_EVIDENCE_KEYWORDS.values() for keyword in keywords}
    trigger_keywords.update(BIOMETRIC_KEYWORDS)
    trigger_keywords.update(SPECIAL_KEYWORDS)
    return any(keyword in lowered for keyword in trigger_keywords)


def map_model_predictions_to_categories(text: str, labels: Dict[str, int]) -> Dict[str, int]:
    counts = {"обычные": 0, "государственные": 0, "платежные": 0, "биометрические": 0, "специальные": 0}
    if not should_run_model(text):
        return counts
    if is_policy_noise(text) and not has_any_label_evidence(text):
        return counts

    if labels.get("health"):
        if has_label_evidence(text, "health"):
            counts["специальные"] += 1
    if labels.get("beliefs"):
        if has_label_evidence(text, "beliefs"):
            counts["специальные"] += 1
    if labels.get("race"):
        if has_label_evidence(text, "race"):
            counts["специальные"] += 1
    if labels.get("other"):
        lowered = (text or "").lower()
        if has_label_evidence(text, "other"):
            if any(keyword in lowered for keyword in BIOMETRIC_KEYWORDS):
                counts["биометрические"] += 1
            else:
                counts["специальные"] += 1
    return counts
