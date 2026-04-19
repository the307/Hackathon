from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Dict

from detectors import BIOMETRIC_KEYWORDS, PERSON_CONTEXT_KEYWORDS, SPECIAL_KEYWORDS


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
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
    except Exception:
        return None
    model.eval()
    return torch, tokenizer, model, device


def _select_relevant_chunks(chunks: list[str], max_chunks: int) -> list[str]:
    if not chunks:
        return []
    scored: list[tuple[int, int, str]] = []
    for index, chunk in enumerate(chunks):
        lowered = chunk.lower()
        score = sum(1 for keyword in _TRIGGER_KEYWORDS if keyword in lowered)
        if score == 0 and any(keyword in lowered for keyword in _PERSON_TRIGGERS):
            score = 1
        if score > 0:
            scored.append((-score, index, chunk))
    if scored:
        scored.sort()
        return [item[2] for item in scored[:max_chunks]]
    return chunks[:max_chunks]


def predict_special_labels(text: str, threshold: float = DEFAULT_THRESHOLD, max_chunks: int = 3) -> Dict[str, int]:
    bundle = _load_model_bundle()
    if bundle is None:
        return {}

    torch, tokenizer, model, device = bundle
    chunks = split_text_for_classification(text)
    if not chunks:
        return {}

    relevant = _select_relevant_chunks(chunks, max_chunks)
    if not relevant:
        return {}

    with torch.no_grad():
        encoded = tokenizer(
            relevant,
            truncation=True,
            padding=True,
            max_length=384,
            return_tensors="pt",
        )
        encoded = {key: value.to(device) for key, value in encoded.items()}
        outputs = model(**encoded)
        logits = outputs.logits
        probs = torch.sigmoid(logits)
        probabilities = probs.max(dim=0).values.cpu()

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


_TRIGGER_KEYWORDS = (
    {keyword for keywords in LABEL_EVIDENCE_KEYWORDS.values() for keyword in keywords}
    | set(BIOMETRIC_KEYWORDS)
    | set(SPECIAL_KEYWORDS)
)
_PERSON_TRIGGERS = set(PERSON_CONTEXT_KEYWORDS)
_MIN_DOC_LEN_FOR_MODEL = 1500


@lru_cache(maxsize=2048)
def _should_run_model_cached(text_hash: int, sample: str, length: int) -> bool:
    if not sample:
        return False
    if is_policy_noise(sample) and not has_any_label_evidence(sample):
        return False
    if any(keyword in sample for keyword in _TRIGGER_KEYWORDS):
        return True
    if length >= _MIN_DOC_LEN_FOR_MODEL:
        person_hits = sum(1 for keyword in _PERSON_TRIGGERS if keyword in sample)
        if person_hits >= 2:
            return True
    return False


def should_run_model(text: str) -> bool:
    lowered = (text or "").lower()
    if not lowered:
        return False
    sample = lowered if len(lowered) <= 4000 else lowered[:2000] + lowered[-2000:]
    return _should_run_model_cached(hash(sample), sample, len(lowered))


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
