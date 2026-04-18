from __future__ import annotations

from typing import Dict

from detectors import detect_classifier_categories
from .model_special_classifier import map_model_predictions_to_categories, predict_special_labels, should_run_model


def run_classifier_branch(text: str) -> Dict[str, int]:
    if not should_run_model(text):
        return {"обычные": 0, "государственные": 0, "платежные": 0, "биометрические": 0, "специальные": 0}
    try:
        labels = predict_special_labels(text)
    except Exception:
        labels = {}

    if labels:
        return map_model_predictions_to_categories(text, labels)
    return detect_classifier_categories(text)
