from __future__ import annotations

from typing import Dict

from detectors import detect_ner_categories


def run_ner_branch(text: str) -> Dict[str, int]:
    return detect_ner_categories(text)
