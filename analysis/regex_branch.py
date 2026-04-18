from __future__ import annotations

from typing import Dict

from detectors import detect_regex_categories


def run_regex_branch(text: str) -> Dict[str, int]:
    return detect_regex_categories(text)
