from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .aggregator import aggregate_analysis
from .classifier_branch import run_classifier_branch
from .ner_branch import run_ner_branch
from .regex_branch import run_regex_branch


def analyze_text(text: str, workers: int = 3) -> tuple[dict[str, int], str, list[str]]:
    max_workers = max(1, workers)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(run_regex_branch, text),
            executor.submit(run_ner_branch, text),
            executor.submit(run_classifier_branch, text),
        ]
        groups = [future.result() for future in futures]
    return aggregate_analysis(groups)
