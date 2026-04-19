from __future__ import annotations

from typing import Dict, Iterable

from detectors import build_recommendations, classify_uz, merge_category_counts


def aggregate_categories(groups: Iterable[Dict[str, int]]) -> Dict[str, int]:
    return merge_category_counts(*groups)


def aggregate_analysis(groups: Iterable[Dict[str, int]]) -> tuple[Dict[str, int], str, list[str]]:
    categories = aggregate_categories(groups)
    uz = classify_uz(categories)
    recommendations = build_recommendations(categories, uz)
    return categories, uz, recommendations
