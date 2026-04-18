from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable

from analysis import analyze_text
from documents import extract_text
from models import ScanConfig, ScanResult


MONTH_ABBR = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")


def discover_files(root: Path, include_extensions: set[str]) -> Iterable[Path]:
    normalized = {extension.lower().lstrip(".") for extension in include_extensions}
    if root.is_file():
        extension = root.suffix.lower().lstrip(".")
        if extension in normalized:
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        extension = path.suffix.lower().lstrip(".")
        if extension in normalized:
            yield path


def format_result_time(path: Path) -> str:
    modified = datetime.fromtimestamp(path.stat().st_mtime)
    month = MONTH_ABBR[modified.month - 1]
    return f"{month} {modified.day:02d} {modified:%H:%M}"


def scan_file(path: Path, config: ScanConfig) -> ScanResult:
    extracted = extract_text(path, config)
    categories, uz, recommendations = analyze_text(extracted.text, workers=config.analysis_workers)
    warnings = list(extracted.warnings)
    if extracted.truncated:
        warnings.append("Извлеченный текст был усечен по лимиту символов.")

    return ScanResult(
        path=str(path),
        name=path.name,
        size=path.stat().st_size,
        time=format_result_time(path),
        file_format=path.suffix.lower().lstrip(".") or "unknown",
        categories=categories,
        uz=uz,
        findings_count=sum(categories.values()),
        extractor=extracted.method,
        recommendations=recommendations,
        warnings=warnings,
    )


def scan_root(config: ScanConfig) -> list[ScanResult]:
    results: list[ScanResult] = []
    for path in discover_files(config.root, config.include_extensions):
        try:
            result = scan_file(path, config)
        except Exception:
            if config.include_empty_results:
                result = ScanResult(
                    path=str(path),
                    name=path.name,
                    size=path.stat().st_size,
                    time=format_result_time(path),
                    file_format=path.suffix.lower().lstrip(".") or "unknown",
                    categories={},
                    uz="нет признаков",
                    findings_count=0,
                    extractor="failed",
                    recommendations=[],
                    warnings=["Файл не удалось обработать."],
                )
            else:
                continue
        if result.findings_count > 0 or config.include_empty_results:
            results.append(result)
    return results
