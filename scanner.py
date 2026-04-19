from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Iterable

from analysis import analyze_text
from documents import extract_text
from models import ScanConfig, ScanResult


MONTH_ABBR = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_PROGRESS_STEP = 50
_PROGRESS_BAR_WIDTH = 24


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
    if not extracted.text or not extracted.text.strip():
        return ScanResult(
            path=str(path),
            name=path.name,
            size=path.stat().st_size,
            time=format_result_time(path),
            file_format=path.suffix.lower().lstrip(".") or "unknown",
            categories={},
            uz="нет признаков",
            findings_count=0,
            extractor=extracted.method,
            recommendations=[],
            warnings=list(extracted.warnings),
        )

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


def _empty_result(path: Path) -> ScanResult:
    return ScanResult(
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


def _process_path(path: Path, config: ScanConfig) -> tuple[Path, float, str, ScanResult | None]:
    started = perf_counter()
    try:
        result = scan_file(path, config)
        return path, perf_counter() - started, "ok", result
    except Exception:
        return path, perf_counter() - started, "failed", None


def _write_slow_log(config: ScanConfig, rows: list[tuple[str, str, float, str]]) -> None:
    target = getattr(config, "slow_log_path", None)
    if target is None:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["path", "ext", "seconds", "status"])
        for path, ext, seconds, status in rows:
            writer.writerow([path, ext, f"{seconds:.3f}", status])


def _print_progress(completed: int, total: int) -> None:
    if total <= 0:
        return
    ratio = min(1.0, max(0.0, completed / total))
    filled = int(round(ratio * _PROGRESS_BAR_WIDTH))
    bar = "#" * filled + "-" * (_PROGRESS_BAR_WIDTH - filled)
    print(f"[progress] [{bar}] {completed}/{total} ({ratio * 100:.1f}%)")


def scan_root(config: ScanConfig) -> list[ScanResult]:
    paths = list(discover_files(config.root, config.include_extensions))
    total_files = len(paths)
    results: list[ScanResult] = []
    slow_rows: list[tuple[str, str, float, str]] = []
    slow_threshold = max(0.0, getattr(config, "slow_threshold_seconds", 20.0))

    workers = max(1, getattr(config, "file_workers", 1))
    if workers <= 1 or total_files <= 1:
        for index, path in enumerate(paths, start=1):
            path_, elapsed, status, result = _process_path(path, config)
            extension = path.suffix.lower().lstrip(".") or "unknown"
            if config.debug_progress:
                print(f"[debug] {index}/{total_files} {extension} {elapsed:.3f}s {path.name} {status}")
            if elapsed >= slow_threshold:
                slow_rows.append((str(path), extension, elapsed, status))
            if result is not None:
                if result.findings_count > 0 or config.include_empty_results:
                    results.append(result)
            elif config.include_empty_results:
                results.append(_empty_result(path))
            if config.debug_progress and (index % _PROGRESS_STEP == 0 or index == total_files):
                _print_progress(index, total_files)
        _write_slow_log(config, slow_rows)
        return results

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_path = {executor.submit(_process_path, path, config): path for path in paths}
        completed = 0
        for future in as_completed(future_to_path):
            completed += 1
            path, elapsed, status, result = future.result()
            extension = path.suffix.lower().lstrip(".") or "unknown"
            if config.debug_progress:
                print(f"[debug] {completed}/{total_files} {extension} {elapsed:.3f}s {path.name} {status}")
            if elapsed >= slow_threshold:
                slow_rows.append((str(path), extension, elapsed, status))
            if result is not None:
                if result.findings_count > 0 or config.include_empty_results:
                    results.append(result)
            elif config.include_empty_results:
                results.append(_empty_result(path))
            if config.debug_progress and (completed % _PROGRESS_STEP == 0 or completed == total_files):
                _print_progress(completed, total_files)
    _write_slow_log(config, slow_rows)
    return results
