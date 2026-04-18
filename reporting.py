from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from models import ScanResult


def write_report(results: list[ScanResult], output_path: Path, output_format: str) -> None:
    output_format = output_format.lower()
    if output_format == "csv":
        _write_csv(results, output_path)
        return
    if output_format == "json":
        _write_json(results, output_path)
        return
    if output_format in {"md", "markdown"}:
        _write_markdown(results, output_path)
        return
    raise ValueError(f"Неподдерживаемый формат отчета: {output_format}")


def _write_csv(results: list[ScanResult], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["size", "time", "name"])
        writer.writeheader()
        for item in results:
            writer.writerow(
                {
                    "size": item.size,
                    "time": item.time,
                    "name": item.name,
                }
            )


def _write_json(results: list[ScanResult], output_path: Path) -> None:
    payload = [
        {
            "path": item.path,
            "name": item.name,
            "size": item.size,
            "time": item.time,
            "file_format": item.file_format,
            "categories": item.categories,
            "findings_count": item.findings_count,
            "uz": item.uz,
            "extractor": item.extractor,
            "recommendations": item.recommendations,
            "warnings": item.warnings,
        }
        for item in results
    ]
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_markdown(results: list[ScanResult], output_path: Path) -> None:
    totals = Counter()
    uz_totals = Counter()
    for item in results:
        uz_totals[item.uz] += 1
        for category, count in item.categories.items():
            totals[category] += count

    lines = [
        "# Отчет по сканированию ПДн",
        "",
        f"- Обработано файлов с результатом: {len(results)}",
        f"- Распределение по УЗ: {dict(uz_totals)}",
        f"- Суммарные находки по категориям: {dict(totals)}",
        "",
        "| Size | Time | Name | УЗ | Категории ПДн |",
        "| ---: | --- | --- | --- | --- |",
    ]
    for item in results:
        lines.append(
            f"| {item.size} | {item.time} | `{item.name}` | {item.uz} | "
            f"{', '.join(item.detected_categories) or 'нет'} |"
        )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
