"""
Построение отчёта по результатам сканирования.

Контракт ТЗ хакатона (цитата задания):
  "В отчёт должно попадать: путь к файлу, найденные категории ПДн,
   количество, уровень защищённости (УЗ), формат файла и (опционально)
   рекомендации."

Отчёт формируется в трёх видах одновременно (форматы из ТЗ):
  - JSON   (машиночитаемый, с полными деталями по находкам)
  - CSV    (плоская таблица, удобна для просмотра/импорта)
  - Markdown (человекочитаемая сводка для проверяющих)

Все три файла пишутся в одну папку output_dir под общим timestamp'ом.

Этический контракт (152-ФЗ + ТЗ):
  В отчёте НЕТ сырых значений ПДн. Используются маски из find_pd.mask_value()
  и короткий SHA-256 для сопоставления находок без раскрытия значений.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from find_pd import CATEGORY_TO_GROUP, FileClassification


# ===========================================================================
# Рекомендации по УЗ
# ===========================================================================
# Источник мер: ПП РФ N 1119 "Об утверждении требований к защите персональных
# данных...", приказ ФСТЭК N 21 (состав и содержание организационных и
# технических мер). Ниже - краткая выжимка по УЗ, не юридическая консультация.
UZ_RECOMMENDATIONS: Dict[Optional[int], List[str]] = {
    1: [
        "УЗ-1 (максимальный): файл содержит биометрию или специальные категории ПДн.",
        "Перенести в изолированный контур с шифрованием хранения и передачи.",
        "Доступ - по списку, с журналированием, с обязательным МФА.",
        "Пересмотреть необходимость хранения: минимизировать или обезличить.",
    ],
    2: [
        "УЗ-2: платёжная информация или большой объём государственных идентификаторов.",
        "Шифрование при хранении; разграничение прав доступа по ролям.",
        "Журналировать доступ и выгрузки; включить DLP-контроль периметра.",
    ],
    3: [
        "УЗ-3: государственные идентификаторы либо большой объём обычных ПДн.",
        "Контроль доступа на уровне каталога; журналирование операций.",
        "Убедиться, что обработка соответствует заявленной цели и сроку хранения.",
    ],
    4: [
        "УЗ-4: небольшой объём обычных ПДн.",
        "Инвентаризировать и пометить как ПДн; ограничить внешнее распространение.",
    ],
    None: [
        "ПДн не обнаружены по текущим правилам. Оставить пометку о проверке.",
        "Если файл бизнес-критичный - повторить сканирование после расширения правил.",
    ],
}


# ===========================================================================
# Данные отчёта
# ===========================================================================
@dataclass
class ReportSummary:
    scanned_at: str
    root: str
    total_files: int
    status_counts: Dict[str, int]                # ok / skipped / error
    files_with_pii: int
    uz_distribution: Dict[str, int]              # ключи "1".."4" и "none"
    group_totals: Dict[str, int]                 # regular/state_ids/...
    category_totals: Dict[str, int]              # FIO/SNILS/...


@dataclass
class ReportRow:
    """Одна строка отчёта = один файл."""
    path: str
    filename: str
    format: str
    status: str
    via_ocr: bool
    uz_level: Optional[int]
    total_findings: int
    groups: Dict[str, int]                       # счётчики по группам
    categories: Dict[str, int]                   # счётчики по категориям
    recommendations: List[str]
    notes: List[str]
    classification: Optional[FileClassification] = field(default=None, repr=False)

    def to_plain_dict(self) -> dict:
        """Для JSON-отчёта: полные детали, но без сырых значений."""
        d = {
            "path": self.path,
            "filename": self.filename,
            "format": self.format,
            "status": self.status,
            "via_ocr": self.via_ocr,
            "uz_level": self.uz_level,
            "total_findings": self.total_findings,
            "groups": self.groups,
            "categories": self.categories,
            "recommendations": self.recommendations,
            "notes": self.notes,
        }
        if self.classification is not None:
            d["findings"] = {
                cat: [
                    {
                        "masked": f.masked,
                        "hash": f.hash,
                        "source": f.source,
                        "field": f.field_name,
                    }
                    for f in items
                ]
                for cat, items in self.classification.findings_by_category.items()
            }
        return d


@dataclass
class Report:
    summary: ReportSummary
    rows: List[ReportRow]


# ===========================================================================
# Сборка отчёта из результатов сканирования/классификации
# ===========================================================================
def build_report(
    extracted_results: Iterable,
    classifications_by_path: Dict[str, FileClassification],
    root: str,
) -> Report:
    """Сводит результаты экстракции и классификации в Report.

    extracted_results        - итератор FileProcessingResult (все файлы прогона);
    classifications_by_path  - FileClassification по path (только для status=ok);
    root                     - корень сканирования (для метаданных отчёта).
    """
    rows: List[ReportRow] = []
    status_counts: Dict[str, int] = {"ok": 0, "skipped": 0, "error": 0}
    uz_distribution: Dict[str, int] = {"1": 0, "2": 0, "3": 0, "4": 0, "none": 0}
    group_totals: Dict[str, int] = {}
    category_totals: Dict[str, int] = {}
    files_with_pii = 0

    for res in extracted_results:
        status_counts[res.status] = status_counts.get(res.status, 0) + 1
        cls = classifications_by_path.get(res.path)

        if cls is not None:
            uz_key = str(cls.uz_level) if cls.uz_level is not None else "none"
            uz_distribution[uz_key] = uz_distribution.get(uz_key, 0) + 1
            if cls.total_findings > 0:
                files_with_pii += 1
            for g, n in cls.findings_by_group.items():
                group_totals[g] = group_totals.get(g, 0) + n
            for cat, items in cls.findings_by_category.items():
                category_totals[cat] = category_totals.get(cat, 0) + len(items)

            row = ReportRow(
                path=cls.path,
                filename=cls.filename,
                format=cls.format,
                status=res.status,
                via_ocr=cls.via_ocr,
                uz_level=cls.uz_level,
                total_findings=cls.total_findings,
                groups=dict(cls.findings_by_group),
                categories={cat: len(items) for cat, items in cls.findings_by_category.items()},
                recommendations=UZ_RECOMMENDATIONS.get(cls.uz_level, []),
                notes=list(res.notes),
                classification=cls,
            )
        else:
            # файл не классифицирован (skipped/error/пусто). УЗ неизвестен.
            uz_distribution["none"] = uz_distribution.get("none", 0) + 1
            row = ReportRow(
                path=res.path,
                filename=Path(res.path).name,
                format=res.extension,
                status=res.status,
                via_ocr=res.via_ocr,
                uz_level=None,
                total_findings=0,
                groups={},
                categories={},
                recommendations=UZ_RECOMMENDATIONS[None],
                notes=list(res.notes) + ([res.error] if res.error else []),
            )
        rows.append(row)

    summary = ReportSummary(
        scanned_at=datetime.now().isoformat(timespec="seconds"),
        root=root,
        total_files=len(rows),
        status_counts=status_counts,
        files_with_pii=files_with_pii,
        uz_distribution=uz_distribution,
        group_totals=group_totals,
        category_totals=category_totals,
    )
    return Report(summary=summary, rows=rows)


# ===========================================================================
# Запись форматов
# ===========================================================================
def write_json(report: Report, path: Path) -> None:
    payload = {
        "summary": {
            "scanned_at": report.summary.scanned_at,
            "root": report.summary.root,
            "total_files": report.summary.total_files,
            "files_with_pii": report.summary.files_with_pii,
            "status_counts": report.summary.status_counts,
            "uz_distribution": report.summary.uz_distribution,
            "group_totals": report.summary.group_totals,
            "category_totals": report.summary.category_totals,
        },
        "files": [r.to_plain_dict() for r in report.rows],
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_csv(report: Report, path: Path) -> None:
    """Плоская таблица - одна строка на файл.

    Категории/группы схлопнуты в строки вида "FIO:1;EMAIL:2".
    Подробности находок (masked/hash/source) - только в JSON, в CSV не
    выгружаем, чтобы не получить мусорную ширину строк.
    """
    fieldnames = [
        "path", "filename", "format", "status", "via_ocr",
        "uz_level", "total_findings",
        "groups", "categories",
        "recommendations",
        "notes",
    ]
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        for r in report.rows:
            writer.writerow({
                "path": r.path,
                "filename": r.filename,
                "format": r.format,
                "status": r.status,
                "via_ocr": str(r.via_ocr).lower(),
                "uz_level": "" if r.uz_level is None else r.uz_level,
                "total_findings": r.total_findings,
                "groups": ";".join(f"{k}:{v}" for k, v in sorted(r.groups.items())),
                "categories": ";".join(f"{k}:{v}" for k, v in sorted(r.categories.items())),
                "recommendations": " | ".join(r.recommendations),
                "notes": " | ".join(r.notes),
            })


def write_markdown(report: Report, path: Path) -> None:
    s = report.summary
    lines: List[str] = []
    lines.append(f"# Отчёт по ПДн")
    lines.append("")
    lines.append(f"- Сканировано: `{s.root}`")
    lines.append(f"- Время: `{s.scanned_at}`")
    lines.append(f"- Всего файлов в отчёте: **{s.total_files}**")
    lines.append(f"- Файлов с ПДн: **{s.files_with_pii}**")
    lines.append("")
    lines.append("## Статусы обработки")
    for k in ("ok", "skipped", "error"):
        if k in s.status_counts:
            lines.append(f"- {k}: {s.status_counts[k]}")
    lines.append("")
    lines.append("## Распределение по УЗ")
    lines.append("| УЗ | Файлов |")
    lines.append("|---|---|")
    for key in ("1", "2", "3", "4", "none"):
        label = key if key != "none" else "нет ПДн / не классифицирован"
        lines.append(f"| {label} | {s.uz_distribution.get(key, 0)} |")
    lines.append("")
    if s.group_totals:
        lines.append("## Находки по группам (всего по датасету)")
        lines.append("| Группа | Количество |")
        lines.append("|---|---|")
        for g, n in sorted(s.group_totals.items(), key=lambda x: -x[1]):
            lines.append(f"| {g} | {n} |")
        lines.append("")
    if s.category_totals:
        lines.append("## Находки по категориям (всего по датасету)")
        lines.append("| Категория | Группа | Количество |")
        lines.append("|---|---|---|")
        for cat, n in sorted(s.category_totals.items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {CATEGORY_TO_GROUP.get(cat, '')} | {n} |")
        lines.append("")
    lines.append("## Файлы")
    lines.append("| Файл | Формат | УЗ | Находок | Категории | Статус |")
    lines.append("|---|---|---|---|---|---|")
    # Сортировка: сначала с более высоким УЗ (меньшее число = выше), потом по количеству находок
    def sort_key(row: ReportRow):
        uz = row.uz_level if row.uz_level is not None else 99
        return (uz, -row.total_findings, row.filename.lower())
    for r in sorted(report.rows, key=sort_key):
        cats = ", ".join(f"{k}({v})" for k, v in sorted(r.categories.items()))
        uz = str(r.uz_level) if r.uz_level is not None else "—"
        # экранируем вертикальные палки в именах, чтобы не ломать таблицу
        fname = r.filename.replace("|", "\\|")
        lines.append(f"| `{fname}` | {r.format} | {uz} | {r.total_findings} | {cats} | {r.status} |")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_all(report: Report, output_dir: Path, stem: str = "pii_report") -> Dict[str, Path]:
    """Пишет все три формата рядом. Возвращает dict{'json':..., 'csv':..., 'md':...}."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{stem}.json"
    csv_path = output_dir / f"{stem}.csv"
    md_path = output_dir / f"{stem}.md"
    write_json(report, json_path)
    write_csv(report, csv_path)
    write_markdown(report, md_path)
    return {"json": json_path, "csv": csv_path, "md": md_path}
