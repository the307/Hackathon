from __future__ import annotations

import argparse
from pathlib import Path

from models import DEFAULT_EXTENSIONS, ScanConfig
from reporting import write_report
from scanner import scan_root


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CLI-сканер для поиска персональных данных в файловом хранилище."
    )
    parser.add_argument("root", help="Корневая директория или одиночный файл для анализа.")
    parser.add_argument(
        "-o",
        "--output",
        default="result.csv",
        help="Путь к итоговому отчету. Для хакатона CSV должен иметь вид size,time,name.",
    )
    parser.add_argument(
        "--output-format",
        choices=("csv", "json", "md"),
        default="csv",
        help="Формат отчета.",
    )
    parser.add_argument(
        "--include-ext",
        nargs="*",
        default=sorted(DEFAULT_EXTENSIONS),
        help="Список расширений для анализа без точки.",
    )
    parser.add_argument(
        "--max-text-chars",
        type=int,
        default=200_000,
        help="Лимит символов на один файл после извлечения.",
    )
    parser.add_argument(
        "--max-structured-rows",
        type=int,
        default=20_000,
        help="Лимит строк/элементов для CSV и JSON.",
    )
    parser.add_argument(
        "--max-binary-read-bytes",
        type=int,
        default=5_000_000,
        help="Сколько байт читать в binary fallback для тяжелых файлов.",
    )
    parser.add_argument(
        "--enable-ocr",
        action="store_true",
        help="Попытаться использовать OCR для изображений, если pillow и pytesseract доступны.",
    )
    parser.add_argument(
        "--include-empty-results",
        action="store_true",
        help="Включать в отчет файлы без найденных признаков ПДн.",
    )
    parser.add_argument(
        "--analysis-workers",
        type=int,
        default=3,
        help="Количество параллельных веток анализа текста одного документа.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    config = ScanConfig(
        root=Path(args.root).expanduser().resolve(),
        output=Path(args.output).expanduser().resolve(),
        output_format=args.output_format,
        include_extensions={extension.lower().lstrip(".") for extension in args.include_ext},
        max_text_chars=args.max_text_chars,
        max_structured_rows=args.max_structured_rows,
        max_binary_read_bytes=args.max_binary_read_bytes,
        enable_ocr=args.enable_ocr,
        include_empty_results=args.include_empty_results,
        analysis_workers=args.analysis_workers,
    )

    if not config.root.exists():
        parser.error(f"Путь не найден: {config.root}")

    results = scan_root(config)
    config.output.parent.mkdir(parents=True, exist_ok=True)
    write_report(results, config.output, config.output_format)

    print(f"Сканирование завершено. Результатов: {len(results)}")
    print(f"Отчет сохранен: {config.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
