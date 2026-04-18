from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


DEFAULT_EXTENSIONS = {
    "csv",
    "doc",
    "docx",
    "gif",
    "html",
    "htm",
    "jpeg",
    "jpg",
    "json",
    "pdf",
    "png",
    "rtf",
    "tif",
    "tiff",
    "txt",
    "xls",
    "xlsx",
}


@dataclass(slots=True)
class ScanConfig:
    root: Path
    output: Path
    output_format: str = "csv"
    include_extensions: set[str] = field(default_factory=lambda: set(DEFAULT_EXTENSIONS))
    max_text_chars: int = 200_000
    max_structured_rows: int = 20_000
    max_binary_read_bytes: int = 5_000_000
    enable_ocr: bool = False
    include_empty_results: bool = False
    analysis_workers: int = 3


@dataclass(slots=True)
class ExtractedContent:
    text: str
    method: str
    warnings: List[str] = field(default_factory=list)
    truncated: bool = False


@dataclass(slots=True)
class ScanResult:
    path: str
    name: str
    size: int
    time: str
    file_format: str
    categories: Dict[str, int]
    uz: str
    findings_count: int
    extractor: str
    recommendations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def detected_categories(self) -> List[str]:
        return [name for name, count in self.categories.items() if count > 0]
