from __future__ import annotations

import re
import zlib
from pathlib import Path

from models import ExtractedContent


def safe_import(module_name: str):
    try:
        return __import__(module_name)
    except Exception:
        return None


def detect_file_encoding(path: Path) -> str:
    raw = path.read_bytes()[:4096]
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if raw.startswith(b"\xff\xfe"):
        return "utf-16le"
    if raw.startswith(b"\xfe\xff"):
        return "utf-16be"
    if _looks_like_utf16(raw):
        return "utf-16le"
    for encoding in ("utf-8", "cp1251", "latin-1"):
        try:
            raw.decode(encoding)
            return encoding
        except Exception:
            continue
    return "utf-8"


def decode_bytes(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", errors="replace")
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16le", errors="replace")
    if raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16be", errors="replace")
    if _looks_like_utf16(raw):
        return raw.decode("utf-16le", errors="replace")
    for encoding in ("utf-8", "cp1251", "latin-1"):
        try:
            return raw.decode(encoding)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def _looks_like_utf16(raw: bytes) -> bool:
    if len(raw) < 4:
        return False
    even_zeroes = sum(1 for index in range(0, len(raw), 2) if raw[index] == 0)
    odd_zeroes = sum(1 for index in range(1, len(raw), 2) if raw[index] == 0)
    even_ratio = even_zeroes / max(1, len(raw[::2]))
    odd_ratio = odd_zeroes / max(1, len(raw[1::2]))
    return even_ratio > 0.3 or odd_ratio > 0.3


def finalize_text(text: str, method: str, limit: int) -> ExtractedContent:
    normalized = re.sub(r"[ \t]+", " ", text or "")
    normalized = re.sub(r"\n{3,}", "\n\n", normalized).strip()
    truncated = len(normalized) > limit
    if truncated:
        normalized = normalized[:limit]
    return ExtractedContent(text=normalized, method=method, truncated=truncated)


def extract_strings_from_bytes(raw: bytes, min_length: int = 4) -> str:
    ascii_hits = [match.decode("latin-1", errors="ignore") for match in re.findall(rb"[\x20-\x7E]{%d,}" % min_length, raw)]
    utf16_hits = []
    for match in re.findall(rb"(?:[\x20-\x7E]\x00){%d,}" % min_length, raw):
        try:
            utf16_hits.append(match.decode("utf-16le", errors="ignore"))
        except Exception:
            continue
    return "\n".join(ascii_hits + utf16_hits)


def iter_pdf_streams(raw: bytes):
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, flags=re.S):
        payload = match.group(1)
        if payload:
            yield payload


def decode_pdf_literal(value: str) -> str:
    core = value.strip()
    if core.endswith("Tj"):
        core = core[:-2].strip()
    if core.startswith("(") and core.endswith(")"):
        core = core[1:-1]
    core = core.replace(r"\(", "(").replace(r"\)", ")").replace(r"\n", "\n")
    return re.sub(r"\\\d{3}", " ", core)


def extract_pdf_text_operators(raw: bytes) -> list[str]:
    decoded = raw.decode("latin-1", errors="ignore")
    fragments: list[str] = []
    for match in re.finditer(r"\((?:\\.|[^()])*\)\s*Tj", decoded):
        fragments.append(decode_pdf_literal(match.group(0)))
    for match in re.finditer(r"\[(.*?)\]\s*TJ", decoded, flags=re.S):
        inner = re.findall(r"\((?:\\.|[^()])*\)", match.group(1))
        fragments.extend(decode_pdf_literal(item) for item in inner)
    return fragments


def extract_pdf_strings(raw: bytes) -> str:
    parts: list[str] = []
    parts.extend(extract_pdf_text_operators(raw))
    for stream in iter_pdf_streams(raw):
        try:
            decoded = zlib.decompress(stream)
        except Exception:
            continue
        parts.extend(extract_pdf_text_operators(decoded))
        parts.append(extract_strings_from_bytes(decoded))
    parts.append(extract_strings_from_bytes(raw))
    return "\n".join(part for part in parts if part.strip())


def repair_mojibake(text: str) -> str:
    if not text:
        return text
    markers = text.count("Ð") + text.count("Ñ")
    if markers < 3:
        return text
    try:
        repaired = text.encode("latin-1", errors="ignore").decode("utf-8", errors="ignore")
    except Exception:
        return text
    original_cyr = len(re.findall(r"[А-Яа-яЁё]", text))
    repaired_cyr = len(re.findall(r"[А-Яа-яЁё]", repaired))
    return repaired if repaired_cyr > original_cyr else text
