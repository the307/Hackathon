"""
Детектор персональных данных (ПДн) по 152-ФЗ.

Переработка первоначального наброска под единый контракт проекта
(FileProcessingResult + TextChunk) и под ровно те категории, которые
требует ТЗ хакатона.

Вход:  FileProcessingResult (из main.process_file / document_handlers / image_processor).
Выход: FileClassification - путь, имя файла, формат, находки по категориям
       152-ФЗ, счётчики по группам, уровень защищённости (УЗ 1..4).

Конвейер для одного файла:
  для каждого TextChunk:
    1) structured regex + валидаторы (СНИЛС/ИНН/Луна) - детерминированно;
    2) Natasha NER (только для неструктурированных чанков без field_name) - ФИО/LOC;
    3) словарные детекторы (биометрия, здоровье, религия, раса/нацпринадлежность);
    4) context-gate для CVV/паспорт/ИНН, чтобы не ловить случайные числа.
  дедупликация по (category, sha256(value)).
  УЗ считается по собранным группам категорий.

Этика (требование ТЗ):
  - В выходе НЕТ сырых значений ПДн. Используется маскирование + SHA-256 (первые 16 hex).

Источники/алгоритмы:
  - 152-ФЗ "О персональных данных".
  - ПП РФ N 1119 (УЗ-1..УЗ-4).
  - Алгоритм Луна (ISO/IEC 7812-1).
  - Контрольная сумма СНИЛС - Постановление Правления ПФР.
  - Контрольные цифры ИНН - приказ ФНС от 29.06.2012 N ММВ-7-6/435@.
  - Natasha: https://github.com/natasha/natasha
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from document_handlers import TextChunk


# ===========================================================================
# 1. КАТЕГОРИИ И ГРУППЫ 152-ФЗ
# ===========================================================================

GROUP_REGULAR = "regular"
GROUP_STATE_IDS = "state_ids"
GROUP_PAYMENT = "payment"
GROUP_BIOMETRIC = "biometric"
GROUP_SPECIAL = "special"

# Категория -> группа (см. ТЗ и 152-ФЗ).
CATEGORY_TO_GROUP: Dict[str, str] = {
    # regular
    "FIO": GROUP_REGULAR,
    "PHONE": GROUP_REGULAR,
    "EMAIL": GROUP_REGULAR,
    "BIRTH_DATE": GROUP_REGULAR,
    "BIRTH_PLACE": GROUP_REGULAR,
    "ADDRESS": GROUP_REGULAR,
    # state identifiers
    "PASSPORT_RF": GROUP_STATE_IDS,
    "SNILS": GROUP_STATE_IDS,
    "INN_PERSONAL": GROUP_STATE_IDS,
    "INN_LEGAL": GROUP_STATE_IDS,
    "DRIVER_LICENSE": GROUP_STATE_IDS,
    "MRZ": GROUP_STATE_IDS,
    # payment
    "BANK_CARD": GROUP_PAYMENT,
    "BANK_ACCOUNT": GROUP_PAYMENT,
    "BIC": GROUP_PAYMENT,
    "CVV": GROUP_PAYMENT,
    # biometric
    "BIOMETRIC_MENTION": GROUP_BIOMETRIC,
    # special (152-ФЗ ст. 10)
    "HEALTH": GROUP_SPECIAL,
    "RELIGION_POLITICS": GROUP_SPECIAL,
    "RACE_NATIONALITY": GROUP_SPECIAL,
}


# ===========================================================================
# 2. ВАЛИДАТОРЫ (детерминированные, снижают ложные срабатывания)
# ===========================================================================

def luhn_valid(digits: str) -> bool:
    """Алгоритм Луна (ISO/IEC 7812-1) для банковских карт (13..19 цифр)."""
    digits = re.sub(r"\D", "", digits)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def snils_valid(value: str) -> bool:
    """Контрольная сумма СНИЛС (11 цифр; алгоритм ПФР)."""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11:
        return False
    nums = [int(c) for c in digits]
    s = sum(nums[i] * (9 - i) for i in range(9))
    control_expected = nums[9] * 10 + nums[10]
    if s < 100:
        control = s
    elif s in (100, 101):
        control = 0
    else:
        control = s % 101
        if control in (100, 101):
            control = 0
    return control == control_expected


def inn_valid(value: str) -> bool:
    """ИНН 10 или 12 цифр (ФНС)."""
    digits = re.sub(r"\D", "", value)
    if len(digits) == 10:
        coeffs = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum = sum(int(digits[i]) * coeffs[i] for i in range(9)) % 11 % 10
        return checksum == int(digits[9])
    if len(digits) == 12:
        coeffs1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        coeffs2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        c1 = sum(int(digits[i]) * coeffs1[i] for i in range(10)) % 11 % 10
        c2 = sum(int(digits[i]) * coeffs2[i] for i in range(11)) % 11 % 10
        return c1 == int(digits[10]) and c2 == int(digits[11])
    return False


def bic_valid(value: str) -> bool:
    """БИК РФ: 9 цифр, первые 2 = '04' (код РФ) согласно Банку России."""
    digits = re.sub(r"\D", "", value)
    return len(digits) == 9 and digits.startswith("04")


# ===========================================================================
# 3. REGEX-ПАТТЕРНЫ
# ===========================================================================

PATTERNS = {
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    # Телефон РФ: начинается с +7 или 8. Это жёстче, чем у команды,
    # и сильно снижает ложные срабатывания на случайных 7-значных числах.
    "PHONE_RU": re.compile(
        r"(?:(?<!\d)(?:\+7|8))[\s\-\(\)]*\d{3}[\s\-\(\)]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}(?!\d)"
    ),
    "PASSPORT_RF": re.compile(r"(?<!\d)\d{4}\s?\d{6}(?!\d)"),
    "SNILS": re.compile(r"(?<!\d)\d{3}-\d{3}-\d{3}[\s\-]?\d{2}(?!\d)"),
    # ИНН проверяется валидатором, но регекс нужен для выделения кандидатов.
    "INN_CAND": re.compile(r"(?<!\d)\d{10}(?:\d{2})?(?!\d)"),
    "BANK_CARD_CAND": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
    "BANK_ACCOUNT_CAND": re.compile(r"(?<!\d)\d{20}(?!\d)"),
    "BIC_CAND": re.compile(r"(?<!\d)04\d{7}(?!\d)"),
    "DRIVER_LICENSE": re.compile(r"(?<!\d)\d{2}\s?[АВЕКМНОРСТУХAВEKMHOPCTYX]{2}\s?\d{6}(?!\d)"),
    # MRZ TD3 (паспорт): две строки по 44 символа, начинается с P<XXX
    "MRZ": re.compile(r"P[<A-Z0-9]{43}\s*[A-Z0-9<]{44}"),
    # Дата в формате dd.mm.yyyy или dd/mm/yyyy
    "DATE": re.compile(r"(?<!\d)(?:0?[1-9]|[12]\d|3[01])[\./](?:0?[1-9]|1[0-2])[\./](?:19|20)\d{2}(?!\d)"),
}


# ===========================================================================
# 4. СЛОВАРНЫЕ ДЕТЕКТОРЫ (биометрия, спец. категории, контекст)
# ===========================================================================

KEYWORDS_BIOMETRIC = [
    "отпечат", "дактилоск", "радужн",
    "голосов образц", "голосовой образц",
    "биометр", "геном",
    "лицев биометр", "лицевая биометр",
]

KEYWORDS_HEALTH = [
    "диагноз", "группа крови", "группу крови",
    "вич", "спид", "беременн", "инвалид", "инвалидност",
    "хронич забол", "медицинск заключ", "справк о состоян здоров",
    "псих расстрой", "онколог",
]

KEYWORDS_RELIGION_POLITICS = [
    "православн", "мусульман", "католик", "буддист", "атеист",
    "иудей", "религиозн убежд", "религиозные убежд",
    "политическ убежд", "член парти", "партийн принадлеж",
]

KEYWORDS_RACE_NATIONALITY = [
    "национальност", "расов принадлеж",
    "этническ происхожд", "этнич",
]

# Контекстные ключи для field_name и окна вокруг числа.
FIELD_HINTS_PASSPORT = ["паспорт", "серия", "series", "passport"]
FIELD_HINTS_SNILS = ["снилс", "snils"]
FIELD_HINTS_INN = ["инн", "inn"]
FIELD_HINTS_CARD = ["карт", "card", "pan"]
FIELD_HINTS_ACCOUNT = ["счет", "счёт", "account", "р/с", "расчетный"]
FIELD_HINTS_BIC = ["бик", "bic"]
FIELD_HINTS_CVV = ["cvv", "cvc", "код безопасн"]
FIELD_HINTS_DL = ["водит", "удостовер", "license"]
FIELD_HINTS_BIRTH_DATE = ["дата рожд", "birth", "дата_рожд", "birthday"]
FIELD_HINTS_BIRTH_PLACE = ["место рожд", "place of birth", "birthplace"]
FIELD_HINTS_ADDRESS = ["адрес", "address", "прож", "регистр"]
FIELD_HINTS_FIO = ["фио", "имя", "фамил", "отчеств", "name", "full name"]

CONTEXT_KEYWORDS_PASSPORT = ["паспорт"]
CONTEXT_KEYWORDS_INN = ["инн"]
CONTEXT_KEYWORDS_CVV = ["cvv", "cvc", "код безопасн"]
# "рожд" покрывает "рождения/рождён", "родил" - "родился/родилась".
CONTEXT_KEYWORDS_BIRTH_DATE = ["рожд", "родил", "born"]


# ===========================================================================
# 5. МАСКИРОВАНИЕ И ХЕШ (ТЗ: не сохранять полные значения)
# ===========================================================================

def sha256_tag(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _mask_tail(s: str, visible: int = 4, ch: str = "*") -> str:
    if len(s) <= visible:
        return ch * len(s)
    return ch * (len(s) - visible) + s[-visible:]


def _mask_digits_tail(value: str, visible: int = 4) -> str:
    digits = re.sub(r"\D", "", value)
    return _mask_tail(digits, visible)


def mask_value(category: str, value: str) -> str:
    v = value.strip()
    if category == "EMAIL":
        if "@" in v:
            local, _, domain = v.partition("@")
            return (local[:1] + "***@" + domain) if local else "***@" + domain
        return "***"
    if category == "PHONE":
        return _mask_digits_tail(v, visible=2)
    if category in ("PASSPORT_RF", "SNILS", "INN_PERSONAL", "INN_LEGAL",
                    "BANK_CARD", "BANK_ACCOUNT", "BIC", "CVV",
                    "DRIVER_LICENSE"):
        return _mask_digits_tail(v, visible=4 if category != "CVV" else 0)
    if category == "MRZ":
        return v[:5] + "..." + v[-2:] if len(v) > 10 else "***"
    if category == "FIO":
        parts = [p for p in re.split(r"\s+", v) if p]
        masked = []
        for p in parts:
            masked.append(p[:1] + "." if p else "")
        return " ".join(masked) or "***"
    if category == "ADDRESS":
        return (v[:6] + "...") if len(v) > 6 else "***"
    # даты/места/словарные метки - оставляем только грубую маску
    if category == "BIRTH_DATE":
        # dd.mm.yyyy -> **.**.yyyy
        m = re.match(r"(\d{1,2})[\./](\d{1,2})[\./]((?:19|20)\d{2})", v)
        return ("**.**." + m.group(3)) if m else "**.**.****"
    if category == "BIRTH_PLACE":
        return (v[:6] + "...") if len(v) > 6 else "***"
    # биометрия / спец. категории - просто метка категории
    return "[" + category + "]"


# ===========================================================================
# 6. ДATACLASS: НАХОДКА И КЛАССИФИКАЦИЯ ФАЙЛА
# ===========================================================================

@dataclass(frozen=True)
class Finding:
    category: str           # "SNILS", "FIO", ...
    group: str              # "state_ids", "regular", ...
    masked: str             # безопасное для вывода представление
    hash: str               # sha256 (первые 16 hex) нормализованного значения
    source: str             # TextChunk.source
    field_name: Optional[str] = None


@dataclass
class FileClassification:
    path: str
    filename: str
    format: str                                      # расширение (без точки)
    via_ocr: bool
    total_findings: int
    findings_by_category: Dict[str, List[Finding]] = field(default_factory=dict)
    findings_by_group: Dict[str, int] = field(default_factory=dict)
    uz_level: Optional[int] = None                   # 1..4 или None если ПДн не нашли

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "filename": self.filename,
            "format": self.format,
            "via_ocr": self.via_ocr,
            "uz_level": self.uz_level,
            "total_findings": self.total_findings,
            "groups": self.findings_by_group,
            "categories": {
                cat: [
                    {
                        "masked": f.masked,
                        "hash": f.hash,
                        "source": f.source,
                        "field": f.field_name,
                    }
                    for f in items
                ]
                for cat, items in self.findings_by_category.items()
            },
        }


# ===========================================================================
# 7. ОСНОВНОЙ ДЕТЕКТОР
# ===========================================================================

# Порог "больших объёмов" для решения про УЗ. В 152-ФЗ и ПП 1119 численный
# порог не зафиксирован - это эвристика, документированная и настраиваемая.
BIG_VOLUME_THRESHOLD = 100


class PIIDetector:
    def __init__(
        self,
        big_volume_threshold: int = BIG_VOLUME_THRESHOLD,
        strict_natasha: bool = False,
    ):
        """Параметры:
          big_volume_threshold - порог "больших объёмов" для УЗ (heuristic).
          strict_natasha       - если True, падаем при ошибке загрузки Natasha;
                                 если False - работаем без NER (FIO будет
                                 ловиться только по field_name), и причина
                                 сбоя доступна через natasha_error.
        """
        self.big_volume_threshold = big_volume_threshold
        self.strict_natasha = strict_natasha
        self._natasha = None          # ленивая инициализация (тяжёлая)
        self.natasha_error: Optional[str] = None

    # ------------------------- Natasha (lazy) -------------------------------
    def _get_natasha(self):
        if self._natasha is not None:
            return self._natasha
        try:
            from natasha import (
                Segmenter, MorphVocab, NewsEmbedding,
                NewsMorphTagger, NewsNERTagger, Doc,
            )
        except ImportError as e:
            self.natasha_error = f"natasha import failed: {e}"
            if self.strict_natasha:
                raise
            self._natasha = False
            return False
        try:
            emb = NewsEmbedding()
            self._natasha = {
                "Doc": Doc,
                "segmenter": Segmenter(),
                "morph_vocab": MorphVocab(),
                "morph_tagger": NewsMorphTagger(emb),
                "ner_tagger": NewsNERTagger(emb),
            }
            return self._natasha
        except Exception as e:
            # Частые причины: отсутствует setuptools (pkg_resources) для
            # pymorphy2, либо не скачались модели NewsEmbedding.
            self.natasha_error = f"{type(e).__name__}: {e}"
            if self.strict_natasha:
                raise
            self._natasha = False
            return False

    def natasha_available(self) -> bool:
        return bool(self._get_natasha())

    # ------------------------- helpers --------------------------------------
    @staticmethod
    def _field_has(field_name: Optional[str], hints: List[str]) -> bool:
        if not field_name:
            return False
        fn = field_name.lower()
        return any(h in fn for h in hints)

    @staticmethod
    def _text_has_keyword(text: str, keywords: List[str]) -> bool:
        low = text.lower()
        return any(k in low for k in keywords)

    @staticmethod
    def _window_around(text: str, start: int, end: int, pad: int = 40) -> str:
        return text[max(0, start - pad): min(len(text), end + pad)].lower()

    def _add_finding(
        self,
        bucket: Dict[Tuple[str, str], Finding],
        category: str,
        raw_value: str,
        chunk: TextChunk,
    ) -> None:
        norm = raw_value.strip()
        if not norm:
            return
        h = sha256_tag(norm)
        key = (category, h)
        if key in bucket:
            return
        bucket[key] = Finding(
            category=category,
            group=CATEGORY_TO_GROUP[category],
            masked=mask_value(category, norm),
            hash=h,
            source=chunk.source,
            field_name=chunk.field_name,
        )

    # ------------------------- per-chunk detection --------------------------
    def _detect_in_chunk(
        self,
        chunk: TextChunk,
        bucket: Dict[Tuple[str, str], Finding],
    ) -> None:
        text = chunk.text
        if not text:
            return
        fn = chunk.field_name

        # --- EMAIL ---
        for m in PATTERNS["EMAIL"].finditer(text):
            self._add_finding(bucket, "EMAIL", m.group(0), chunk)

        # --- PHONE_RU ---
        for m in PATTERNS["PHONE_RU"].finditer(text):
            self._add_finding(bucket, "PHONE", m.group(0), chunk)

        # --- PASSPORT_RF: нужен контекст (field_name или ключ рядом) ---
        for m in PATTERNS["PASSPORT_RF"].finditer(text):
            val = m.group(0)
            ctx_ok = (
                self._field_has(fn, FIELD_HINTS_PASSPORT)
                or self._text_has_keyword(
                    self._window_around(text, m.start(), m.end()),
                    CONTEXT_KEYWORDS_PASSPORT,
                )
            )
            if ctx_ok:
                self._add_finding(bucket, "PASSPORT_RF", val, chunk)

        # --- SNILS: только валидные по контрольной сумме ---
        for m in PATTERNS["SNILS"].finditer(text):
            val = m.group(0)
            if snils_valid(val):
                self._add_finding(bucket, "SNILS", val, chunk)

        # --- ИНН: валидные + контекст (field_name или ключ) ---
        for m in PATTERNS["INN_CAND"].finditer(text):
            val = m.group(0)
            if not inn_valid(val):
                continue
            ctx_ok = (
                self._field_has(fn, FIELD_HINTS_INN)
                or self._text_has_keyword(
                    self._window_around(text, m.start(), m.end()),
                    CONTEXT_KEYWORDS_INN,
                )
            )
            if not ctx_ok:
                continue
            cat = "INN_PERSONAL" if len(re.sub(r"\D", "", val)) == 12 else "INN_LEGAL"
            self._add_finding(bucket, cat, val, chunk)

        # --- BANK_CARD: Luhn ---
        for m in PATTERNS["BANK_CARD_CAND"].finditer(text):
            val = m.group(0)
            if luhn_valid(val):
                self._add_finding(bucket, "BANK_CARD", val, chunk)

        # --- BANK_ACCOUNT: 20 цифр, контекст ---
        for m in PATTERNS["BANK_ACCOUNT_CAND"].finditer(text):
            val = m.group(0)
            if self._field_has(fn, FIELD_HINTS_ACCOUNT):
                self._add_finding(bucket, "BANK_ACCOUNT", val, chunk)

        # --- BIC ---
        for m in PATTERNS["BIC_CAND"].finditer(text):
            val = m.group(0)
            if bic_valid(val):
                self._add_finding(bucket, "BIC", val, chunk)

        # --- CVV: крайне короткий код, срабатываем только по полю/ключу ---
        if self._field_has(fn, FIELD_HINTS_CVV):
            # в поле со значением CVV вся ячейка - потенциальный CVV, если 3-4 цифры
            digits = re.sub(r"\D", "", text)
            if 3 <= len(digits) <= 4:
                self._add_finding(bucket, "CVV", digits, chunk)
        else:
            if self._text_has_keyword(text, CONTEXT_KEYWORDS_CVV):
                for m in re.finditer(r"(?<!\d)\d{3,4}(?!\d)", text):
                    ctx = self._window_around(text, m.start(), m.end(), pad=15)
                    if self._text_has_keyword(ctx, CONTEXT_KEYWORDS_CVV):
                        self._add_finding(bucket, "CVV", m.group(0), chunk)

        # --- DRIVER_LICENSE ---
        for m in PATTERNS["DRIVER_LICENSE"].finditer(text):
            self._add_finding(bucket, "DRIVER_LICENSE", m.group(0), chunk)

        # --- MRZ ---
        for m in PATTERNS["MRZ"].finditer(text):
            self._add_finding(bucket, "MRZ", m.group(0), chunk)

        # --- BIRTH_DATE / BIRTH_PLACE ---
        # BIRTH_DATE: дата + контекст "родился/birth" ИЛИ field_name
        if self._field_has(fn, FIELD_HINTS_BIRTH_DATE):
            for m in PATTERNS["DATE"].finditer(text):
                self._add_finding(bucket, "BIRTH_DATE", m.group(0), chunk)
        elif self._text_has_keyword(text, CONTEXT_KEYWORDS_BIRTH_DATE):
            for m in PATTERNS["DATE"].finditer(text):
                ctx = self._window_around(text, m.start(), m.end())
                if self._text_has_keyword(ctx, CONTEXT_KEYWORDS_BIRTH_DATE):
                    self._add_finding(bucket, "BIRTH_DATE", m.group(0), chunk)

        if self._field_has(fn, FIELD_HINTS_BIRTH_PLACE):
            self._add_finding(bucket, "BIRTH_PLACE", text, chunk)

        # --- ADDRESS: только по field_name, чтобы не ловить любую локацию ---
        if self._field_has(fn, FIELD_HINTS_ADDRESS):
            self._add_finding(bucket, "ADDRESS", text, chunk)

        # --- FIO: если field_name однозначно "фамилия/имя/фио" ---
        if self._field_has(fn, FIELD_HINTS_FIO):
            self._add_finding(bucket, "FIO", text, chunk)

        # --- Словарные: биометрия и спец. категории ---
        if self._text_has_keyword(text, KEYWORDS_BIOMETRIC):
            self._add_finding(bucket, "BIOMETRIC_MENTION", text[:120], chunk)
        if self._text_has_keyword(text, KEYWORDS_HEALTH):
            self._add_finding(bucket, "HEALTH", text[:120], chunk)
        if self._text_has_keyword(text, KEYWORDS_RELIGION_POLITICS):
            self._add_finding(bucket, "RELIGION_POLITICS", text[:120], chunk)
        if self._text_has_keyword(text, KEYWORDS_RACE_NATIONALITY):
            self._add_finding(bucket, "RACE_NATIONALITY", text[:120], chunk)

    # ------------------------- Natasha NER pass -----------------------------
    def _detect_fio_with_natasha(
        self,
        chunks: List[TextChunk],
        bucket: Dict[Tuple[str, str], Finding],
    ) -> None:
        nat = self._get_natasha()
        if not nat:
            return

        # Конкатенируем чанки БЕЗ field_name (неструктурированные) в большой текст
        # с разделителем, и сохраняем соответствие position->chunk.
        # Это гораздо быстрее, чем гонять Natasha на каждом маленьком чанке.
        pieces: List[Tuple[int, int, TextChunk]] = []
        buf: List[str] = []
        pos = 0
        sep = "\n\n"
        for ch in chunks:
            if ch.field_name:
                continue
            if not ch.text or not ch.text.strip():
                continue
            start = pos
            buf.append(ch.text)
            pos += len(ch.text)
            pieces.append((start, pos, ch))
            buf.append(sep)
            pos += len(sep)

        if not pieces:
            return
        combined = "".join(buf)
        if len(combined) > 500_000:
            combined = combined[:500_000]  # защитный лимит

        Doc = nat["Doc"]
        doc = Doc(combined)
        doc.segment(nat["segmenter"])
        doc.tag_morph(nat["morph_tagger"])
        doc.tag_ner(nat["ner_tagger"])

        def chunk_for(pos: int) -> Optional[TextChunk]:
            for s, e, ch in pieces:
                if s <= pos < e:
                    return ch
            return None

        for span in doc.spans:
            if span.type != "PER":
                continue
            try:
                span.normalize(nat["morph_vocab"])
            except Exception:
                pass
            value = (span.normal or span.text or "").strip()
            if not value or len(value) < 3:
                continue
            ch = chunk_for(span.start)
            if ch is None:
                continue
            self._add_finding(bucket, "FIO", value, ch)

    # ------------------------- УЗ (уровень защищённости) --------------------
    def _compute_uz(self, group_counts: Dict[str, int]) -> Optional[int]:
        total = sum(group_counts.values())
        if total == 0:
            return None
        if group_counts.get(GROUP_SPECIAL, 0) > 0 or group_counts.get(GROUP_BIOMETRIC, 0) > 0:
            return 1
        if group_counts.get(GROUP_PAYMENT, 0) > 0:
            return 2
        if group_counts.get(GROUP_STATE_IDS, 0) >= self.big_volume_threshold:
            return 2
        if group_counts.get(GROUP_STATE_IDS, 0) > 0:
            return 3
        if group_counts.get(GROUP_REGULAR, 0) >= self.big_volume_threshold:
            return 3
        return 4

    # ------------------------- public API -----------------------------------
    def detect(self, file_result) -> FileClassification:
        """Классификация одного файла (принимает FileProcessingResult)."""
        chunks: List[TextChunk] = list(getattr(file_result, "chunks", []) or [])
        bucket: Dict[Tuple[str, str], Finding] = {}

        for ch in chunks:
            self._detect_in_chunk(ch, bucket)

        # Natasha пускаем только если есть неструктурированные чанки
        if any(not ch.field_name and (ch.text or "").strip() for ch in chunks):
            self._detect_fio_with_natasha(chunks, bucket)

        findings_by_category: Dict[str, List[Finding]] = defaultdict(list)
        group_counts: Dict[str, int] = defaultdict(int)
        for f in bucket.values():
            findings_by_category[f.category].append(f)
            group_counts[f.group] += 1

        path = str(getattr(file_result, "path", ""))
        return FileClassification(
            path=path,
            filename=Path(path).name if path else "",
            format=str(getattr(file_result, "extension", "")),
            via_ocr=bool(getattr(file_result, "via_ocr", False)),
            total_findings=sum(group_counts.values()),
            findings_by_category=dict(findings_by_category),
            findings_by_group=dict(group_counts),
            uz_level=self._compute_uz(dict(group_counts)),
        )


# ===========================================================================
# 8. ВЫСОКОУРОВНЕВЫЙ API
# ===========================================================================

def classify_files(
    file_results: Iterable,
    detector: Optional[PIIDetector] = None,
) -> List[FileClassification]:
    """Пройтись по списку FileProcessingResult и получить список классификаций.

    Детектор создаётся один раз (Natasha грузится один раз на процесс).
    """
    det = detector or PIIDetector()
    out: List[FileClassification] = []
    for r in file_results:
        try:
            out.append(det.detect(r))
        except Exception as exc:
            # не валим весь прогон из-за одного файла
            path = str(getattr(r, "path", "")) or ""
            out.append(FileClassification(
                path=path,
                filename=Path(path).name if path else "",
                format=str(getattr(r, "extension", "")),
                via_ocr=bool(getattr(r, "via_ocr", False)),
                total_findings=0,
                findings_by_category={},
                findings_by_group={},
                uz_level=None,
            ))
            _ = exc  # в отчёт на следующем шаге можно логировать
    return out
