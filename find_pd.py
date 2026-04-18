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

# ВАЖНО: ключевые слова матчатся по word boundaries (re.search со \b), а не
# подстрокой. Иначе "вич" ловит "Иванович", "спид" ловит "спидометр",
# "этнич" ловит любую "техничную" ерунду, "инвалид" срабатывает на
# единичное упоминание в юридическом тексте. Проверено на полном прогоне
# (998 HEALTH findings в патентных документах ЮФУ - почти всё было ложным).
# \b в Python 3 корректно работает с Unicode/кириллицей.
KEYWORDS_BIOMETRIC = [
    r"отпечат(ок|ка|ков|ки)? пальц",
    r"дактилоскоп",
    r"радужн\w* оболоч",
    r"голосов\w+ образ",
    r"\bбиометри",
    r"\bгеном\w*\b",
    r"лицев\w+ биометри",
]

# HEALTH: требуем словосочетания, а не одиночные слова. "Инвалид" один -
# не повод ставить УЗ-1. "Диагноз X", "группа крови", "ВИЧ-инфек" - да.
KEYWORDS_HEALTH = [
    r"\bдиагноз\w*\b",
    r"групп[аыу]\s+крови",
    r"\bВИЧ[-\s]",
    r"\bСПИД\w*",
    r"беременн(ость|ая|ой|ости)",
    r"инвалидност",
    r"\bинвалид(ы|ов|ам|ами|ах)?\b",
    r"хронич\w+\s+заболев",
    r"медицинск\w+\s+заключ",
    r"справк\w+\s+о\s+состоян\w+\s+здоров",
    r"псих\w*\s+расстрой",
    r"онколог\w+",
]

KEYWORDS_RELIGION_POLITICS = [
    r"\bправославн\w+",
    r"\bмусульман\w+",
    r"\bкатолик\w*",
    r"\bбуддист\w*",
    r"\bиудей\w*",
    r"религиозн\w+\s+убежд",
    r"политическ\w+\s+убежд",
    r"член\s+парти",
    r"партийн\w+\s+принадлежност",
]

# Было "этнич" substring - ловило "техничный". Сузили до корней этно-/расов-
# в связке с национальностью/происхождением.
KEYWORDS_RACE_NATIONALITY = [
    r"национальност\w*",
    r"расов\w+\s+принадлежност",
    r"этническ\w+\s+(происхожден|принадлежност|состав)",
    r"\bэтнос\w*\b",
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
        # Маска вида "И.(6) П.(7) С.(9)": первая буква + длина основы в
        # скобках. Это нужно, чтобы отличать реальные токены ("Борис" = 5
        # букв) от одиночных инициалов ("Б." - 1 буква), иначе отчёт
        # визуально теряет разницу после маскировки.
        parts = [p for p in re.split(r"\s+", v) if p]
        masked = []
        for p in parts:
            core = p.rstrip(".")
            if not core:
                continue
            masked.append(f"{core[:1]}.({len(core)})")
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
        """Для контекстных подсказок (паспорт/ИНН/CVV/дата рождения) -
        быстрый подстрочный матч в уже lowercased окне."""
        low = text.lower()
        return any(k in low for k in keywords)

    @staticmethod
    def _text_matches_any_regex(text: str, patterns: List[str]) -> bool:
        """Для словарных категорий (HEALTH/BIOMETRIC/...) - матч с
        учётом word boundaries. re.IGNORECASE, т.к. тексты русскоязычные."""
        for p in patterns:
            if re.search(p, text, flags=re.IGNORECASE | re.UNICODE):
                return True
        return False

    # Форма "похоже на ФИО": 2-5 токенов, каждый - либо инициал (одна
    # заглавная буква с точкой или без), либо слово на кириллице/латинице
    # с ОДНОЙ заглавной первой буквой и дальше только строчными. Цифры
    # и внутренние заглавные (iPhone, S20) запрещены - это надёжно
    # отрезает товарные и технические названия, но допускает "Michael
    # Roman" / "Иванов Иван" и "Иван Петрович Сергеев-Кузнецов".
    # Нужен как value-gate к field_name: "product_name" подстрочно
    # содержит "name", но "Смартфон Samsung Galaxy S20" - не ФИО.
    _FIO_TOKEN_RE = re.compile(r"^([А-ЯЁA-Z]\.?|[А-ЯЁA-Z][а-яёa-z\-]+)$")

    @classmethod
    def _looks_like_fio(cls, value: str) -> bool:
        v = (value or "").strip()
        if not v or len(v) < 3 or len(v) > 120:
            return False
        tokens = [t for t in re.split(r"\s+", v) if t]
        if not (2 <= len(tokens) <= 5):
            return False
        meaningful = 0
        for t in tokens:
            if not cls._FIO_TOKEN_RE.match(t):
                return False
            if len(t.rstrip(".")) >= 2:
                meaningful += 1
        return meaningful >= 1

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

        # --- BANK_CARD: Luhn + контекст ---
        # Luhn на 13-19 цифрах сам по себе даёт ~10% ложных срабатываний
        # (IMEI, GTIN, ISBN-13, номера патентов). Требуем контекст:
        # field_name указывает на карту, ИЛИ рядом слова "карт/card/pan/
        # visa/masterc/mir" в окне 60 символов.
        for m in PATTERNS["BANK_CARD_CAND"].finditer(text):
            val = m.group(0)
            if not luhn_valid(val):
                continue
            ctx_ok = (
                self._field_has(fn, FIELD_HINTS_CARD)
                or self._text_has_keyword(
                    self._window_around(text, m.start(), m.end(), pad=60),
                    ["карт", "card", "pan", "visa", "masterc", "мир"],
                )
            )
            if not ctx_ok:
                continue
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

        # --- FIO: field_name + value-gate по форме русскоязычного ФИО ---
        # Без value-gate "product_name" матчится по подстроке "name" и
        # каждая строка продукта получает ложный FIO finding. Проверено
        # на products.csv (320 FP).
        if self._field_has(fn, FIELD_HINTS_FIO) and self._looks_like_fio(text):
            self._add_finding(bucket, "FIO", text, chunk)

        # --- Словарные: биометрия и спец. категории (word boundaries) ---
        if self._text_matches_any_regex(text, KEYWORDS_BIOMETRIC):
            self._add_finding(bucket, "BIOMETRIC_MENTION", text[:120], chunk)
        if self._text_matches_any_regex(text, KEYWORDS_HEALTH):
            self._add_finding(bucket, "HEALTH", text[:120], chunk)
        if self._text_matches_any_regex(text, KEYWORDS_RELIGION_POLITICS):
            self._add_finding(bucket, "RELIGION_POLITICS", text[:120], chunk)
        if self._text_matches_any_regex(text, KEYWORDS_RACE_NATIONALITY):
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
        # Защитный лимит: Natasha + morph tagger на больших PDF - основной
        # bottleneck прогона (full scan 2795 файлов: ~16 мин). Текст сверх
        # лимита отбрасывается - ФИО в "хвосте" больших документов могут
        # быть не найдены. Значение подобрано как компромисс между охватом
        # и производительностью. Можно настраивать через инжект в класс.
        if len(combined) > 300_000:
            combined = combined[:300_000]

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
            # Отсекаем одиночные инициалы и "мусорные" спаны без
            # полноценного слова (минимум 2 буквы). Проверено на полном
            # прогоне: Natasha массово выдавала "Н.", "П.", "И.И." как
            # самостоятельные спаны - это формально PER, но бесполезно.
            tokens = [t for t in re.split(r"\s+", value) if t]
            meaningful = [t for t in tokens if len(t.rstrip(".")) >= 2]
            if not meaningful:
                continue
            ch = chunk_for(span.start)
            if ch is None:
                continue
            self._add_finding(bucket, "FIO", value, ch)

    # ------------------------- УЗ (уровень защищённости) --------------------
    # По 152-ФЗ + ПП 1119 УЗ-1 применяется когда СПЕЦИАЛЬНЫЕ категории
    # ОБРАБАТЫВАЮТСЯ относительно конкретного субъекта, а не просто
    # упоминаются в тексте (например, в научной статье или патенте).
    #
    # Сигналы "обработки конкретного субъекта" (достаточно одного):
    #   Только строгий персональный идентификатор - СНИЛС, паспорт РФ,
    #   ИНН физлица, ВУ, MRZ, дата рождения. Ранее сюда также входил
    #   порог ФИО (>=5), но он даёт ложные УЗ-1 на шумных источниках:
    #   публичные блог-страницы с заголовками постов, где Natasha
    #   находит десятки "ФИО" среди псевдонимов/героев, а одно случайное
    #   упоминание "диагноз" или "национальность" вытягивает документ
    #   в высшую категорию защищённости. Без жёсткого идентификатора мы
    #   не можем утверждать, что идёт обработка конкретного субъекта,
    #   поэтому максимальный УЗ привязываем только к таким признакам.
    _PERSONAL_IDENTIFIER_CATEGORIES = {
        "SNILS", "PASSPORT_RF", "INN_PERSONAL",
        "DRIVER_LICENSE", "MRZ", "BIRTH_DATE",
    }

    def _compute_uz(
        self,
        group_counts: Dict[str, int],
        findings_by_category: Dict[str, List[Finding]],
    ) -> Optional[int]:
        total = sum(group_counts.values())
        if total == 0:
            return None

        has_strict_pid = any(
            cat in findings_by_category
            for cat in self._PERSONAL_IDENTIFIER_CATEGORIES
        )

        has_special = group_counts.get(GROUP_SPECIAL, 0) > 0
        has_biometric = group_counts.get(GROUP_BIOMETRIC, 0) > 0

        # УЗ-1: спец/био + жёсткий идентификатор конкретного субъекта.
        if (has_special or has_biometric) and has_strict_pid:
            return 1

        if group_counts.get(GROUP_PAYMENT, 0) > 0:
            return 2
        if group_counts.get(GROUP_STATE_IDS, 0) >= self.big_volume_threshold:
            return 2

        # Чувствительный контент без subject-context (упоминание в общем
        # смысле): УЗ-3 - повышенная категория, но не максимум.
        if has_special or has_biometric:
            return 3

        if group_counts.get(GROUP_STATE_IDS, 0) > 0:
            return 3
        if group_counts.get(GROUP_REGULAR, 0) >= self.big_volume_threshold:
            return 3
        return 4

    # ------------------------- public API -----------------------------------
    def detect(self, file_result) -> FileClassification:
        """Классификация одного файла (принимает FileProcessingResult).

        Режим "batch": все чанки уже материализованы в file_result.chunks.
        Подходит для документов/изображений, где чанков мало (десятки-сотни).
        Для крупных структурированных источников используйте detect_stream.
        """
        chunks: List[TextChunk] = list(getattr(file_result, "chunks", []) or [])
        bucket: Dict[Tuple[str, str], Finding] = {}

        for ch in chunks:
            self._detect_in_chunk(ch, bucket)

        # Natasha пускаем только если есть неструктурированные чанки
        if any(not ch.field_name and (ch.text or "").strip() for ch in chunks):
            self._detect_fio_with_natasha(chunks, bucket)

        return self._finalize(bucket, file_result)

    def detect_stream(
        self,
        file_meta,
        chunks: Iterable[TextChunk],
    ) -> FileClassification:
        """Потоковая классификация.

        Принимает метаданные (FileProcessingResult без chunks) и итератор
        чанков. Предназначено для структурированных источников на 100k+
        записей - чанки обрабатываются по одному без материализации.

        Natasha NER в этом режиме НЕ запускается: все чанки структурных
        форматов имеют field_name, а Natasha и так такие чанки пропускает.
        Для .ipynb (смешанный формат) на неструктурированных чанках NER
        можно включить отдельно, если понадобится.
        """
        bucket: Dict[Tuple[str, str], Finding] = {}
        for ch in chunks:
            self._detect_in_chunk(ch, bucket)
        return self._finalize(bucket, file_meta)

    def _finalize(
        self,
        bucket: Dict[Tuple[str, str], Finding],
        file_meta,
    ) -> FileClassification:
        findings_by_category: Dict[str, List[Finding]] = defaultdict(list)
        group_counts: Dict[str, int] = defaultdict(int)
        for f in bucket.values():
            findings_by_category[f.category].append(f)
            group_counts[f.group] += 1

        path = str(getattr(file_meta, "path", ""))
        return FileClassification(
            path=path,
            filename=Path(path).name if path else "",
            format=str(getattr(file_meta, "extension", "")),
            via_ocr=bool(getattr(file_meta, "via_ocr", False)),
            total_findings=sum(group_counts.values()),
            findings_by_category=dict(findings_by_category),
            findings_by_group=dict(group_counts),
            uz_level=self._compute_uz(dict(group_counts), dict(findings_by_category)),
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
