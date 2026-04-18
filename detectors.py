from __future__ import annotations

from datetime import datetime
import re
from collections import Counter
from typing import Dict, Iterable


CATEGORY_ORDER = (
    "обычные",
    "государственные",
    "платежные",
    "биометрические",
    "специальные",
)

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?:(?:\+7|8)\s*\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2})")
FIO_RE = re.compile(r"\b[А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+){1,2}\b")
DOB_RE = re.compile(r"\b\d{2}[./]\d{2}[./]\d{4}\b")
BIRTH_PLACE_RE = re.compile(r"(?i)(место\s+рождени[яи]|родил[а-я]+\s+в|урожен[еца][кц]?)")
ADDRESS_CONTEXT_RE = re.compile(
    r"(?i)(адрес(?:\s+регистрации)?|зарегистрирован(?:а|ный)?\s+по\s+адресу|прожива(?:ет|ющий)|место\s+жительства|прописка)"
)
ADDRESS_COMPONENT_RE = re.compile(
    r"(?i)(индекс|г\.\s*[А-ЯЁ]|город|ул\.|улица|проспект|пр-кт|б-р|бульвар|пер\.|переулок|д\.|дом|кв\.|квартира|корп\.|строен)"
)
INDEX_RE = re.compile(r"(?<!\d)\d{6}(?!\d)")

SNILS_RE = re.compile(r"\b\d{3}-\d{3}-\d{3}\s?\d{2}\b")
INN10_RE = re.compile(r"(?<!\d)\d{10}(?!\d)")
INN12_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
PASSPORT_RE = re.compile(r"(?<!\d)\d{2}\s?\d{2}\s?\d{6}(?!\d)")
MRZ_RE = re.compile(r"(?m)^[A-Z0-9<]{30,44}$")
DL_RE = re.compile(r"(?<!\d)\d{10}(?!\d)")

CARD_RE = re.compile(r"(?:(?:\d[ -]*?){13,19})")
ACCOUNT_RE = re.compile(r"(?i)(?:р/с|расчетн(?:ый)?\s+счет|расч[её]тный\s+сч[её]т)[^\d]*(\d{20})")
BIK_RE = re.compile(r"(?i)бик[^\d]*(\d{9})")
CVV_RE = re.compile(r"(?i)\b(?:cvv|cvc|cvv2)\b[^\d]{0,5}(\d{3,4})")

PERSON_CONTEXT_KEYWORDS = (
    "гражданин",
    "сотрудник",
    "кандидат",
    "фио",
    "заявитель",
    "подписал",
    "работник",
    "пациент",
)
PERSON_EXCLUDE_TOKENS = {
    "главная",
    "новые",
    "лица",
    "сообщества",
    "лаборатория",
    "коротко",
    "еда",
    "кино",
    "ещё",
    "главное",
    "жж",
    "livejournal",
    "english",
    "android",
    "huawei",
    "россия",
    "республики",
    "области",
    "края",
    "города",
    "компании",
    "университет",
    "федерации",
    "нижний",
    "новгород",
    "санкт",
    "петербург",
    "москва",
}
PHONE_CONTEXT_KEYWORDS = ("тел", "моб", "звонить", "контакт", "связ", "номер")
EMAIL_CONTEXT_KEYWORDS = ("почта", "e-mail", "email", "ящик", "корпоратив")
BIRTH_CONTEXT_KEYWORDS = ("дата рождения", "г. рождения", "родился", "родилась", "др", "возраст")
BIRTH_EXCLUDE_KEYWORDS = ("дата выдачи", "срок действия", "выдан", "действителен")
PASSPORT_CONTEXT_KEYWORDS = ("паспорт", "серия", "номер", "выдан", "кем")
DRIVER_CONTEXT_KEYWORDS = ("ву", "права", "водительское", "категория")
CARD_CONTEXT_KEYWORDS = ("карта", "visa", "mastercard", "mir", "мир", "cvc", "cvv", "срок действия")
ACCOUNT_CONTEXT_KEYWORDS = ("р/с", "бик", "банк", "реквизиты", "платеж")
MRZ_CONTEXT_KEYWORDS = ("mrz", "passport", "машиносчитываемая зона")

BIOMETRIC_KEYWORDS = (
    "биометр",
    "отпечатк",
    "радужной оболоч",
    "радужк",
    "голосовой образец",
    "face id",
    "распознавание лица",
    "геометрия лица",
    "образец голоса",
    "дактилоскоп",
)

SPECIAL_KEYWORDS = (
    "состояние здоровья",
    "диагноз",
    "медицинск",
    "инвалидност",
    "религиозн",
    "политическ",
    "национальн",
    "расов",
    "судимост",
)

GENERIC_EMAIL_LOCALPARTS = {
    "admin",
    "bloggers",
    "contact",
    "contacts",
    "help",
    "hello",
    "hr",
    "info",
    "mail",
    "marketing",
    "partner",
    "partners",
    "press",
    "pr",
    "sales",
    "service",
    "support",
    "team",
    "livejournal",
}


def luhn_check(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def snils_valid(snils: str) -> bool:
    numbers = re.sub(r"\D", "", snils)
    if len(numbers) != 11:
        return False
    body = numbers[:9]
    checksum = int(numbers[-2:])
    total = sum(int(num) * weight for num, weight in zip(body, range(9, 0, -1)))
    if total < 100:
        expected = total
    elif total in (100, 101):
        expected = 0
    else:
        expected = total % 101
        if expected == 100:
            expected = 0
    return checksum == expected


def inn_valid(inn: str) -> bool:
    numbers = re.sub(r"\D", "", inn)
    if len(numbers) == 10:
        coeffs = (2, 4, 10, 3, 5, 9, 4, 6, 8)
        check = sum(int(numbers[i]) * coeffs[i] for i in range(9)) % 11 % 10
        return check == int(numbers[9])
    if len(numbers) == 12:
        coeffs11 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        coeffs12 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        check11 = sum(int(numbers[i]) * coeffs11[i] for i in range(10)) % 11 % 10
        check12 = sum(int(numbers[i]) * coeffs12[i] for i in range(11)) % 11 % 10
        return check11 == int(numbers[10]) and check12 == int(numbers[11])
    return False


def has_context(text: str, start: int, radius: int, *keywords: str) -> bool:
    fragment = text[max(0, start - radius) : start + radius]
    return any(keyword in fragment for keyword in keywords)


def surrounding_fragment(text: str, start: int, end: int, radius: int = 80) -> str:
    return text[max(0, start - radius) : min(len(text), end + radius)]


def _keyword_hits(text: str, keywords: Iterable[str]) -> int:
    lowered = text.lower()
    return sum(1 for keyword in keywords if keyword in lowered)


def _valid_phone(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 11 and digits[0] in {"7", "8"}:
        subscriber = digits[1:]
    elif len(digits) == 10:
        subscriber = digits
    else:
        return False
    if len(set(subscriber)) == 1:
        return False
    return True


def _valid_email(raw: str) -> bool:
    local, _, domain = raw.lower().partition("@")
    if not local or not domain or "." not in domain:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    return True


def _looks_generic_email(raw: str) -> bool:
    local = raw.lower().partition("@")[0]
    tokens = [token for token in re.split(r"[._+-]+", local) if token]
    return bool(tokens) and all(token in GENERIC_EMAIL_LOCALPARTS for token in tokens)


def _valid_passport(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 10:
        return False
    region = int(digits[:2])
    issue_year_marker = int(digits[2:4])
    return 1 <= region <= 99 and 0 <= issue_year_marker <= 99


def _valid_card_bin(digits: str) -> bool:
    if digits.startswith("4"):
        return True
    if digits.startswith(tuple(str(prefix) for prefix in range(51, 56))):
        return True
    if 2221 <= int(digits[:4]) <= 2720:
        return True
    if 2200 <= int(digits[:4]) <= 2204:
        return True
    return False


def _valid_bik(raw: str) -> bool:
    return len(raw) == 9 and raw.startswith("04")


def _valid_birth_date(raw: str) -> bool:
    try:
        day, month, year = map(int, re.split(r"[./]", raw))
        date = datetime(year, month, day)
    except ValueError:
        return False
    current_year = datetime.now().year
    return 1900 <= date.year <= current_year


def _has_person_context_nearby(lowered_text: str, start: int, end: int, radius: int) -> bool:
    fragment = surrounding_fragment(lowered_text, start, end, radius)
    for keyword in PERSON_CONTEXT_KEYWORDS:
        if re.search(rf"\b{re.escape(keyword)}\b", fragment):
            return True
    prefix = lowered_text[max(0, start - 6) : start + 1]
    return bool(re.search(r"(?:^|[^а-яё])я,\s*$", prefix))


def _looks_like_person_name(match_text: str, lowered_text: str, start: int, end: int) -> bool:
    tokens = match_text.split()
    if not all(re.fullmatch(r"[А-ЯЁ][а-яё-]+", token) for token in tokens):
        return False
    if any(token.lower() in PERSON_EXCLUDE_TOKENS for token in tokens):
        return False
    if len(tokens) == 3:
        middle_or_last = (tokens[1].lower(), tokens[2].lower())
        if any(token.endswith(("вич", "вна", "ична", "оглы", "кызы")) for token in middle_or_last):
            return True
        return _has_person_context_nearby(lowered_text, start, end, 80)
    return _has_person_context_nearby(lowered_text, start, end, 60)


def _looks_like_address(fragment: str) -> bool:
    lowered = fragment.lower()
    component_hits = len(ADDRESS_COMPONENT_RE.findall(fragment))
    has_index = bool(INDEX_RE.search(fragment))
    has_context_hint = bool(ADDRESS_CONTEXT_RE.search(fragment))
    has_street = bool(re.search(r"(?i)(ул\.|улица|проспект|пр-кт|б-р|бульвар|пер\.|переулок)", fragment))
    has_house = bool(re.search(r"(?i)(д\.|дом)\s*\d+", fragment))
    has_apartment = bool(re.search(r"(?i)(кв\.|квартира)\s*\d+", fragment))
    if has_context_hint and ((has_street and has_house) or (has_index and has_street)):
        return True
    return component_hits >= 3 and (has_house or has_apartment or has_index)


def _valid_mrz(raw: str) -> bool:
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        return False
    candidate = max(lines, key=len)
    if len(candidate) not in {30, 36, 44}:
        return False
    return bool(re.fullmatch(r"[A-Z0-9<]+", candidate))


def empty_categories() -> Dict[str, int]:
    return {name: 0 for name in CATEGORY_ORDER}


def merge_category_counts(*groups: Dict[str, int]) -> Dict[str, int]:
    merged = Counter(empty_categories())
    for group in groups:
        merged.update(group)
    return dict(merged)


def detect_regex_categories(text: str) -> Dict[str, int]:
    normalized = text or ""
    lowered = normalized.lower()
    counts = Counter(empty_categories())

    for match in EMAIL_RE.finditer(normalized):
        if _valid_email(match.group(0)):
            fragment = surrounding_fragment(lowered, match.start(), match.end())
            if _looks_generic_email(match.group(0)):
                continue
            if any(keyword in fragment for keyword in EMAIL_CONTEXT_KEYWORDS) or "@" in match.group(0):
                counts["обычные"] += 1

    for match in PHONE_RE.finditer(normalized):
        if _valid_phone(match.group(0)):
            fragment = surrounding_fragment(lowered, match.start(), match.end())
            if any(keyword in fragment for keyword in PHONE_CONTEXT_KEYWORDS) or match.group(0).startswith(("+7", "8")):
                counts["обычные"] += 1

    for match in SNILS_RE.finditer(normalized):
        if snils_valid(match.group(0)):
            counts["государственные"] += 1
    for match in INN10_RE.finditer(normalized):
        if inn_valid(match.group(0)):
            counts["государственные"] += 1
    for match in INN12_RE.finditer(normalized):
        if inn_valid(match.group(0)):
            counts["государственные"] += 1
    for match in PASSPORT_RE.finditer(normalized):
        if _valid_passport(match.group(0)) and has_context(lowered, match.start(), 50, *PASSPORT_CONTEXT_KEYWORDS):
            counts["государственные"] += 1
    for match in DL_RE.finditer(normalized):
        if has_context(lowered, match.start(), 50, *DRIVER_CONTEXT_KEYWORDS):
            counts["государственные"] += 1
    for match in MRZ_RE.finditer(normalized):
        if _valid_mrz(match.group(0)) and has_context(lowered, match.start(), 60, *MRZ_CONTEXT_KEYWORDS):
            counts["государственные"] += 1

    for match in CARD_RE.finditer(normalized):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and luhn_check(digits) and _valid_card_bin(digits):
            if has_context(lowered, match.start(), 50, *CARD_CONTEXT_KEYWORDS):
                counts["платежные"] += 1
    for account in ACCOUNT_RE.finditer(normalized):
        if has_context(lowered, account.start(), 60, *ACCOUNT_CONTEXT_KEYWORDS):
            counts["платежные"] += 1
    for bik in BIK_RE.finditer(normalized):
        if _valid_bik(bik.group(1)) and has_context(lowered, bik.start(), 60, *ACCOUNT_CONTEXT_KEYWORDS):
            counts["платежные"] += 1
    for cvv in CVV_RE.finditer(normalized):
        if has_context(lowered, cvv.start(), 40, *CARD_CONTEXT_KEYWORDS):
            counts["платежные"] += 1

    return dict(counts)


def detect_ner_categories(text: str) -> Dict[str, int]:
    normalized = text or ""
    lowered = normalized.lower()
    counts = Counter(empty_categories())

    fio_hits = 0
    for match in FIO_RE.finditer(normalized):
        if _looks_like_person_name(match.group(0), lowered, match.start(), match.end()):
            fio_hits += 1
    counts["обычные"] += min(10, fio_hits)

    dob_hits = 0
    for match in DOB_RE.finditer(normalized):
        left_fragment = lowered[max(0, match.start() - 40) : match.start()]
        right_fragment = lowered[match.end() : min(len(lowered), match.end() + 40)]
        birth_context = any(keyword in left_fragment or keyword in right_fragment for keyword in BIRTH_CONTEXT_KEYWORDS)
        exclude_context = any(keyword in left_fragment or keyword in right_fragment for keyword in BIRTH_EXCLUDE_KEYWORDS)
        if _valid_birth_date(match.group(0)) and birth_context:
            if not exclude_context or "дата рождения" in left_fragment or "г. рождения" in right_fragment:
                dob_hits += 1
    counts["обычные"] += dob_hits

    birth_place_hits = 0
    for match in BIRTH_PLACE_RE.finditer(normalized):
        fragment = surrounding_fragment(normalized, match.start(), match.end(), radius=120)
        if re.search(r"[А-ЯЁ][а-яё]+(?:[-\s][А-ЯЁ][а-яё]+){0,2}", fragment):
            birth_place_hits += 1
    counts["обычные"] += birth_place_hits

    address_hits = 0
    for match in ADDRESS_CONTEXT_RE.finditer(normalized):
        fragment = surrounding_fragment(normalized, match.start(), match.end(), radius=160)
        if _looks_like_address(fragment):
            address_hits += 1
    counts["обычные"] += address_hits

    return dict(counts)


def detect_classifier_categories(text: str) -> Dict[str, int]:
    normalized = text or ""
    counts = Counter(empty_categories())
    counts["биометрические"] += _keyword_hits(normalized, BIOMETRIC_KEYWORDS)
    counts["специальные"] += _keyword_hits(normalized, SPECIAL_KEYWORDS)
    return dict(counts)


def detect_categories(text: str) -> Dict[str, int]:
    return merge_category_counts(
        detect_regex_categories(text),
        detect_ner_categories(text),
        detect_classifier_categories(text),
    )


def classify_uz(categories: Dict[str, int]) -> str:
    common_count = categories.get("обычные", 0)
    gov_count = categories.get("государственные", 0)
    pay_count = categories.get("платежные", 0)
    bio_count = categories.get("биометрические", 0)
    special_count = categories.get("специальные", 0)

    if special_count or bio_count:
        return "УЗ-1"
    if pay_count or gov_count >= 5:
        return "УЗ-2"
    if gov_count or common_count >= 5:
        return "УЗ-3"
    if common_count:
        return "УЗ-4"
    return "нет признаков"


def build_recommendations(categories: Dict[str, int], uz: str) -> list[str]:
    recommendations: list[str] = []
    if uz == "УЗ-1":
        recommendations.append("Ограничить доступ и провести приоритетную проверку оснований обработки.")
    elif uz == "УЗ-2":
        recommendations.append("Проверить права доступа, сроки хранения и необходимость шифрования.")
    elif uz == "УЗ-3":
        recommendations.append("Классифицировать файл и ограничить распространение внутри хранилища.")
    elif uz == "УЗ-4":
        recommendations.append("Пометить файл как содержащий ПДн и контролировать жизненный цикл.")

    if categories.get("платежные", 0):
        recommendations.append("Не включать полные платежные реквизиты в отчет и логи.")
    if categories.get("государственные", 0):
        recommendations.append("Проверить наличие правового основания на хранение идентификаторов.")
    if categories.get("специальные", 0) or categories.get("биометрические", 0):
        recommendations.append("Рассмотреть отдельный контур обработки для чувствительных данных.")
    return recommendations
