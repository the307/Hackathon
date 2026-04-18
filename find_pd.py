import re
from collections import defaultdict
from natasha import (
    Segmenter,
    MorphVocab,
    NewsEmbedding,
    NewsMorphTagger,
    NewsSyntaxParser,
    NewsNERTagger,
    Doc
)


class PIIDetector:
    def __init__(self):
        # Natasha components
        self.segmenter = Segmenter()
        self.morph_vocab = MorphVocab()
        self.emb = NewsEmbedding()
        self.morph_tagger = NewsMorphTagger(self.emb)
        self.syntax_parser = NewsSyntaxParser(self.emb)
        self.ner_tagger = NewsNERTagger(self.emb)

        # Regex patterns
        self.patterns = {
            "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            "PHONE": re.compile(
                r"(?:(?:\+7|8)[\s\-]?)?(?:\(?\d{3}\)?[\s\-]?)?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b"
            ),
            "PASSPORT": re.compile(r"\b\d{4}\s?\d{6}\b"),
            "SNILS": re.compile(r"\b\d{3}-\d{3}-\d{3}\s?\d{2}\b"),
            "INN": re.compile(r"\b\d{10}(?:\d{2})?\b"),
            "DATE": re.compile(r"\b\d{2}\.\d{2}\.\d{4}\b"),
            "IP": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        }

        # Упрощённый словарь имён для доп. эвристики
        self.name_dictionary = {
            "иван", "петр", "пётр", "анна", "мария", "сергей",
            "алексей", "елена", "наталья", "дмитрий", "андрей"
        }

        # Веса для оценки риска
        self.weights = {
            "PASSPORT": 10,
            "SNILS": 9,
            "INN": 8,
            "PERSON": 5,
            "EMAIL": 3,
            "PHONE": 3,
            "DATE": 2,
            "ADDRESS": 4,
            "LOCATION": 2,
            "IP": 2
        }

    def detect_regex(self, text: str) -> dict:
        results = defaultdict(list)

        for label, pattern in self.patterns.items():
            matches = pattern.findall(text)
            if not matches:
                continue

            for match in matches:
                if isinstance(match, tuple):
                    match = "".join(match)
                results[label].append(match.strip())

        return results

    def detect_natasha_entities(self, text: str) -> dict:
        results = defaultdict(list)

        doc = Doc(text)
        doc.segment(self.segmenter)
        doc.tag_morph(self.morph_tagger)
        doc.parse_syntax(self.syntax_parser)
        doc.tag_ner(self.ner_tagger)

        for span in doc.spans:
            span.normalize(self.morph_vocab)
            value = span.text.strip()
            normalized = (span.normal or value).strip()

            if span.type == "PER":
                results["PERSON"].append(normalized)
            elif span.type == "LOC":
                results["LOCATION"].append(normalized)
            elif span.type == "ORG":
                results["ORGANIZATION"].append(normalized)

        return results

    def detect_dictionary_names(self, text: str) -> dict:
        results = defaultdict(list)

        words = re.findall(r"[А-Яа-яЁёA-Za-z-]+", text.lower())
        for word in words:
            if word in self.name_dictionary:
                results["PERSON"].append(word.title())

        return results

    def detect_address_candidates(self, text: str) -> dict:
        """
        Простая эвристика для адресов.
        Для хакатона этого обычно достаточно как дополнительного сигнала.
        """
        results = defaultdict(list)

        address_patterns = [
            r"(?:г\.?|город)\s+[А-ЯЁA-Z][а-яёa-zA-Z-]+",
            r"(?:ул\.?|улица)\s+[А-ЯЁA-Z0-9][а-яёa-zA-Z0-9\- ]+",
            r"(?:д\.?|дом)\s*\d+[А-Яа-яA-Za-z]?",
            r"(?:кв\.?|квартира)\s*\d+",
            r"(?:проспект|пр-т)\s+[А-ЯЁA-Z0-9][а-яёa-zA-Z0-9\- ]+",
        ]

        for pattern in address_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                results["ADDRESS"].append(match.strip())

        return results

    def merge_results(self, *args) -> dict:
        merged = defaultdict(set)

        for result in args:
            for key, values in result.items():
                for value in values:
                    clean_value = value.strip()
                    if clean_value:
                        merged[key].add(clean_value)

        return {k: sorted(v) for k, v in merged.items()}

    def apply_rules(self, entities: dict, text: str) -> tuple[int, list]:
        """
        Дополнительные rule-based сигналы поверх найденных сущностей.
        """
        score_bonus = 0
        triggered_rules = []
        text_lower = text.lower()

        if entities.get("PERSON") and entities.get("DATE"):
            score_bonus += 5
            triggered_rules.append("PERSON + DATE")

        if entities.get("PERSON") and entities.get("PHONE"):
            score_bonus += 4
            triggered_rules.append("PERSON + PHONE")

        if entities.get("PERSON") and entities.get("EMAIL"):
            score_bonus += 4
            triggered_rules.append("PERSON + EMAIL")

        if entities.get("PERSON") and entities.get("ADDRESS"):
            score_bonus += 5
            triggered_rules.append("PERSON + ADDRESS")

        if entities.get("PASSPORT"):
            score_bonus += 8
            triggered_rules.append("PASSPORT_PRESENT")

        if entities.get("SNILS"):
            score_bonus += 7
            triggered_rules.append("SNILS_PRESENT")

        context_keywords = [
            "паспорт", "снилс", "инн", "дата рождения",
            "место жительства", "адрес регистрации", "персональные данные"
        ]
        found_context = [kw for kw in context_keywords if kw in text_lower]
        if found_context:
            score_bonus += min(len(found_context) * 2, 8)
            triggered_rules.append(f"CONTEXT:{', '.join(found_context)}")

        return score_bonus, triggered_rules

    def calculate_risk(self, entities: dict, text: str) -> tuple[int, str, list]:
        score = 0

        for entity_type, values in entities.items():
            weight = self.weights.get(entity_type, 0)
            score += weight * len(values)

        bonus, rules = self.apply_rules(entities, text)
        score += bonus

        if score >= 20:
            level = "HIGH"
        elif score >= 8:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level, rules

    def analyze(self, text: str) -> dict:
        regex_results = self.detect_regex(text)
        natasha_results = self.detect_natasha_entities(text)
        dict_results = self.detect_dictionary_names(text)
        address_results = self.detect_address_candidates(text)

        entities = self.merge_results(
            regex_results,
            natasha_results,
            dict_results,
            address_results
        )

        score, level, rules = self.calculate_risk(entities, text)

        return {
            "entities": entities,
            "risk_score": score,
            "risk_level": level,
            "triggered_rules": rules
        }


if __name__ == "__main__":
    sample_text = """
    Иван Петров гулял с собакой по двору 12.05.1987 г. Москва, ул. Тверская, д. 10, кв. 15. 1234 567890 123-456-789 00 ivan.petrov@gmail.com +7-999-123-4567
    """

    detector = PIIDetector()
    result = detector.analyze(sample_text)

    from pprint import pprint
    pprint(result)

