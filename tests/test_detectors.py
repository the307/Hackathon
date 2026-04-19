import unittest

from detectors import classify_uz, detect_categories, inn_valid, luhn_check, snils_valid


def make_valid_snils(body: str) -> str:
    total = sum(int(number) * weight for number, weight in zip(body, range(9, 0, -1)))
    if total < 100:
        checksum = total
    elif total in (100, 101):
        checksum = 0
    else:
        checksum = total % 101
        if checksum == 100:
            checksum = 0
    return f"{body[:3]}-{body[3:6]}-{body[6:9]} {checksum:02d}"


def make_valid_inn12(base: str) -> str:
    coeffs11 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
    coeffs12 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
    eleventh = sum(int(base[index]) * coeffs11[index] for index in range(10)) % 11 % 10
    first_eleven = base + str(eleventh)
    twelfth = sum(int(first_eleven[index]) * coeffs12[index] for index in range(11)) % 11 % 10
    return first_eleven + str(twelfth)


class DetectorTests(unittest.TestCase):
    def test_detect_categories_for_synthetic_candidate_form(self):
        valid_snils = make_valid_snils("112233445")
        valid_inn = make_valid_inn12("1234567890")
        text = """
        Я, Воронцов Тимур Алексеевич, 17.11.1988 г. рождения,
        паспорт серии 52 17 118903, зарегистрированный по адресу:
        контактный телефон: +7 910 245-63-18,
        адрес электронной почты: t.vorontsov.synthetic@inbox.test,
        ИНН: {valid_inn},
        СНИЛС: {valid_snils}
        """.format(valid_inn=valid_inn, valid_snils=valid_snils)
        categories = detect_categories(text)

        self.assertGreaterEqual(categories["обычные"], 4)
        self.assertGreaterEqual(categories["государственные"], 3)
        self.assertEqual(classify_uz(categories), "УЗ-3")

    def test_special_categories_raise_highest_level(self):
        categories = detect_categories("Состояние здоровья, биометрия, образец голоса")
        self.assertGreaterEqual(categories["специальные"], 1)
        self.assertGreaterEqual(categories["биометрические"], 1)
        self.assertEqual(classify_uz(categories), "УЗ-1")

    def test_validators_accept_known_valid_values(self):
        valid_snils = make_valid_snils("112233445")
        valid_inn = make_valid_inn12("1234567890")
        self.assertTrue(luhn_check("4111111111111111"))
        self.assertTrue(snils_valid(valid_snils))
        self.assertTrue(inn_valid(valid_inn))

    def test_birth_context_ignores_issue_dates(self):
        categories = detect_categories(
            "Паспорт выдан 12.03.2020. Дата рождения: 17.11.1988. "
            "Зарегистрирован по адресу: 603104, г. Нижний Новгород, ул. Тихая Слобода, д. 5, кв. 88."
        )
        self.assertGreaterEqual(categories["обычные"], 2)

    def test_card_requires_context_and_valid_bin(self):
        categories = detect_categories(
            "Банковская карта клиента: 4111 1111 1111 1111, CVV 123, срок действия 12/30."
        )
        self.assertGreaterEqual(categories["платежные"], 2)

    def test_html_menu_like_titles_do_not_count_as_fio(self):
        categories = detect_categories("Главная Новые лица Сообщества Лаборатория ЖЖ")
        self.assertEqual(categories["обычные"], 0)

    def test_name_order_first_patronymic_last_is_detected(self):
        categories = detect_categories("customer_name | Филипп Елизарович Воробьев | Физическое лицо")
        self.assertGreaterEqual(categories["обычные"], 1)

    def test_logistics_addresses_do_not_count_as_fio_or_biometrics(self):
        categories = detect_categories(
            "53 | 60 | 1 | ст. Александров Гай, наб. Ставропольская, д. 98 стр. 57, 670633 | ЖД | ТрансЛогистик"
        )
        self.assertEqual(categories["обычные"], 0)
        self.assertEqual(categories["биометрические"], 0)

    def test_demo_markers_suppress_findings(self):
        valid_snils = make_valid_snils("112233445")
        text = (
            "Пример заявления (образец, для тестирования). "
            f"СНИЛС: {valid_snils}, телефон: +7 910 245-63-18, "
            "email: ivanov@example.com"
        )
        categories = detect_categories(text)
        self.assertEqual(categories["государственные"], 0)
        self.assertEqual(categories["обычные"], 0)

    def test_duplicate_values_counted_once(self):
        text = (
            "Контакты сотрудника: телефон +7 910 245-63-18, e-mail ivanov@corp.ru. "
            "Дублирующая строка ниже:\n"
            "телефон +7 910 245-63-18, e-mail ivanov@corp.ru.\n"
            "телефон +7 910 245-63-18."
        )
        categories = detect_categories(text)
        self.assertEqual(categories["обычные"], 2)

    def test_generic_role_emails_do_not_count_as_personal_contacts(self):
        categories = detect_categories(
            "Advertising: livejournal@sberseller.ru Promotion: bloggers@livejournalinc.com PR: pr@ramber-co.ru"
        )
        self.assertEqual(categories["обычные"], 0)


if __name__ == "__main__":
    unittest.main()
