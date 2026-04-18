import unittest

from analysis.classifier_branch import run_classifier_branch


class ClassifierBranchTests(unittest.TestCase):
    def test_public_university_page_does_not_raise_special_categories(self):
        categories = run_classifier_branch(
            "Южный Федеральный Университет. Рейтинг НПР. Анкета. "
            "Председатель комиссии Цатурян Аршак Асланович. "
            "support@sfedu.ru caturyan@sfedu.ru"
        )
        self.assertEqual(categories["специальные"], 0)
        self.assertEqual(categories["биометрические"], 0)


if __name__ == "__main__":
    unittest.main()
