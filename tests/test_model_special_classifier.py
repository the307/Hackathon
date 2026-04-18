import unittest

from analysis.model_special_classifier import map_model_predictions_to_categories


class ModelSpecialClassifierTests(unittest.TestCase):
    def test_policy_noise_is_suppressed_without_person_context(self):
        text = "Privacy policy and cookies notice for website visitors. Special categories of personal data are described in general terms."
        categories = map_model_predictions_to_categories(text, {"health": 1, "beliefs": 1, "other": 1})
        self.assertEqual(categories["специальные"], 0)
        self.assertEqual(categories["биометрические"], 0)

    def test_person_context_allows_special_category(self):
        text = "По данным медосмотра, пациенту диагностирован сахарный диабет второго типа."
        categories = map_model_predictions_to_categories(text, {"health": 1})
        self.assertEqual(categories["специальные"], 1)


if __name__ == "__main__":
    unittest.main()
