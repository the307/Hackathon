import unittest

from main import DEFAULT_DATASET_ROOT, build_parser


class MainCliTests(unittest.TestCase):
    def test_root_defaults_to_local_dataset(self):
        args = build_parser().parse_args([])
        self.assertEqual(args.root, str(DEFAULT_DATASET_ROOT))

    def test_debug_progress_flag_is_parsed(self):
        args = build_parser().parse_args(["--debug-progress"])
        self.assertTrue(args.debug_progress)


if __name__ == "__main__":
    unittest.main()
