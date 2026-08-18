import os
import re
import unittest
from unittest import mock

os.environ.setdefault("SCANNER_SKIP_PREREQ_CHECK", "1")

import scanner


class OutputDirDefaultTests(unittest.TestCase):
    def test_default_output_dir_appends_timestamp(self):
        with mock.patch.object(scanner, "datetime") as mock_dt:
            mock_dt.now.return_value.strftime.return_value = "20260406_123456"
            out = scanner.default_output_dir()
        self.assertEqual(out, "nis2_scan_output_20260406_123456")

    def test_default_output_dir_matches_expected_format(self):
        out = scanner.default_output_dir()
        self.assertRegex(out, r"^nis2_scan_output_\d{8}_\d{6}$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
