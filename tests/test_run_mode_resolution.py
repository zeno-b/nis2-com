import os
import unittest
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("SCANNER_SKIP_PREREQ_CHECK", "1")

import scanner


class RunModeResolutionTests(unittest.TestCase):
    def _args(self, *, run_mode="auto", dry_run=False, resume=False):
        return SimpleNamespace(run_mode=run_mode, dry_run=dry_run, resume=resume)

    def test_auto_mode_default_keeps_scan_behavior(self):
        mode, dry, resume, from_dry = scanner.resolve_run_mode(self._args())
        self.assertEqual((mode, dry, resume, from_dry), ("auto", False, False, False))

    def test_auto_mode_maps_dry_run_flag(self):
        mode, dry, resume, from_dry = scanner.resolve_run_mode(self._args(dry_run=True))
        self.assertEqual((mode, dry, resume, from_dry), ("dryrun", True, False, False))

    def test_auto_mode_maps_dry_run_plus_resume_flags(self):
        mode, dry, resume, from_dry = scanner.resolve_run_mode(
            self._args(dry_run=True, resume=True)
        )
        self.assertEqual(
            (mode, dry, resume, from_dry),
            ("dryrun-skip-selected", True, True, False),
        )

    def test_explicit_run_mode_overrides_legacy_flags(self):
        with mock.patch.object(scanner, "warn") as mock_warn:
            mode, dry, resume, from_dry = scanner.resolve_run_mode(
                self._args(run_mode="run-from-dryrun", dry_run=True, resume=True)
            )
        self.assertEqual(
            (mode, dry, resume, from_dry),
            ("run-from-dryrun", False, False, True),
        )
        mock_warn.assert_called_once()

    def test_config_can_set_run_mode_when_cli_left_default(self):
        args = SimpleNamespace(run_mode="auto")
        scanner.apply_config_to_args({"run_mode": "dryrun-skip-selected"}, args)
        self.assertEqual(args.run_mode, "dryrun-skip-selected")

    def test_config_does_not_override_explicit_cli_run_mode(self):
        args = SimpleNamespace(run_mode="dryrun")
        scanner.apply_config_to_args({"run_mode": "run-from-dryrun"}, args)
        self.assertEqual(args.run_mode, "dryrun")


if __name__ == "__main__":
    unittest.main(verbosity=2)
