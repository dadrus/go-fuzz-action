"""Validate exact package and fuzz function selection."""

import unittest

from go_fuzz.native_go.error import NativeGoError
from go_fuzz.native_go.target_selector import TargetSelector


class TestTargetSelector(unittest.TestCase):
    def test_selector_accepts_exact_names(self):
        # GIVEN
        for package, target in [
            ("example.com/a/v2", "FuzzA"),
            ("example.org/x", "Fuzz"),
            ("example.org/x", "FuzzÄ"),
            ("a", "Fuzzbad"),  # Native Go decides whether the name exists.
            ("a", "Fuzz.*"),  # Literal, not a pattern.
        ]:
            with self.subTest(package=package, target=target):
                # WHEN
                selector = TargetSelector(package, target)

                # THEN
                self.assertEqual(selector.package, package)
                self.assertEqual(selector.name, target)

    def test_selector_rejects_unsafe_inputs(self):
        # GIVEN
        for package, target in [
            ("./...", "FuzzA"),
            ("-mod=foo", "FuzzA"),
            ("a/../b", "FuzzA"),
            ("all", "FuzzA"),
            ("", "FuzzA"),
            ("/a", "FuzzA"),
            ("a", "TestA"),
            ("a", "FuzzA\\B"),
            ("a", "FuzzA\0"),
            ("a", "FuzzA/FuzzB"),
            ("../outside", "FuzzA"),
            ("a", "FuzzA/../../outside"),
        ]:
            # WHEN / THEN
            with (
                self.subTest(package=package, target=target),
                self.assertRaises(NativeGoError),
            ):
                TargetSelector(package, target)

    def test_pattern_matches_only_literal_target_and_input_reference(self):
        for target, reference, expected in (
            ("FuzzA", None, "^FuzzA$"),
            ("FuzzA", "a.b+", r"^FuzzA$/^a\.b\+$"),
            ("FuzzA", "seed#0", r"^FuzzA$/^seed\#0$"),
            ("Fuzz.*", None, r"^Fuzz\.\*$"),
        ):
            with self.subTest(target=target, reference=reference):
                # GIVEN
                selector = TargetSelector("example.org/a", target)

                # WHEN
                pattern = selector.build_test_pattern(reference)

                # THEN
                self.assertEqual(pattern, expected)
