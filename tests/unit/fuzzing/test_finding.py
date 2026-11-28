"""Finding identity, validation and native reproduction commands."""

import hashlib
import shlex
import tempfile
import unittest
from pathlib import Path

from go_fuzz.corpus import File
from go_fuzz.fuzzing.error import FuzzingError
from go_fuzz.fuzzing.finding import Finding
from go_fuzz.native_go import Target, TargetSelector, TestOutcome


class TestFinding(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.target = Target(
            TargetSelector("example.org/a", "FuzzA"), self.root, self.root
        )
        source = self.root / "one"
        source.write_bytes(b"opaque corpus content")
        self.entry = File(source)

    def test_identity_distinguishes_file_inputs_and_native_seeds(self):
        for reference, corpus, kind, identity in (
            ("one", self.entry, "file", self.entry.digest),
            ("seed#0", None, "seed", "seed#0"),
        ):
            with self.subTest(kind=kind):
                # GIVEN
                finding = Finding(self.target, reference, "failure", None, corpus)

                # WHEN
                key = finding.key

                # THEN
                self.assertEqual(key, ("example.org/a", "FuzzA", kind, identity))
                self.assertEqual(finding.input_kind, kind)
                self.assertEqual(finding.input_identity, identity)

    def test_rejects_reference_not_identifying_its_input(self):
        for reference, corpus in (
            ("missing", None),
            ("two", self.entry),
            ("seed#0", self.entry),
        ):
            # GIVEN
            # A reference must identify its file, or be a native seed without a file.

            # WHEN / THEN
            with self.subTest(reference=reference), self.assertRaises(FuzzingError):
                Finding(self.target, reference, "failure", None, corpus)

    def test_fingerprint_depends_on_full_finding_identity(self):
        # GIVEN
        duplicate = self.root / "duplicate"
        duplicate.write_bytes(self.entry.path.read_bytes())
        different = self.root / "different"
        different.write_bytes(b"different")
        second = File(different)
        other_package = Target(
            TargetSelector("example.org/other", "FuzzA"), self.root, self.root
        )
        other_target = Target(
            TargetSelector("example.org/a", "FuzzOther"), self.root, self.root
        )
        for finding, key in (
            (
                Finding(self.target, "one", "failure", None, self.entry),
                f"example.org/a\0FuzzA\0file\0{self.entry.digest}",
            ),
            (
                Finding(
                    self.target,
                    "duplicate",
                    "different diagnosis",
                    ("other.go", 2),
                    File(duplicate),
                ),
                f"example.org/a\0FuzzA\0file\0{self.entry.digest}",
            ),
            (
                Finding(self.target, "different", "failure", None, second),
                f"example.org/a\0FuzzA\0file\0{second.digest}",
            ),
            (
                Finding(self.target, "seed#0", "failure", None),
                "example.org/a\0FuzzA\0seed\0seed#0",
            ),
            (
                Finding(other_package, "seed#0", "failure", None),
                "example.org/other\0FuzzA\0seed\0seed#0",
            ),
            (
                Finding(other_target, "seed#0", "failure", None),
                "example.org/a\0FuzzOther\0seed\0seed#0",
            ),
        ):
            with self.subTest(reference=finding.reference, key=key):
                # GIVEN
                expected = hashlib.sha256(key.encode()).hexdigest()

                # WHEN
                fingerprint = finding.fingerprint

                # THEN
                self.assertEqual(fingerprint, expected)

    def test_reproduction_uses_exported_file_name_or_native_seed_reference(self):
        for reference, corpus, pattern in (
            ("one", self.entry, f"^FuzzA$/^{self.entry.digest}$"),
            ("seed#0", None, r"^FuzzA$/^seed\#0$"),
        ):
            with self.subTest(reference=reference):
                # GIVEN
                finding = Finding(self.target, reference, "failure", None, corpus)

                # WHEN
                command = shlex.split(finding.reproduction_command)

                # THEN
                self.assertEqual(
                    command,
                    ["go", "test", "-count=1", "-run", pattern, "example.org/a"],
                )

    def test_from_outcome_preserves_native_diagnostic_or_uses_fallback(self):
        # GIVEN
        corpus = self.entry
        for reference, entry, message, location, expected_message in (
            ("one", corpus, "native failure", ("fuzz_test.go", 2), "native failure"),
            ("seed#0", None, "", None, "--- FAIL: FuzzA/seed#0"),
        ):
            with self.subTest(reference=reference):
                # GIVEN
                outcome = TestOutcome(True, frozenset({reference}), message, location)
                expected = Finding(
                    self.target, reference, expected_message, location, entry
                )

                # WHEN
                finding = Finding.from_outcome(self.target, reference, outcome, entry)

                # THEN
                self.assertEqual(finding, expected)
