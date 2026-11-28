"""Target-scoped deduplication and native error-corpus export."""

import tempfile
import unittest
from pathlib import Path

from go_fuzz.corpus import File
from go_fuzz.filesystem import FilesystemError
from go_fuzz.fuzzing.error import FuzzingError
from go_fuzz.fuzzing.finding import Finding
from go_fuzz.fuzzing.findings import Findings
from go_fuzz.native_go import Target, TargetSelector


class TestFindings(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.target = Target(
            TargetSelector("example.org/a", "FuzzA"), self.root, self.root
        )
        first, duplicate, different = (
            self.root / name for name in ("first", "duplicate", "different")
        )
        first.write_bytes(b"one")
        duplicate.write_bytes(b"one")
        different.write_bytes(b"two")
        self.original = Finding(self.target, first.name, "first", None, File(first))
        self.repeated = Finding(
            self.target, duplicate.name, "repeat", None, File(duplicate)
        )
        self.second = Finding(
            self.target, different.name, "second", None, File(different)
        )
        self.seed = Finding(self.target, "seed#0", "failure", None)

    def test_deduplication_retains_first_evidence_for_each_identity(self):
        for initial, candidate, expected in (
            ((), self.original, (self.original,)),
            ((self.original,), self.repeated, (self.original,)),
            ((self.original,), self.second, (self.original, self.second)),
            (
                (self.original, self.second),
                self.seed,
                (self.original, self.second, self.seed),
            ),
            (
                (self.original, self.second, self.seed),
                self.seed,
                (self.original, self.second, self.seed),
            ),
        ):
            with self.subTest(
                initial_count=len(initial), reference=candidate.reference
            ):
                # GIVEN
                findings = Findings(self.target)
                for finding in initial:
                    findings.add(finding)

                # WHEN
                findings.add(candidate)

                # THEN
                self.assertEqual(tuple(findings), expected)
                self.assertEqual(len(findings), len(expected))

    def test_rejects_finding_from_different_target(self):
        # GIVEN
        findings = Findings(self.target)
        findings.add(self.original)
        foreign = Finding(
            Target(TargetSelector("example.org/a", "FuzzOther"), self.root, self.root),
            "seed#0",
            "failure",
            None,
        )

        # WHEN / THEN
        with self.assertRaises(FuzzingError):
            findings.add(foreign)

        # THEN
        self.assertEqual(tuple(findings), (self.original,))

    def test_file_hashes_exclude_native_seeds(self):
        # GIVEN
        findings = Findings(self.target)
        for finding in (self.original, self.second, self.seed):
            findings.add(finding)

        # WHEN
        hashes = findings.file_hashes

        # THEN
        self.assertEqual(
            hashes, {self.original.input_identity, self.second.input_identity}
        )

    def test_export_writes_only_file_inputs_under_content_identity(self):
        for name, inputs, expected in (
            (
                "mixed",
                (self.original, self.second, self.seed),
                {
                    self.original.input_identity: b"one",
                    self.second.input_identity: b"two",
                },
            ),
            ("seed-only", (self.seed,), {}),
        ):
            with self.subTest(name=name):
                # GIVEN
                findings = Findings(self.target)
                for finding in inputs:
                    findings.add(finding)
                output = self.root / name

                # WHEN
                findings.export_error_corpus(output)

                # THEN
                self.assertTrue(output.is_dir())
                self.assertEqual(
                    {p.name: p.read_bytes() for p in output.iterdir()}, expected
                )
                self.assertEqual((self.root / "first").read_bytes(), b"one")

    def test_export_does_not_overwrite_existing_file(self):
        # GIVEN
        findings = Findings(self.target)
        findings.add(self.original)
        output = self.root / "error"
        output.mkdir()
        existing = output / self.original.input_identity
        existing.write_bytes(b"existing")

        # WHEN / THEN
        with self.assertRaises(FileExistsError):
            findings.export_error_corpus(output)

        # THEN
        self.assertEqual(existing.read_bytes(), b"existing")
        self.assertEqual((self.root / "first").read_bytes(), b"one")

    def test_export_rejects_symlink_destination(self):
        # GIVEN
        findings = Findings(self.target)
        output = self.root / "error"
        output.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(output, target_is_directory=True)
        # WHEN / THEN
        with self.assertRaises(FilesystemError):
            findings.export_error_corpus(alias)

        # THEN
        self.assertEqual(list(output.iterdir()), [])
