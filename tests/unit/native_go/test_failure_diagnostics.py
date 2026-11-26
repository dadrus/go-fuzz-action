"""Collect native references, diagnostics and locations without classifying runs."""

import tempfile
import unittest
from pathlib import Path

from go_fuzz.native_go.event import Event
from go_fuzz.native_go.failure_diagnostics import FailureDiagnostics
from go_fuzz.native_go.target import Target
from go_fuzz.native_go.target_selector import TargetSelector

PACKAGE = "example.com/a"
TARGET = "FuzzA"
REPLAY = "FuzzA/bad"
PROGRESS = "fuzz: elapsed: 0s, gathering baseline coverage: 0/1 completed\n"
SUMMARY = "--- FAIL: FuzzA (0.01s)\n"
SEED = "failure while testing seed corpus entry: FuzzA/seed#0\n"
SAVED = "    Failing input written to testdata/fuzz/FuzzA/abc\n"


class TestFailureDiagnostics(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "fuzz_test.go"
        self.source.touch()
        self.target = Target(TargetSelector(PACKAGE, TARGET), self.root, self.root)

    def test_fuzz_references_require_native_execution_context(self):
        for output, references in (
            (PROGRESS + SEED + SUMMARY, {"seed#0"}),
            (PROGRESS + SUMMARY + SAVED, {"abc"}),
            (
                PROGRESS
                + SUMMARY
                + f"    Failing input written to {self.target.seed_directory / 'abc'}\n",
                {"abc"},
            ),
            (SEED + SUMMARY, set()),
            (SUMMARY + SAVED, set()),
            (PROGRESS + SUMMARY, set()),
            (PROGRESS + SAVED + SUMMARY, set()),
            (PROGRESS + SUMMARY + SEED, set()),
            (PROGRESS + SEED.replace("FuzzA/", "FuzzOther/") + SUMMARY, set()),
        ):
            with self.subTest(output=output):
                # GIVEN
                diagnostics = FailureDiagnostics(self.target, TARGET)

                # WHEN
                diagnostics.record(Event("output", PACKAGE, TARGET, output))

                # THEN
                self.assertEqual(diagnostics.references, references)

    def test_saved_reference_must_belong_to_target_corpus(self):
        for path in ("testdata/fuzz/FuzzOther/abc", str(self.root / "abc"), "../abc"):
            with self.subTest(path=path):
                # GIVEN
                diagnostics = FailureDiagnostics(self.target, TARGET)
                output = PROGRESS + SUMMARY + f"    Failing input written to {path}\n"

                # WHEN
                diagnostics.record(Event("output", PACKAGE, TARGET, output))

                # THEN
                self.assertEqual(diagnostics.references, set())

    def test_fuzz_diagnostic_retains_native_failure_and_location(self):
        # GIVEN
        diagnostics = FailureDiagnostics(self.target, TARGET)
        message = f"        {self.source}:1: assertion failed\n"
        output = PROGRESS + SEED + SUMMARY + "    --- FAIL: FuzzA (0.00s)\n" + message

        # WHEN
        diagnostics.record(Event("output", PACKAGE, TARGET, output))

        # THEN
        self.assertEqual("".join(diagnostics.lines), output[len(PROGRESS) :])
        self.assertEqual(diagnostics.location, ("fuzz_test.go", 1))

    def test_fuzz_diagnostics_ignore_other_tests(self):
        # GIVEN
        diagnostics = FailureDiagnostics(self.target, TARGET)
        output = PROGRESS + SEED + SUMMARY

        # WHEN
        diagnostics.record(Event("output", PACKAGE, "FuzzOther", output))

        # THEN
        self.assertEqual(diagnostics.references, set())
        self.assertEqual(diagnostics.lines, [])

    def test_replay_retains_only_associated_subtest_diagnostics(self):
        # GIVEN
        diagnostics = FailureDiagnostics(self.target, REPLAY)
        child = f"{REPLAY}/child"
        grandchild = f"{child}/grandchild"
        message = f"{self.source}:3: nested failure\n"
        events = (
            Event("output", PACKAGE, TARGET, "parent setup\n"),
            Event("output", PACKAGE, REPLAY, "input context\n"),
            Event("output", PACKAGE, REPLAY, "exit status 2\nsignal: killed\n"),
            Event("output", PACKAGE, "FuzzA/badly/child", "unrelated\n"),
            Event("output", PACKAGE, child, "child context\n"),
            Event("output", PACKAGE, grandchild, message),
            Event("fail", PACKAGE, grandchild),
            Event("fail", PACKAGE, REPLAY),
            Event("output", PACKAGE, TARGET, "panic: input failure\n"),
            Event("output", PACKAGE, output="package context\n"),
        )

        # WHEN
        for event in events:
            diagnostics.record(event)

        # THEN
        self.assertEqual(
            "".join(diagnostics.lines),
            f"input context\nexit status 2\nsignal: killed\n"
            f"child context\n{message}panic: input failure\n",
        )
        self.assertEqual(diagnostics.location, ("fuzz_test.go", 3))

    def test_native_source_positions(self):
        # GIVEN
        spaced = self.root / "directory with spaces" / "source.go"
        spaced.parent.mkdir()
        spaced.touch()
        for message, expected in (
            (f"{self.source}:1: failure", ("fuzz_test.go", 1)),
            (f"{spaced}:3: failure", ("directory with spaces/source.go", 3)),
            (f"{self.source}:2 +0x123", ("fuzz_test.go", 2)),
            (f"{self.source}:2", ("fuzz_test.go", 2)),
            ("fuzz_test.go:1: failure", None),
            (f"{PACKAGE}/fuzz_test.go:1: failure", None),
            (f"{self.root / 'missing.go'}:1: failure", None),
        ):
            with self.subTest(message=message):
                # GIVEN
                diagnostics = FailureDiagnostics(self.target, REPLAY)

                # WHEN
                diagnostics.record(Event("output", PACKAGE, REPLAY, f"    {message}\n"))

                # THEN
                self.assertEqual(diagnostics.location, expected)
                self.assertIn(message, "".join(diagnostics.lines))

    def test_location_uses_a_line_only_for_one_distinct_native_position(self):
        # GIVEN
        other = self.root / "other.go"
        other.touch()
        for messages, expected in (
            (
                (f"{self.source}:2: context\n{self.source}:3: actual failure\n",),
                ("fuzz_test.go", None),
            ),
            (
                (f"{self.source}:2\n    {other}:3 +0x123\n",),
                ("fuzz_test.go", None),
            ),
            (
                (f"{self.source}:1: context\n", f"{self.source}:1: failure\n"),
                ("fuzz_test.go", 1),
            ),
        ):
            with self.subTest(messages=messages):
                # GIVEN
                diagnostics = FailureDiagnostics(self.target, REPLAY)
                for message in messages[:-1]:
                    diagnostics.record(Event("output", PACKAGE, REPLAY, message))

                # WHEN
                diagnostics.record(Event("output", PACKAGE, REPLAY, messages[-1]))

                # THEN
                self.assertEqual("".join(diagnostics.lines), "".join(messages))
                self.assertEqual(diagnostics.location, expected)
