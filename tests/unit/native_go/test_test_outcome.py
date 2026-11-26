"""Stream and classify native JSONL without keeping all output."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from textwrap import dedent
from unittest.mock import patch

from go_fuzz.native_go.error import NativeGoError
from go_fuzz.native_go.target import Target
from go_fuzz.native_go.target_selector import TargetSelector
from go_fuzz.native_go.test_outcome import TestOutcome

PACKAGE = "example.com/project"


def write_events(path, *events):
    with path.open("wb") as stream:
        for event in events:
            stream.write(
                json.dumps(
                    {"Package": PACKAGE, **event},
                    separators=(",", ":"),
                ).encode()
                + b"\n"
            )
    return path


class TestTestOutcome(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / "events"
        self.target = Target(TargetSelector(PACKAGE, "FuzzA"), self.root, self.root)
        (self.root / "fuzz_test.go").write_text("package a\n")

    def outcome(self, code):
        return TestOutcome.classify(self.path, code, self.target, "FuzzA")

    def test_unknown_events_do_not_change_classification(self):
        # GIVEN
        write_events(
            self.path,
            {"Action": "run", "Test": "FuzzA"},
            {"Action": "future-event", "Package": "other", "Test": None},
            {"Action": "pass", "Test": "FuzzA"},
            {"Action": "pass"},
            {"Action": "future-summary"},
        )

        # WHEN
        outcome = self.outcome(0)

        # THEN
        self.assertEqual(outcome, TestOutcome(False, frozenset(), "", None))

    def test_foreign_package_evidence_is_rejected(self):
        # GIVEN
        write_events(self.path, {"Action": "run", "Package": "other", "Test": "FuzzA"})

        # WHEN / THEN
        with self.assertRaisesRegex(NativeGoError, "Unexpected Go event package"):
            self.outcome(0)

    def test_passed_outcome_does_not_collect_diagnostics(self):
        # GIVEN
        write_events(
            self.path,
            {"Action": "run", "Test": "FuzzA"},
            {"Action": "pass", "Test": "FuzzA"},
            {"Action": "pass"},
        )
        with patch(
            "go_fuzz.native_go.test_outcome.FailureDiagnostics",
            side_effect=AssertionError("Successful run needs no diagnostics"),
        ):
            # WHEN
            outcome = self.outcome(0)

        # THEN
        self.assertEqual(outcome, TestOutcome(False, frozenset(), "", None))

    def test_completed_failure_combines_completion_and_diagnostics(self):
        # GIVEN
        write_events(
            self.path,
            {"Action": "run", "Test": "FuzzA"},
            {
                "Action": "output",
                "Test": "FuzzA",
                "Output": "fuzz: elapsed: 0s, gathering baseline coverage: 0/1 completed\n",
            },
            {
                "Action": "output",
                "Test": "FuzzA",
                "Output": "failure while testing seed corpus entry: FuzzA/seed#0\n",
            },
            {
                "Action": "output",
                "Test": "FuzzA",
                "Output": "--- FAIL: FuzzA (0.01s)\n",
            },
            {
                "Action": "output",
                "Test": "FuzzA",
                "Output": f"    {self.root}/fuzz_test.go:1: failure\n",
            },
            {"Action": "fail", "Test": "FuzzA"},
            {"Action": "fail"},
        )

        # WHEN
        outcome = self.outcome(1)

        # THEN
        self.assertEqual(
            outcome,
            TestOutcome(
                True,
                frozenset({"seed#0"}),
                f"failure while testing seed corpus entry: FuzzA/seed#0\n--- FAIL: FuzzA (0.01s)\n    {self.root}/fuzz_test.go:1: failure",
                ("fuzz_test.go", 1),
            ),
        )

    def test_completion_error_is_propagated_without_diagnostics(self):
        # GIVEN
        write_events(self.path, {"Action": "future-event"}, {"Action": "pass"})
        # WHEN / THEN
        with (
            patch(
                "go_fuzz.native_go.test_outcome.FailureDiagnostics",
                side_effect=AssertionError("Incomplete run needs no diagnostics"),
            ),
            self.assertRaisesRegex(NativeGoError, "not executed exactly once"),
        ):
            self.outcome(0)

    def test_invalid_event_is_propagated(self):
        # GIVEN
        self.path.write_text("not JSONL\n")

        # WHEN / THEN
        with self.assertRaisesRegex(NativeGoError, "Invalid Go JSONL event"):
            self.outcome(0)

    def test_build_error_is_technical(self):
        # GIVEN
        write_events(self.path, {"Action": "build-fail", "ImportPath": PACKAGE})

        # WHEN / THEN
        with self.assertRaisesRegex(NativeGoError, "build failed"):
            self.outcome(1)

    def test_stream_large_event_log(self):
        # GIVEN
        with self.path.open("wb") as stream:
            line = (
                json.dumps(
                    {
                        "Package": PACKAGE,
                        "Action": "output",
                        "Test": "FuzzA",
                        "Output": "x" * 8192,
                    }
                ).encode()
                + b"\n"
            )
            stream.write(
                json.dumps(
                    {"Package": PACKAGE, "Action": "run", "Test": "FuzzA"}
                ).encode()
                + b"\n"
            )
            for _ in range(2048):
                stream.write(line)
            for event in ({"Action": "pass", "Test": "FuzzA"}, {"Action": "pass"}):
                stream.write(json.dumps({"Package": PACKAGE, **event}).encode() + b"\n")
        # Measure in a fresh interpreter without affecting an external tracer.
        script = dedent("""\
            import sys
            import tracemalloc
            from pathlib import Path
            from go_fuzz.native_go.target import Target
            from go_fuzz.native_go.target_selector import TargetSelector
            from go_fuzz.native_go.test_outcome import TestOutcome

            path = Path(sys.argv[1])
            selector = TargetSelector(sys.argv[2], sys.argv[3])
            target = Target(selector, path.parent, path.parent)
            tracemalloc.start()
            TestOutcome.classify(path, 0, target, selector.name)
            print(tracemalloc.get_traced_memory()[1])
            """)

        # WHEN
        completed = subprocess.run(
            [sys.executable, "-E", "-c", script, str(self.path), PACKAGE, "FuzzA"],
            cwd=Path(__file__).resolve().parents[3],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

        # THEN
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertLess(int(completed.stdout), 2 * 1024 * 1024)
