"""Classify the native completion evidence independently of diagnostics."""

import unittest

from go_fuzz.native_go.completion_evidence import CompletionEvidence
from go_fuzz.native_go.error import NativeGoError
from go_fuzz.native_go.event import Event

PACKAGE = "example.com/a"
TARGET = "FuzzA"
REPLAY = "FuzzA/input"


class TestCompletionEvidence(unittest.TestCase):
    def test_completed_test_agrees_with_process_result(self):
        for test in (TARGET, REPLAY):
            for status, code, failed in (("pass", 0, False), ("fail", 1, True)):
                with self.subTest(test=test, status=status):
                    # GIVEN
                    evidence = CompletionEvidence(test, TARGET)
                    evidence.record(Event("run", PACKAGE, test))
                    evidence.record(Event(status, PACKAGE, test))
                    if test != TARGET:
                        evidence.record(Event(status, PACKAGE, TARGET))
                    evidence.record(Event(status, PACKAGE))

                    # WHEN
                    result = evidence.determine_failure(code)

                    # THEN
                    self.assertEqual(result, failed)

    def test_requires_exactly_one_execution_of_requested_test(self):
        for test, runs in (
            (TARGET, ("FuzzAOther",)),
            (TARGET, (TARGET, TARGET)),
            (REPLAY, (TARGET,)),
            (REPLAY, (REPLAY, REPLAY)),
        ):
            with self.subTest(test=test, runs=runs):
                # GIVEN
                evidence = CompletionEvidence(test, TARGET)
                for name in runs:
                    evidence.record(Event("run", PACKAGE, name))
                evidence.record(Event("fail", PACKAGE, test))
                if test != TARGET:
                    evidence.record(Event("fail", PACKAGE, TARGET))
                evidence.record(Event("output", PACKAGE, output="exit status 1\n"))
                evidence.record(
                    Event("output", PACKAGE, output=f"FAIL\t{PACKAGE}\t0s\n")
                )
                evidence.record(Event("fail", PACKAGE))

                # WHEN / THEN
                with self.assertRaisesRegex(NativeGoError, "not executed exactly once"):
                    evidence.determine_failure(1)

    def test_requires_consistent_terminal_events_and_exit_code(self):
        for test_status, target_status, package_status, code in (
            ("pass", "pass", "fail", 1),
            ("skip", "skip", "pass", 0),
            ("fail", "fail", "fail", 0),
            ("fail", "fail", "fail", 2),
            (None, "fail", "fail", 1),
            ("fail", None, "fail", 1),
            ("fail", "fail", None, 1),
            ("fail", "pass", "fail", 1),
        ):
            with self.subTest(
                test=test_status,
                target=target_status,
                package=package_status,
                code=code,
            ):
                # GIVEN
                evidence = CompletionEvidence(REPLAY, TARGET)
                evidence.record(Event("run", PACKAGE, REPLAY))
                for name, status in (
                    (REPLAY, test_status),
                    (TARGET, target_status),
                    (None, package_status),
                ):
                    if status is not None:
                        evidence.record(Event(status, PACKAGE, name))

                # WHEN / THEN
                with self.assertRaisesRegex(
                    NativeGoError, "Incomplete or inconsistent"
                ):
                    evidence.determine_failure(code)

    def test_rejects_relevant_events_after_package_completion(self):
        # GIVEN
        evidence = CompletionEvidence(TARGET, TARGET)
        evidence.record(Event("run", PACKAGE, TARGET))
        evidence.record(Event("pass", PACKAGE, TARGET))
        evidence.record(Event("pass", PACKAGE))

        # WHEN / THEN
        with self.assertRaisesRegex(NativeGoError, "after Go package completion"):
            evidence.record(Event("output", PACKAGE, output="late output\n"))

    def test_rejects_failure_outside_requested_target(self):
        # GIVEN
        evidence = CompletionEvidence(TARGET, TARGET)
        evidence.record(Event("run", PACKAGE, TARGET))

        # WHEN / THEN
        with self.assertRaisesRegex(NativeGoError, "Unexpected failing Go test"):
            evidence.record(Event("fail", PACKAGE, "FuzzAOther"))

    def test_native_process_completion_must_agree_with_finding(self):
        for test, status, target_closed, expected_error in (
            (TARGET, None, True, False),
            (TARGET, "exit status 1", True, False),
            (TARGET, "exit status 2", True, True),
            (TARGET, "exit status 2", False, True),
            (TARGET, "signal: killed", True, True),
            (TARGET, "signal: terminated", False, True),
            (REPLAY, None, True, False),
            (REPLAY, "exit status 1", True, False),
            (REPLAY, "exit status 2", False, False),
            (REPLAY, "exit status 2", True, True),
            (REPLAY, "exit status 3", True, True),
            (REPLAY, "exit status 3", False, True),
            (REPLAY, "signal: killed", True, True),
            (REPLAY, "signal: aborted (core dumped)", False, True),
        ):
            with self.subTest(test=test, status=status, target_closed=target_closed):
                # GIVEN
                evidence = CompletionEvidence(test, TARGET)
                evidence.record(Event("run", PACKAGE, TARGET))
                if test == REPLAY:
                    evidence.record(Event("run", PACKAGE, REPLAY))
                    evidence.record(Event("fail", PACKAGE, REPLAY))
                if target_closed:
                    evidence.record(Event("fail", PACKAGE, TARGET))
                    evidence.record(Event("output", PACKAGE, output="FAIL\n"))
                elif test == REPLAY:
                    evidence.record(
                        Event("output", PACKAGE, TARGET, "panic: input failure\n")
                    )
                if status is not None:
                    evidence.record(
                        Event(
                            "output",
                            PACKAGE,
                            None if target_closed else TARGET,
                            f"{status}\n",
                        )
                    )
                if not target_closed:
                    evidence.record(Event("fail", PACKAGE, TARGET))
                evidence.record(
                    Event("output", PACKAGE, output=f"FAIL\t{PACKAGE}\t0s\n")
                )
                evidence.record(Event("fail", PACKAGE))

                if expected_error:
                    # WHEN / THEN
                    with self.assertRaisesRegex(
                        NativeGoError, "Abnormal native Go test process exit"
                    ):
                        evidence.determine_failure(1)
                else:
                    # WHEN
                    failed = evidence.determine_failure(1)

                    # THEN
                    self.assertTrue(failed)

    def test_ordinary_process_status_text_is_not_completion_evidence(self):
        for test in (TARGET, REPLAY):
            for status in ("exit status 2\n", "signal: killed\n"):
                with self.subTest(test=test, status=status):
                    # GIVEN
                    evidence = CompletionEvidence(test, TARGET)
                    evidence.record(Event("run", PACKAGE, test))
                    evidence.record(Event("output", PACKAGE, test, status))
                    evidence.record(
                        Event("output", PACKAGE, test, "ordinary diagnostic\n")
                    )
                    evidence.record(Event("fail", PACKAGE, test))
                    if test != TARGET:
                        evidence.record(Event("fail", PACKAGE, TARGET))
                    evidence.record(Event("output", PACKAGE, output="FAIL\n"))
                    evidence.record(Event("output", PACKAGE, output=status))
                    evidence.record(
                        Event(
                            "output", PACKAGE, output="ordinary teardown diagnostic\n"
                        )
                    )
                    evidence.record(
                        Event("output", PACKAGE, output=f"FAIL\t{PACKAGE}\t0s\n")
                    )
                    evidence.record(Event("fail", PACKAGE))

                    # WHEN
                    failed = evidence.determine_failure(1)

                    # THEN
                    self.assertTrue(failed)
