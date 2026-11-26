"""Collect and evaluate native test completion evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .error import NativeGoError
from .event import Event

PROCESS_EXIT = re.compile(r"exit status ([0-9]+)\n")
PROCESS_SIGNAL = re.compile(r"signal: [^\n]+\n")


@dataclass
class CompletionEvidence:
    """Execution evidence, independent of finding diagnostics."""

    test: str
    target: str
    ran: int = 0
    test_status: list[str] = field(default_factory=list)
    target_status: list[str] = field(default_factory=list)
    package_status: list[str] = field(default_factory=list)

    _pending_abnormal_exit: bool = False
    _abnormal_exit: bool = False

    def record(self, event: Event) -> None:
        action, name = event.action, event.test

        if self.package_status:
            raise NativeGoError("Unexpected event after Go package completion")

        if action == "output":
            self._record_process_output(event)
            return

        # A native target failure may be flushed after the process status.
        if action != "fail" or name != self.target:
            self._pending_abnormal_exit = False

        if action == "run" and name == self.test:
            self.ran += 1

        if action not in {"pass", "fail", "skip"}:
            return

        if name == self.test:
            self.test_status.append(action)
        if name == self.target:
            self.target_status.append(action)
        if name is None:
            self.package_status.append(action)
        elif action == "fail" and not (
            name == self.target or name.startswith(self.target + "/")
        ):
            raise NativeGoError("Unexpected failing Go test")

    def _record_process_output(self, event: Event) -> None:
        # Only a status immediately preceding the native package summary is
        # process evidence, not arbitrary diagnostic text.
        if (
            self._pending_abnormal_exit
            and event.test is None
            and event.output.startswith(f"FAIL\t{event.package}\t")
        ):
            self._abnormal_exit = True

        self._pending_abnormal_exit = False
        if event.test not in {None, self.target}:
            return

        if PROCESS_SIGNAL.fullmatch(event.output):
            self._pending_abnormal_exit = True
            return

        status = PROCESS_EXIT.fullmatch(event.output)
        if status and status[1] != "1":
            # Go handles input panics during fuzzing itself. A replay panic
            # can exit with status 2 before Go reports the target completion.
            self._pending_abnormal_exit = (
                self.test == self.target or status[1] != "2" or bool(self.target_status)
            )

    def determine_failure(self, returncode: int) -> bool:
        if self._abnormal_exit:
            raise NativeGoError("Abnormal native Go test process exit")

        if self.ran != 1:
            raise NativeGoError("Requested Go test was not executed exactly once")

        if (
            returncode == 0
            and self.test_status
            == self.target_status
            == self.package_status
            == ["pass"]
        ):
            return False

        if (
            returncode == 1
            and self.test_status
            == self.target_status
            == self.package_status
            == ["fail"]
        ):
            return True

        raise NativeGoError("Incomplete or inconsistent native Go test result")
