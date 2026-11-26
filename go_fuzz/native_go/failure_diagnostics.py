"""Collect attributable native failure diagnostics and locations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .event import Event
from .target import Target

SOURCE = re.compile(r"^(/.+?\.go):(\d+)(?::\d+)?:\s*.*$")
STACK = re.compile(r"^(/.+?\.go):(\d+)(?:\s+\+0x[0-9a-f]+)?$")
SEED_FAILURE = re.compile(r"^failure while testing seed corpus entry: ([^/]+)/([^/]+)$")
SAVED_FAILURE = re.compile(r"^    Failing input written to (.+)$")


@dataclass
class FailureDiagnostics:
    """Native failure context, without ranking individual log messages."""

    target: Target
    test: str
    references: set[str] = field(default_factory=set)
    lines: list[str] = field(default_factory=list)
    locations: dict[tuple[str, int], None] = field(default_factory=dict)
    fuzz_started: bool = False
    failure_summary: bool = False
    replay_failed: bool = False

    def _record_fuzz_line(self, raw: str) -> None:
        name = self.target.selector.name
        line = raw.rstrip("\r\n")

        # The coordinator announces its execution before reporting an input.
        # A message emitted during target setup is not such evidence.
        if line.startswith("fuzz: elapsed:") and any(
            marker in line
            for marker in (
                ", gathering baseline coverage:",
                ", testing seed corpus:",
                ", execs:",
            )
        ):
            self.fuzz_started = True

        if not self.fuzz_started:
            return

        seed = SEED_FAILURE.fullmatch(line)
        if seed and seed[1] == name and not self.failure_summary:
            self.references.add(seed[2])
            self._record_diagnostic_line(raw)

        if line.startswith(f"--- FAIL: {name} ("):
            self.failure_summary = True

        if not self.failure_summary:
            return

        saved = SAVED_FAILURE.fullmatch(line)
        if saved:
            path = Path(saved[1])
            if (
                path.parent == Path("testdata/fuzz") / name
                or path.parent == self.target.seed_directory
            ):
                self.references.add(path.name)

        self._record_diagnostic_line(raw)

    def _record_diagnostic_line(self, line: str) -> None:
        self.lines.append(line)

        match = SOURCE.fullmatch(line.strip()) or STACK.fullmatch(line.strip())
        if match:
            location = self.target.resolve_source_location(match[1], int(match[2]))
            if location is not None:
                self.locations[location] = None

    def record(self, event: Event) -> None:
        name = self.target.selector.name
        if self.test == name:
            if event.action == "output" and event.test == name:
                for line in event.output.splitlines(keepends=True):
                    self._record_fuzz_line(line)
            return

        if event.action == "fail" and event.test == self.test:
            self.replay_failed = True

        # A replay panic may be emitted under the parent after the subtest fails.
        if (
            event.action == "output"
            and event.test is not None
            and (
                event.test == self.test
                or event.test.startswith(self.test + "/")
                or (self.replay_failed and event.test == name)
            )
        ):
            for line in event.output.splitlines(keepends=True):
                self._record_diagnostic_line(line)

    @property
    def location(self) -> tuple[str, int | None] | None:
        if not self.locations:
            return None

        uri, line = next(iter(self.locations))

        # Use an actual diagnostic file as an anchor, not a guessed cause.
        return uri, line if len(self.locations) == 1 else None
