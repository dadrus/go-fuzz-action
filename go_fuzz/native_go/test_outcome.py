"""Classify native test completion and associated diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .completion_evidence import CompletionEvidence
from .error import NativeGoError
from .event import TEST_EVIDENCE, parse_events
from .failure_diagnostics import FailureDiagnostics
from .target import Target


@dataclass(frozen=True)
class TestOutcome:
    """An unambiguously completed native test, not its mutable parser state."""

    failed: bool
    references: frozenset[str]
    message: str
    location: tuple[str, int | None] | None

    @classmethod
    def classify(
        cls,
        stdout: Path,
        returncode: int,
        target: Target,
        test: str,
    ) -> TestOutcome:
        selector = target.selector
        completion = CompletionEvidence(test, selector.name)

        for event in parse_events(stdout):
            action = event.action
            if action == "build-fail":
                raise NativeGoError("Native Go build failed")

            if action not in TEST_EVIDENCE:
                continue
            if event.package != selector.package:
                raise NativeGoError("Unexpected Go event package")

            completion.record(event)

        if not completion.determine_failure(returncode):
            return cls(False, frozenset(), "", None)

        # Only a failed run needs diagnostic text. Re-read its file rather than
        # collecting arbitrary output from successful runs in memory.
        diagnostics = FailureDiagnostics(target, test)
        for event in parse_events(stdout):
            diagnostics.record(event)

        return cls(
            True,
            frozenset(diagnostics.references),
            "".join(diagnostics.lines).strip(),
            diagnostics.location,
        )
