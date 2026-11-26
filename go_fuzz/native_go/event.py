"""Parse the Go JSONL fields needed by classification."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .error import NativeGoError

TEST_EVIDENCE = {"run", "output", "pass", "fail", "skip"}


@dataclass(frozen=True)
class Event:
    """The validated fields needed to classify a native Go event."""

    action: str
    package: str | None = None
    test: str | None = None
    output: str = ""


def parse_events(path: Path) -> Iterator[Event]:
    with path.open("rb") as stream:
        for number, line in enumerate(stream, 1):
            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    raise ValueError("not an object")

                action = event.get("Action")
                if not isinstance(action, str) or not action:
                    raise ValueError("missing or invalid action")

                if action not in TEST_EVIDENCE:
                    yield Event(action)
                    continue

                package = event.get("Package")
                if not isinstance(package, str):
                    raise ValueError("missing or invalid package")

                name = event.get("Test")
                if "Test" in event and not isinstance(name, str):
                    raise ValueError("invalid test name")

                output = event.get("Output") if action == "output" else ""
                if not isinstance(output, str):
                    raise ValueError("invalid output event")
            except (ValueError, TypeError, UnicodeError) as exc:
                raise NativeGoError(f"Invalid Go JSONL event at line {number}") from exc

            yield Event(action, package, name, output)
