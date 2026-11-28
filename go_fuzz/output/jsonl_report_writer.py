"""Preserve native Go JSONL events in execution order."""

import shutil
from collections.abc import Iterable
from pathlib import Path

from ..fuzzing import Findings


class JsonlReportWriter:
    def write(self, directory: Path, logs: Iterable[Path], _findings: Findings) -> Path:
        """Stream original Go JSONL logs in execution order."""
        path = directory / "results.jsonl"

        with path.open("xb") as output:
            for stdout in logs:
                with stdout.open("rb") as stream:
                    shutil.copyfileobj(stream, output, length=1024 * 1024)

        return path
