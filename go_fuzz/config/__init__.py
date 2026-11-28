"""Immutable, validated analysis configuration and resolved execution paths."""

import os
import tempfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from ..corpus import Snapshot
from ..errors import FuzzActionError
from ..filesystem import WritePathGuard
from ..native_go import TargetSelector


class ConfigError(FuzzActionError):
    """An invalid analysis configuration value."""


class ResultsFormat(StrEnum):
    """Supported formats for the generated analysis report."""

    JSONL = "jsonl"
    SARIF = "sarif"


@dataclass(frozen=True)
class Config:
    """Immutable single-target analysis configuration with resolved paths."""

    workspace: Path
    package: str
    target: str
    fuzztime: str = "30s"
    results_format: ResultsFormat = ResultsFormat.JSONL
    coverage_corpus: Path | None = None
    error_corpus: Path | None = None
    selector: TargetSelector = field(init=False)
    temporary_root: Path = field(init=False)
    path_guard: WritePathGuard = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        selector = TargetSelector(self.package, self.target)

        # Go owns the actual fuzz budget syntax.
        if "\0" in self.fuzztime:
            raise ConfigError("Invalid character in fuzztime")

        try:
            results_format = ResultsFormat(self.results_format)
        except ValueError as exc:
            raise ConfigError("results-format must be jsonl or sarif") from exc

        try:
            workspace = self.workspace.resolve(strict=True)
        except (OSError, ValueError) as exc:
            raise ConfigError("Workspace is not a directory") from exc

        if not workspace.is_dir():
            raise ConfigError("Workspace is not a directory")

        object.__setattr__(self, "workspace", workspace)

        if self.coverage_corpus is not None:
            object.__setattr__(
                self,
                "coverage_corpus",
                Snapshot.resolve_input_directory(self.coverage_corpus),
            )

        if self.error_corpus is not None:
            object.__setattr__(
                self,
                "error_corpus",
                Snapshot.resolve_input_directory(self.error_corpus),
            )

        guard = WritePathGuard(
            tuple(
                path
                for path in (workspace, self.coverage_corpus, self.error_corpus)
                if path is not None
            ),
        )
        root = guard.resolve_directory(
            Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()),
        )

        object.__setattr__(self, "selector", selector)
        object.__setattr__(self, "results_format", results_format)
        object.__setattr__(self, "path_guard", guard)
        object.__setattr__(self, "temporary_root", root)


__all__ = ["Config", "ConfigError", "ResultsFormat"]
