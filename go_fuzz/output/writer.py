"""Persist complete session results, independently of the native Go runner."""

import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from ..config import Config, ResultsFormat
from ..fuzzing import SessionResult
from .error import OutputError
from .jsonl_report_writer import JsonlReportWriter
from .sarif_report_writer import SarifReportWriter


@dataclass(frozen=True)
class AnalysisResult:
    """Published report and corpus paths with the distinct finding count."""

    results_file: Path
    findings_count: int
    coverage_corpus: Path
    error_corpus: Path


class ResultWriter:
    """Persist a complete analysis in a fresh Action-owned result directory."""

    def __init__(self, config: Config) -> None:
        self._root = config.temporary_root
        self._path_guard = config.path_guard
        self._directory: Path | None = None
        self._writer = (
            SarifReportWriter()
            if config.results_format is ResultsFormat.SARIF
            else JsonlReportWriter()
        )

    @contextmanager
    def open(self) -> Iterator[Self]:
        if self._directory is not None:
            raise OutputError("Analysis result writer is already open")

        root = self._path_guard.resolve_directory(self._root)

        root.mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="go-fuzz-results-", dir=root))
        self._directory = directory

        try:
            yield self
        except BaseException:
            # Covers both output failures and failures while closing the session.
            shutil.rmtree(directory)
            raise
        finally:
            self._directory = None

    def write(self, result: SessionResult) -> AnalysisResult:
        directory = self._directory
        if directory is None:
            raise OutputError("Analysis result writer is not open")

        self._path_guard.resolve_path(directory)

        coverage = directory / "coverage"
        error = directory / "error"

        result.coverage.copy_to(coverage)
        result.findings.export_error_corpus(error)

        report = self._writer.write(directory, result.logs, result.findings)

        if report.parent != directory or not report.is_file(follow_symlinks=False):
            raise OutputError("Report must be a regular file in the output directory")

        self._path_guard.resolve_path(report)

        return AnalysisResult(
            results_file=report,
            findings_count=len(result.findings),
            coverage_corpus=coverage,
            error_corpus=error,
        )
