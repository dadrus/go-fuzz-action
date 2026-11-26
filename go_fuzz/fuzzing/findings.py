"""Deduplicate findings and export the native error corpus."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ..filesystem import require_symlink_free_path
from ..native_go import Target
from .error import FuzzingError
from .finding import Finding


class Findings:
    """Deduplicate results without retaining corpus payloads."""

    def __init__(self, target: Target) -> None:
        self._target = target
        self._findings: dict[tuple[str, str], Finding] = {}

    @property
    def target(self) -> Target:
        return self._target

    def add(self, finding: Finding) -> None:
        if finding.target != self._target:
            raise FuzzingError("Finding belongs to a different target")

        self._findings.setdefault((finding.input_kind, finding.input_identity), finding)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self._findings.values())

    def __len__(self) -> int:
        return len(self._findings)

    def export_error_corpus(self, directory: Path) -> None:
        require_symlink_free_path(directory.absolute())
        directory.mkdir(parents=True, exist_ok=True)

        for finding in self:
            if finding.corpus is not None:
                finding.corpus.copy_to(directory / finding.input_identity)

    @property
    def file_hashes(self) -> set[str]:
        return {identity for kind, identity in self._findings if kind == "file"}
