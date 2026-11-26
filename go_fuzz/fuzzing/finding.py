"""Finding identity and reproduction information."""

from __future__ import annotations

import hashlib
import shlex
from dataclasses import dataclass

from ..corpus import File
from ..native_go import SEED_NAME, Target, TestOutcome
from .error import FuzzingError


@dataclass(frozen=True)
class Finding:
    target: Target
    reference: str
    message: str
    location: tuple[str, int | None] | None
    corpus: File | None = None

    def __post_init__(self) -> None:
        if self.corpus is None:
            if not SEED_NAME.fullmatch(self.reference):
                raise FuzzingError(
                    "Finding without a file requires a native seed reference"
                )
        elif self.reference != self.corpus.path.name:
            raise FuzzingError("Finding reference does not identify its corpus file")

    @classmethod
    def from_outcome(
        cls,
        target: Target,
        reference: str,
        outcome: TestOutcome,
        corpus: File | None,
    ) -> Finding:
        return cls(
            target,
            reference,
            outcome.message or f"--- FAIL: {target.selector.name}/{reference}",
            outcome.location,
            corpus,
        )

    @property
    def input_kind(self) -> str:
        return "file" if self.corpus is not None else "seed"

    @property
    def input_identity(self) -> str:
        return self.corpus.digest if self.corpus is not None else self.reference

    @property
    def key(self) -> tuple[str, str, str, str]:
        selector = self.target.selector

        return selector.package, selector.name, self.input_kind, self.input_identity

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256("\0".join(self.key).encode("utf-8")).hexdigest()

    @property
    def reproduction_command(self) -> str:
        selector = self.target.selector

        return shlex.join(
            [
                "go",
                "test",
                "-count=1",
                "-run",
                selector.build_test_pattern(self.input_identity),
                selector.package,
            ]
        )
