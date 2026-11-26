"""Validated exact package and fuzz function selection."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .error import NativeGoError

# Native source seeds use this reference rather than a corpus filename.
SEED_NAME = re.compile(r"seed#[0-9]+")


@dataclass(frozen=True)
class TargetSelector:
    """A validated, exact package and fuzz function selection."""

    package: str
    name: str

    def __post_init__(self) -> None:
        package, target = self.package, self.name

        # Enforce the single-package and safe-path contract, not Go's grammar.
        if (
            package.startswith("-")
            or "..." in package
            or any(part in {"", ".", ".."} for part in package.split("/"))
            or any(char in package for char in ("\\", "\0", "\r", "\n"))
            or package in {"all", "std", "cmd"}
        ):
            raise NativeGoError("Package must be one exact Go import path")

        if not target.startswith("Fuzz") or any(
            char in target for char in ("/", "\\", "\0", "\r", "\n")
        ):
            raise NativeGoError("Target must be one exact Go fuzz function name")

    def build_test_pattern(self, reference: str | None = None) -> str:
        pattern = f"^{re.escape(self.name)}$"

        if reference is not None:
            pattern += f"/^{re.escape(reference)}$"

        return pattern
