"""Validate symlink-free paths and protect roots from Action-owned writes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..errors import FuzzActionError


class FilesystemError(FuzzActionError):
    """A path violates a filesystem access or write protection invariant."""


def require_symlink_free_path(path: Path) -> None:
    """Reject symlinks in the supplied path or any of its ancestors."""
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise FilesystemError("Refusing access through a symlink")


@dataclass(frozen=True)
class WritePathGuard:
    """Guard writes against the supplied canonical protected roots."""

    protected: tuple[Path, ...]

    def resolve_path(self, path: Path) -> Path:
        if any(char in str(path) for char in ("\r", "\n", "\0")):
            raise FilesystemError("Invalid character in output path")

        absolute = path.absolute()
        try:
            resolved = path.resolve()
        except (OSError, ValueError, RuntimeError) as exc:
            raise FilesystemError("Could not resolve output path") from exc

        # On newer Python versions non-strict resolution can leave a symlink
        # loop unresolved rather than raising an exception.
        if any(part.is_symlink() for part in (resolved, *resolved.parents)):
            raise FilesystemError("Could not resolve output path")

        for root in self.protected:
            if absolute.is_relative_to(root) or resolved.is_relative_to(root):
                raise FilesystemError(
                    "Output path is inside the working tree or an input corpus"
                )

        if any(char in str(resolved) for char in ("\r", "\n", "\0")):
            raise FilesystemError("Invalid character in output path")

        return resolved

    def resolve_directory(self, path: Path) -> Path:
        directory = self.resolve_path(path)

        if any(
            part.exists() and not part.is_dir()
            for part in (directory, *directory.parents)
        ):
            raise FilesystemError("Temporary root must be a directory")

        return directory
