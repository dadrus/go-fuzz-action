"""Validate symlink-free paths and protect roots from Action-owned writes."""

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from ..errors import FuzzActionError


class FilesystemError(FuzzActionError):
    """A path violates a filesystem access or write protection invariant."""


def require_symlink_free_path(path: Path) -> None:
    """Reject symlinks in the supplied path or any of its ancestors."""
    for part in (*reversed(path.parents), path):
        try:
            mode = part.lstat().st_mode
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            raise FilesystemError("Could not inspect path for symlinks") from exc

        if stat.S_ISLNK(mode):
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
            resolved = Path(os.path.realpath(path, strict=os.path.ALLOW_MISSING))
        except NotADirectoryError as exc:
            raise FilesystemError("Output path has a non-directory component") from exc
        except (OSError, ValueError) as exc:
            raise FilesystemError("Could not resolve output path") from exc

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

        try:
            mode = directory.stat().st_mode
        except FileNotFoundError:
            return directory
        except OSError as exc:
            raise FilesystemError("Could not inspect temporary root") from exc

        if not stat.S_ISDIR(mode):
            raise FilesystemError("Temporary root must be a directory")

        return directory
