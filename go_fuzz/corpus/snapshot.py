"""Validated flat, file-backed corpus snapshots."""

from collections.abc import Iterator, Set
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from ..filesystem import require_symlink_free_path
from .error import CorpusError
from .file import File


@dataclass(frozen=True)
class Snapshot:
    """A snapshot of validated Go corpus files at loading time, not their bytes."""

    entries: tuple[File, ...] = ()

    @staticmethod
    def resolve_input_directory(folder: Path) -> Path:
        root = folder.absolute()
        require_symlink_free_path(root)

        if not root.is_dir():
            raise CorpusError("Corpus input must be a real, readable directory")

        return root.resolve()

    @classmethod
    def load(cls, folder: Path | None) -> Self:
        if folder is None:
            return cls()

        root = folder.absolute()
        require_symlink_free_path(root)

        try:
            paths = sorted(root.iterdir())
        except OSError as exc:
            raise CorpusError(
                "Corpus input must be a real, readable directory"
            ) from exc

        return cls(tuple(File(path) for path in paths))

    def __iter__(self) -> Iterator[File]:
        return iter(self.entries)

    def copy_to(
        self,
        directory: Path,
        *,
        excluded: Set[str] = frozenset(),
    ) -> None:
        require_symlink_free_path(directory.absolute())
        directory.mkdir(parents=True, exist_ok=True)

        for entry in self:
            if entry.digest not in excluded:
                entry.copy_to(directory / entry.path.name)
