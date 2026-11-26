"""Opaque native input, content identity and replay staging."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from ..filesystem import require_symlink_free_path
from ..native_go import SEED_NAME
from .error import CorpusError


@dataclass(frozen=True)
class File:
    """A validated Go fuzzing corpus file identified by its content hash."""

    path: Path
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        path = self.path.absolute()
        object.__setattr__(self, "path", path)

        # The name is also an unchanged native Go subtest reference.
        if (
            not re.fullmatch(r"[A-Za-z0-9_.+#-]+", path.name)
            or path.name in {".", ".."}
            or SEED_NAME.fullmatch(path.name)
        ):
            raise CorpusError("Invalid or ambiguous corpus filename")

        with self._open() as stream:
            digest = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)

        object.__setattr__(self, "digest", digest.hexdigest())

    @contextmanager
    def _open(self) -> Iterator[BinaryIO]:
        require_symlink_free_path(self.path)

        # Reject special files without blocking on FIFOs. Go owns the contents.
        # Concurrent runner manipulation is out of scope.
        # Let open() own the descriptor even if constructing the stream fails.
        try:
            # The context below keeps open-error translation separate from reads.
            stream = open(  # noqa: SIM115 -- managed by with stream below
                self.path,
                "rb",
                opener=lambda path, flags: os.open(
                    path, flags | os.O_NOFOLLOW | os.O_NONBLOCK
                ),
            )
        except OSError as exc:
            raise CorpusError("Cannot read native corpus file") from exc

        with stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise CorpusError("Corpus entry is not a regular file")
            yield stream

    def copy_to(self, destination: Path) -> None:
        """Copy without overwriting another input or following a symlink."""
        require_symlink_free_path(destination.parent.absolute())

        digest = hashlib.sha256()

        output = destination.open("xb")
        try:
            with output:
                with self._open() as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        output.write(block)
                        digest.update(block)

                if digest.hexdigest() != self.digest:
                    raise CorpusError("Native corpus bytes changed since loading")
        except BaseException:
            destination.unlink(missing_ok=True)
            raise

    @contextmanager
    def stage_for_replay(self, seed_directory: Path) -> Iterator[Path]:
        """Allocate a temporary replay seed without touching existing seeds."""
        if not seed_directory.is_dir():
            require_symlink_free_path(seed_directory.absolute())
            seed_directory.mkdir(parents=True, exist_ok=True)

        for index in range(1000):
            path = seed_directory / f"go_fuzz_action_{self.digest[:24]}_{index}"

            try:
                self.copy_to(path)
            except FileExistsError:
                continue

            try:
                yield path
            finally:
                path.unlink(missing_ok=True)
            return

        raise CorpusError("Could not allocate a temporary replay filename")
