"""Native corpus files and flat corpus snapshots."""

from .error import CorpusError
from .file import File
from .snapshot import Snapshot

__all__ = [
    "CorpusError",
    "File",
    "Snapshot",
]
