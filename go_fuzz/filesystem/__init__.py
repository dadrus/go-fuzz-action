"""Shared filesystem validation and Action-owned write protection."""

from .paths import FilesystemError, WritePathGuard, require_symlink_free_path

__all__ = [
    "FilesystemError",
    "WritePathGuard",
    "require_symlink_free_path",
]
