"""Validate Action-owned output paths at the write boundary."""

import os
import tempfile
import unittest
from pathlib import Path

from go_fuzz.filesystem.paths import (
    FilesystemError,
    WritePathGuard,
    require_symlink_free_path,
)


class TestWritePathGuard(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.protected = self.root / "protected"
        self.protected.mkdir()
        self.guard = WritePathGuard((self.protected,))

    def test_resolves_allowed_paths_without_creating_them(self):
        # GIVEN
        outside = self.root / "outside"
        outside.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(outside, target_is_directory=True)
        for path in (alias / "report", Path(os.path.relpath(outside / "report"))):
            with self.subTest(path=path):
                # WHEN
                resolved = self.guard.resolve_path(path)

                # THEN
                self.assertEqual(resolved, outside / "report")
                self.assertFalse(resolved.exists())

    def test_rejects_direct_and_symlink_resolved_protected_destinations(self):
        # GIVEN
        original = self.protected / "original"
        original.write_text("original")
        alias = self.root / "alias"
        alias.symlink_to(self.protected, target_is_directory=True)
        outside = self.root / "outside"
        outside.mkdir()
        outward = self.protected / "outward"
        outward.symlink_to(outside, target_is_directory=True)
        for path in (original, self.protected / "new", alias / "new", outward / "new"):
            # WHEN / THEN
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(FilesystemError, "inside"),
            ):
                self.guard.resolve_path(path)

        # THEN
        self.assertEqual(original.read_text(), "original")
        self.assertFalse((self.protected / "new").exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_rejects_invalid_characters_in_original_or_resolved_path(self):
        # GIVEN
        alias = self.root / "alias"
        alias.symlink_to(self.root / "report\nextra")
        for path in (
            alias,
            self.root / "report\nfoo",
            self.root / "report\rfoo",
            self.root / "report\0foo",
        ):
            # WHEN / THEN
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(FilesystemError, "Invalid character"),
            ):
                self.guard.resolve_path(path)

    def test_rejects_unresolvable_symlink_loop(self):
        # GIVEN
        loop = self.root / "loop"
        loop.symlink_to(loop)

        # WHEN / THEN
        with self.assertRaisesRegex(FilesystemError, "Could not resolve output path"):
            self.guard.resolve_path(loop)

    def test_resolve_directory_accepts_existing_or_new_directory(self):
        # GIVEN
        directory = self.root / "directory"
        directory.mkdir()
        for path in (directory, directory / "new"):
            with self.subTest(path=path):
                # WHEN
                result = self.guard.resolve_directory(path)

                # THEN
                self.assertEqual(result, path)
                self.assertFalse((directory / "new").exists())

    def test_resolve_directory_rejects_non_directory_components(self):
        # GIVEN
        file = self.root / "file"
        file.touch()
        for path in (file, file / "nested"):
            # WHEN / THEN
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(
                    FilesystemError, "Temporary root must be a directory"
                ),
            ):
                self.guard.resolve_directory(path)


class TestSymlinkFreePath(unittest.TestCase):
    def test_accepts_symlink_free_paths_even_if_not_yet_created(self):
        with tempfile.TemporaryDirectory() as directory:
            # GIVEN
            root = Path(directory)
            source = root / "source"
            source.touch()
            for path in (root, source, root / "new" / "file"):
                with self.subTest(path=path):
                    # WHEN
                    require_symlink_free_path(path)

                    # THEN
                    self.assertEqual(list(root.iterdir()), [source])

    def test_rejects_symlink_leaf_or_ancestor_even_if_dangling(self):
        with tempfile.TemporaryDirectory() as directory:
            # GIVEN
            root = Path(directory)
            folder = root / "folder"
            folder.mkdir()
            source = folder / "source"
            source.touch()
            linked = root / "linked"
            linked.symlink_to(source)
            alias = root / "alias"
            alias.symlink_to(folder, target_is_directory=True)
            dangling = root / "dangling"
            dangling.symlink_to(root / "missing")
            loop = root / "loop"
            loop.symlink_to(loop)
            for path in (
                linked,
                alias,
                alias / "source",
                dangling,
                dangling / "new",
                loop,
            ):
                # WHEN / THEN
                with (
                    self.subTest(path=path),
                    self.assertRaisesRegex(FilesystemError, "symlink"),
                ):
                    require_symlink_free_path(path)
