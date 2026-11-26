"""Flat corpus snapshots, membership and copy selection."""

import os
import tempfile
import unittest
from pathlib import Path

from go_fuzz.corpus.error import CorpusError
from go_fuzz.corpus.file import File
from go_fuzz.corpus.snapshot import Snapshot
from go_fuzz.filesystem import FilesystemError

NATIVE = b'go test fuzz v1\nstring("bad")\n'


class TestSnapshot(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.input = self.root / "input"
        self.input.mkdir()

    def test_load_accepts_absent_or_empty_corpus(self):
        for folder in (None, self.input):
            with self.subTest(folder=folder):
                # GIVEN
                # No corpus files are provided.

                # WHEN
                corpus = Snapshot.load(folder)

                # THEN
                self.assertEqual(list(corpus), [])

    def test_load_returns_all_flat_entries(self):
        # GIVEN
        first, second = self.input / "a", self.input / "b"
        first.write_bytes(NATIVE)
        second.write_bytes(b"opaque")

        # WHEN
        corpus = Snapshot.load(self.input)

        # THEN
        self.assertEqual(list(corpus), [File(first), File(second)])
        self.assertEqual(first.read_bytes(), NATIVE)
        self.assertEqual(second.read_bytes(), b"opaque")

    def test_resolve_input_directory_returns_absolute_path(self):
        # GIVEN
        relative = Path(os.path.relpath(self.input))

        # WHEN
        resolved = Snapshot.resolve_input_directory(relative)

        # THEN
        self.assertEqual(resolved, self.input)

    def test_resolve_input_directory_rejects_invalid_roots(self):
        # GIVEN
        file = self.root / "file"
        file.touch()
        alias = self.root / "alias"
        alias.symlink_to(self.input, target_is_directory=True)
        for path, error in (
            (file, CorpusError),
            (self.root / "missing", CorpusError),
            (alias, FilesystemError),
        ):
            # WHEN / THEN
            with self.subTest(path=path), self.assertRaises(error):
                Snapshot.resolve_input_directory(path)

    def test_load_rejects_invalid_roots(self):
        # GIVEN
        file = self.root / "file"
        file.touch()
        alias = self.root / "alias"
        alias.symlink_to(self.input, target_is_directory=True)
        for path, error in (
            (file, CorpusError),
            (self.root / "missing", CorpusError),
            (alias, FilesystemError),
        ):
            # WHEN / THEN
            with self.subTest(path=path), self.assertRaises(error):
                Snapshot.load(path)

    def test_load_propagates_invalid_entry(self):
        # GIVEN
        (self.input / "nested").mkdir()

        # WHEN / THEN
        with self.assertRaises(CorpusError):
            Snapshot.load(self.input)

    def test_copy_preserves_names_and_bytes_except_excluded_inputs(self):
        # GIVEN
        bad, good = self.input / "bad", self.input / "good"
        bad.write_bytes(NATIVE)
        good_bytes = NATIVE.replace(b"bad", b"good")
        good.write_bytes(good_bytes)
        bad_digest = File(bad).digest
        corpus = Snapshot.load(self.input)
        for name, options, expected in (
            ("all", {}, {"bad": NATIVE, "good": good_bytes}),
            ("filtered", {"excluded": {bad_digest}}, {"good": good_bytes}),
        ):
            with self.subTest(name=name):
                # GIVEN
                output = self.root / name

                # WHEN
                corpus.copy_to(output, **options)

                # THEN
                self.assertEqual(
                    {p.name: p.read_bytes() for p in output.iterdir()}, expected
                )
                self.assertEqual(bad.read_bytes(), NATIVE)
                self.assertEqual(good.read_bytes(), good_bytes)

    def test_copy_creates_empty_directory(self):
        # GIVEN
        corpus = Snapshot()
        output = self.root / "output"

        # WHEN
        corpus.copy_to(output)

        # THEN
        self.assertTrue(output.is_dir())
        self.assertEqual(list(output.iterdir()), [])

    def test_copy_rejects_symlink_directory(self):
        # GIVEN
        corpus = Snapshot()
        alias = self.root / "alias"
        alias.symlink_to(self.input, target_is_directory=True)

        # WHEN / THEN
        with self.assertRaisesRegex(FilesystemError, "symlink"):
            corpus.copy_to(alias / "new")

        # THEN
        self.assertEqual(list(self.input.iterdir()), [])
