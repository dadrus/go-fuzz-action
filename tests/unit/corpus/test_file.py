"""Native file identity, safe copying and replay staging."""

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from textwrap import dedent

from go_fuzz.corpus.error import CorpusError
from go_fuzz.corpus.file import File
from go_fuzz.filesystem import FilesystemError

NATIVE = b'go test fuzz v1\nstring("bad")\n'


class TestFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.input = self.root / "input"
        self.input.mkdir()
        self.project = self.root / "project"
        self.project.mkdir()
        self.seeds = self.project / "testdata/fuzz/FuzzA"

    def test_hashes_opaque_native_bytes(self):
        for content in (b"", b"not a Go corpus", b"go test fuzz v1\n"):
            with self.subTest(content=content):
                # GIVEN
                path = self.input / "entry"
                path.write_bytes(content)

                # WHEN
                entry = File(path)

                # THEN
                self.assertEqual(entry.digest, hashlib.sha256(content).hexdigest())
                self.assertEqual(path.read_bytes(), content)

    def test_rejects_non_regular_or_missing_file(self):
        # GIVEN
        directory = self.input / "directory"
        directory.mkdir()
        fifo = self.input / "fifo"
        os.mkfifo(fifo)
        for path in (directory, fifo, self.input / "missing"):
            # WHEN / THEN
            with self.subTest(path=path), self.assertRaises(CorpusError):
                File(path)

    def test_rejected_directory_does_not_leak_descriptor(self):
        # GIVEN
        directory = self.input / "directory"
        directory.mkdir()
        script = dedent("""\
            import os
            import sys
            from pathlib import Path
            from go_fuzz.corpus.file import File
            from go_fuzz.corpus.error import CorpusError

            before = len(os.listdir("/proc/self/fd"))
            try:
                File(Path(sys.argv[1]))
            except CorpusError:
                pass
            else:
                raise AssertionError("Directory was accepted as a corpus file")
            print(len(os.listdir("/proc/self/fd")) - before)
            """)

        # WHEN
        completed = subprocess.run(
            [sys.executable, "-E", "-c", script, str(directory)],
            cwd=Path(__file__).resolve().parents[3],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

        # THEN
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(int(completed.stdout), 0)

    def test_rejects_ambiguous_or_unsafe_filename(self):
        for name in ("seed#0", "with space", "line\nbreak"):
            with self.subTest(name=name):
                # GIVEN
                path = self.input / name
                path.write_bytes(NATIVE)

                # WHEN / THEN
                with self.assertRaisesRegex(
                    CorpusError, "Invalid or ambiguous corpus filename"
                ):
                    File(path)

    def test_rejects_symlink_file(self):
        # GIVEN
        source = self.input / "source"
        source.write_bytes(NATIVE)
        linked = self.input / "linked"
        linked.symlink_to(source)

        # WHEN / THEN
        with self.assertRaisesRegex(FilesystemError, "symlink"):
            File(linked)

        # THEN
        self.assertEqual(source.read_bytes(), NATIVE)

    def test_copy_preserves_existing_destination(self):
        # GIVEN
        source = self.input / "old"
        source.write_bytes(NATIVE)
        entry = File(source)
        destination = self.root / "destination"
        destination.write_bytes(b"existing")

        # WHEN / THEN
        with self.assertRaises(FileExistsError):
            entry.copy_to(destination)

        # THEN
        self.assertEqual(destination.read_bytes(), b"existing")
        self.assertEqual(source.read_bytes(), NATIVE)

    def test_copy_preserves_bytes(self):
        # GIVEN
        source = self.input / "old"
        source.write_bytes(NATIVE)
        entry = File(source)
        destination = self.root / "copy"

        # WHEN
        entry.copy_to(destination)

        # THEN
        self.assertEqual(destination.read_bytes(), NATIVE)
        self.assertEqual(source.read_bytes(), NATIVE)

    def test_stream_hash_does_not_load_entire_payload(self):
        # GIVEN
        path = self.input / "large"
        with path.open("wb") as stream:
            stream.write(b'go test fuzz v1\nstring("')
            for _ in range(24):
                stream.write(b"a" * 1024 * 1024)
            stream.write(b'")\n')
        # Measure in a fresh interpreter without affecting an external tracer.
        script = dedent("""\
            import sys
            import tracemalloc
            from pathlib import Path
            from go_fuzz.corpus.file import File

            path = Path(sys.argv[1])
            tracemalloc.start()
            File(path)
            print(tracemalloc.get_traced_memory()[1])
            """)

        # WHEN
        completed = subprocess.run(
            [sys.executable, "-E", "-c", script, str(path)],
            cwd=Path(__file__).resolve().parents[3],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

        # THEN
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertLess(int(completed.stdout), 5 * 1024 * 1024)

    def test_replay_staging_preserves_existing_files_and_cleans_up(self):
        # GIVEN
        entry = self.input / "original"
        entry.write_bytes(NATIVE)
        corpus = File(entry)
        self.seeds.mkdir(parents=True)
        original = self.seeds / f"go_fuzz_action_{corpus.digest[:24]}_0"
        original.write_bytes(b"existing")

        # WHEN / THEN
        with (
            self.assertRaisesRegex(RuntimeError, "abort"),
            corpus.stage_for_replay(self.seeds) as staged,
        ):
            # THEN
            self.assertNotEqual(staged, original)
            self.assertEqual(staged.read_bytes(), NATIVE)

            # Simulate an aborted replay.
            raise RuntimeError("abort")

        # THEN
        self.assertEqual(list(self.seeds.iterdir()), [original])
        self.assertEqual(original.read_bytes(), b"existing")

    def test_staging_rejects_symlink_directory(self):
        # GIVEN
        self.seeds.parent.mkdir(parents=True)
        self.seeds.symlink_to(self.input, target_is_directory=True)
        source = self.root / "old"
        source.write_bytes(NATIVE)

        entry = File(source)

        # WHEN / THEN
        with self.assertRaises(FilesystemError), entry.stage_for_replay(self.seeds):
            self.fail("Must not stage outside the project")

        # THEN
        self.assertEqual(list(self.input.iterdir()), [])

    def test_copy_rejects_changed_bytes_and_removes_incomplete_output(self):
        # GIVEN
        source = self.input / "old"
        source.write_bytes(NATIVE)
        entry = File(source)
        changed = NATIVE.replace(b"bad", b"new")
        source.write_bytes(changed)
        destination = self.root / "copy"

        # WHEN / THEN
        with self.assertRaisesRegex(CorpusError, "changed"):
            entry.copy_to(destination)

        # THEN
        self.assertFalse(destination.exists())
        self.assertEqual(source.read_bytes(), changed)

    def test_copy_removes_incomplete_output_when_close_fails(self):
        # GIVEN
        source = self.input / "old"
        source.write_bytes(NATIVE)
        destination = self.root / "copy"
        # A small buffered write fails on close under this file size limit.
        # Change the resource limit and signal handler only in a child process.
        script = dedent("""\
            import errno
            import os
            import resource
            import signal
            import sys
            from pathlib import Path
            from go_fuzz.corpus.file import File

            entry = File(Path(sys.argv[1]))
            before = len(os.listdir("/proc/self/fd"))
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, hard))
            try:
                entry.copy_to(Path(sys.argv[2]))
            except OSError as exc:
                if exc.errno != errno.EFBIG:
                    raise
            else:
                raise AssertionError("File size limit did not cause a write error")
            print(len(os.listdir("/proc/self/fd")) - before)
            """)

        # WHEN
        completed = subprocess.run(
            [sys.executable, "-E", "-c", script, str(source), str(destination)],
            cwd=Path(__file__).resolve().parents[3],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

        # THEN
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(int(completed.stdout), 0)
        self.assertFalse(destination.exists())
        self.assertEqual(source.read_bytes(), NATIVE)

    def test_copy_rejects_symlink_destination_parent(self):
        # GIVEN
        source = self.input / "old"
        source.write_bytes(NATIVE)
        entry = File(source)
        alias = self.root / "alias"
        alias.symlink_to(self.input, target_is_directory=True)

        # WHEN / THEN
        with self.assertRaisesRegex(FilesystemError, "symlink"):
            entry.copy_to(alias / "copy")

        # THEN
        self.assertEqual(list(self.input.iterdir()), [source])

    def test_replay_staging_removes_its_file_after_success(self):
        # GIVEN
        source = self.input / "old"
        source.write_bytes(NATIVE)
        entry = File(source)

        # WHEN
        with entry.stage_for_replay(self.seeds) as staged:
            # THEN
            self.assertEqual(staged.read_bytes(), NATIVE)

        self.assertFalse(staged.exists())
        self.assertEqual(source.read_bytes(), NATIVE)
