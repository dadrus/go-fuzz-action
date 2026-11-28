"""Test the session lifecycle, not the interpretation of native Go events."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from go_fuzz.config import Config
from go_fuzz.corpus import CorpusError, File
from go_fuzz.fuzzing.error import FuzzingError
from go_fuzz.fuzzing.session import Session, _resolve_failure_corpus_file
from go_fuzz.native_go import (
    NativeGoError,
    Target,
    TargetSelector,
    TestOutcome,
    TestResult,
)

PACKAGE = "example.com/project"
NATIVE = b'go test fuzz v1\nstring("bad")\n'
PASSED = TestOutcome(False, frozenset(), "", None)


class TestSession(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.project = self.root / "project"
        self.package = self.project / "nested"
        self.package.mkdir(parents=True)
        self.errors = self.root / "errors"
        self.coverage = self.root / "coverage"
        self.errors.mkdir()
        self.coverage.mkdir()

        self.enterContext(patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}))

        self.resolver = self.enterContext(
            patch("go_fuzz.fuzzing.session.Target.resolve", autospec=True),
        )
        self.resolver.side_effect = self.resolve_package

        self.runner_class = self.enterContext(
            patch("go_fuzz.fuzzing.session.Runner", autospec=True),
        )
        self.runner = self.runner_class.return_value
        self.runner.run.side_effect = self.run_test

        self.read_outcome = self.enterContext(
            patch("go_fuzz.fuzzing.session.TestOutcome.classify", return_value=PASSED),
        )

    def config(self, **overrides):
        return Config(
            **{
                "workspace": self.project,
                "package": PACKAGE,
                "target": "FuzzA",
                "fuzztime": "1s",
                "coverage_corpus": self.coverage,
                "error_corpus": self.errors,
                **overrides,
            },
        )

    def resolve_package(self, selector, project, env, logs):
        return Target(selector, project / "nested", project)

    def run_test(self, *arguments, code=0):
        logs = self.runner_class.call_args.args[2]
        stdout = logs / f"test-{self.runner.run.call_count}"
        stdout.write_bytes(b"native stdout")
        stderr = stdout.with_suffix(".stderr")
        stderr.touch()

        return TestResult(code, stdout, stderr)

    def test_resolution_failure_prevents_fuzzing_and_cleans_up(self):
        # GIVEN
        self.resolver.side_effect = NativeGoError("Package resolution failed")
        session = Session(self.config())

        # WHEN / THEN
        with (
            self.assertRaisesRegex(NativeGoError, "Package resolution failed"),
            session.run(),
        ):
            self.fail("Unresolved package must not start fuzzing")

        # THEN
        self.runner.run.assert_not_called()
        self.assertEqual(list(self.root.glob("go-fuzz-work-*")), [])

    def test_session_preserves_project_and_cleans_temporary_resources(self):
        # GIVEN
        (self.project / ".git").mkdir()
        (self.project / ".git/config").write_text("local configuration")
        (self.project / "file").write_text("original")
        (self.project / "link").symlink_to("file")

        session = Session(self.config())

        # WHEN
        with session.run() as result:
            # THEN
            target = result.findings.target
            work = target.project.parent

            self.assertEqual(target.directory, target.project / "nested")
            self.assertFalse((target.project / ".git").exists())
            self.assertEqual((target.project / "link").readlink(), Path("file"))
            self.assertEqual((target.project / "file").read_text(), "original")
            self.assertEqual(len(result.logs), 1)
            self.assertEqual(result.logs[0].read_bytes(), b"native stdout")
            self.assertEqual(len(result.findings), 0)
            self.assertEqual(self.runner_class.call_args.args[0], target.directory)

            selector, project, env, logs = self.resolver.call_args.args
            self.assertEqual(selector, target.selector)
            self.assertEqual(project, target.project)
            self.assertEqual(Path(env["GOCACHE"]), project.parent / "cache")
            self.assertEqual(logs, project.parent / "logs")

        self.assertFalse(work.exists())
        self.assertEqual((self.project / "file").read_text(), "original")
        self.assertTrue((self.project / ".git/config").exists())

    def test_cleanup_if_consumer_aborts(self):
        # GIVEN
        session = Session(self.config())

        # WHEN / THEN
        with self.assertRaisesRegex(RuntimeError, "abort"), session.run() as result:
            work = result.findings.target.project.parent
            # Simulate a consumer abort while the session is open.
            raise RuntimeError("abort")

        # THEN
        self.assertFalse(work.exists())

    def test_replay_retains_only_inputs_that_still_fail(self):
        # GIVEN
        original = self.errors / "old"
        original.write_bytes(NATIVE)

        for failed in (False, True):
            with self.subTest(failed=failed):
                self.runner.run.reset_mock()
                self.read_outcome.side_effect = [
                    TestOutcome(failed, frozenset(), "failure" if failed else "", None),
                    PASSED,
                ]

                staged_inputs = []

                def run(*arguments, failed=failed, staged_inputs=staged_inputs):
                    if "-fuzz" in arguments:
                        return self.run_test(*arguments)

                    directory = self.runner_class.call_args.args[0]
                    staged = next((directory / "testdata/fuzz/FuzzA").iterdir())
                    staged_inputs.append((staged.name, staged.read_bytes(), arguments))

                    return self.run_test(*arguments, code=int(failed))

                self.runner.run.side_effect = run
                session = Session(self.config())

                # WHEN
                with session.run() as result:
                    # THEN
                    self.assertEqual(len(staged_inputs), 1)
                    name, content, arguments = staged_inputs[0]
                    self.assertEqual(content, NATIVE)
                    self.assertEqual(arguments, ("-run", f"^FuzzA$/^{name}$"))
                    self.assertEqual(
                        [f.corpus for f in result.findings],
                        [File(original)] if failed else [],
                    )
                    self.assertEqual(len(result.logs), 2)
                    self.assertEqual(
                        list(result.findings.target.seed_directory.iterdir()), []
                    )

                self.assertEqual(self.runner.run.call_count, 2)
                self.assertEqual(original.read_bytes(), NATIVE)
                self.assertEqual(list(self.root.glob("go-fuzz-work-*")), [])

    def test_incomplete_replay_prevents_exploration(self):
        # GIVEN
        original = self.errors / "old"
        original.write_bytes(NATIVE)
        self.read_outcome.side_effect = NativeGoError("Incomplete replay")

        session = Session(self.config())

        # WHEN / THEN
        with (
            self.assertRaisesRegex(NativeGoError, "Incomplete replay"),
            session.run(),
        ):
            self.fail("Incomplete replay must not produce a result")

        # THEN
        self.assertEqual(self.runner.run.call_count, 1)
        self.assertEqual(original.read_bytes(), NATIVE)
        self.assertEqual(list(self.root.glob("go-fuzz-work-*")), [])

    def test_fuzz_findings_are_retained_without_replay(self):
        # GIVEN
        seeds = self.package / "testdata/fuzz/FuzzA"
        seeds.mkdir(parents=True)
        (seeds / "abc").write_bytes(NATIVE)
        self.runner.run.side_effect = lambda *args: self.run_test(*args, code=1)

        for reference, kind in (("abc", "file"), ("seed#0", "seed")):
            with self.subTest(reference=reference):
                self.runner.run.reset_mock()
                self.read_outcome.return_value = TestOutcome(
                    True, frozenset({reference}), "failure", None
                )

                session = Session(self.config())

                # WHEN
                with session.run() as result:
                    # THEN
                    self.assertEqual(
                        [(f.reference, f.input_kind) for f in result.findings],
                        [(reference, kind)],
                    )
                    self.assertEqual(len(result.logs), 1)

                self.assertEqual(self.runner.run.call_count, 1)
                self.assertEqual(list(seeds.iterdir()), [seeds / "abc"])

    def test_unattributable_fuzz_failure_is_technical(self):
        # GIVEN
        self.runner.run.side_effect = lambda *args: self.run_test(*args, code=1)
        for references in (
            frozenset(),
            frozenset({"seed#0", "seed#1"}),
        ):
            with self.subTest(references=references):
                self.read_outcome.return_value = TestOutcome(
                    True, references, "failure", None
                )

                session = Session(self.config())

                # WHEN / THEN
                with (
                    self.assertRaisesRegex(
                        FuzzingError, "without one attributable input or seed"
                    ),
                    session.run(),
                ):
                    self.fail("Unattributable failure must not produce a result")

                # THEN
                self.assertEqual(list(self.root.glob("go-fuzz-work-*")), [])

    def test_failure_reference_resolution_error_prevents_publication(self):
        # GIVEN
        self.read_outcome.return_value = TestOutcome(
            True, frozenset({"missing"}), "failure", None
        )
        session = Session(self.config())

        # WHEN / THEN
        with (
            patch(
                "go_fuzz.fuzzing.session._resolve_failure_corpus_file",
                side_effect=CorpusError("Could not resolve failure reference"),
            ),
            self.assertRaisesRegex(CorpusError, "Could not resolve failure reference"),
            session.run(),
        ):
            self.fail("Unresolved failure reference must not produce a result")

        # THEN
        self.assertEqual(list(self.root.glob("go-fuzz-work-*")), [])

    def test_workspace_copy_error_prevents_execution_and_cleans_up(self):
        # GIVEN
        session = Session(self.config())

        # WHEN / THEN
        with (
            patch(
                "go_fuzz.fuzzing.session.shutil.copytree",
                side_effect=OSError("copy failed"),
            ),
            self.assertRaisesRegex(FuzzingError, "Could not copy project workspace"),
            session.run(),
        ):
            self.fail("Failed workspace copy must not produce a result")

        # THEN
        self.resolver.assert_not_called()
        self.runner.run.assert_not_called()
        self.assertEqual(list(self.root.glob("go-fuzz-work-*")), [])

    def test_budget_is_one_argument_and_worker_count_is_native(self):
        # GIVEN
        self.read_outcome.side_effect = NativeGoError("Invalid budget")
        self.runner.run.side_effect = lambda *args: self.run_test(*args, code=1)

        session = Session(self.config(fuzztime="-run=.*"))

        # WHEN / THEN
        with self.assertRaisesRegex(NativeGoError, "Invalid budget"), session.run():
            self.fail("Invalid budget must be a technical error")

        # THEN
        self.runner.run.assert_called_once_with(
            "-run", "^$", "-fuzz", "^FuzzA$", "-fuzztime=-run=.*"
        )

    def test_coverage_excludes_known_and_new_failures_and_preserves_inputs(self):
        # GIVEN
        old = self.errors / "old"
        old.write_bytes(NATIVE)
        (self.coverage / "duplicate").write_bytes(NATIVE)
        good = self.coverage / "good"
        good.write_bytes(b"opaque native bytes")
        newly_bad = b"new failed bytes"
        self.read_outcome.side_effect = [
            TestOutcome(True, frozenset(), "old failure", None),
            TestOutcome(True, frozenset({"new"}), "new failure", None),
        ]

        initial_cache = []

        def run(*arguments):
            if "-fuzz" in arguments:
                directory, env, _ = self.runner_class.call_args.args
                cache = Path(env["GOCACHE"]) / "fuzz" / PACKAGE / "FuzzA"
                initial_cache.append({path.name for path in cache.iterdir()})
                (cache / "new").write_bytes(newly_bad)
                (directory / "testdata/fuzz/FuzzA/new").write_bytes(newly_bad)

            return self.run_test(*arguments, code=1)

        self.runner.run.side_effect = run
        session = Session(self.config())

        # WHEN
        with session.run() as result:
            # THEN
            self.assertEqual(initial_cache, [{"good"}])
            self.assertEqual(
                {entry.digest for entry in result.coverage}, {File(good).digest}
            )
            self.assertEqual(len(result.findings), 2)
            self.assertEqual(len(result.logs), 2)

        self.assertEqual(old.read_bytes(), NATIVE)
        self.assertEqual((self.coverage / "duplicate").read_bytes(), NATIVE)

    def test_missing_cache_is_empty(self):
        # GIVEN
        def run(*arguments):
            _, env, _ = self.runner_class.call_args.args
            (Path(env["GOCACHE"]) / "fuzz" / PACKAGE / "FuzzA").rmdir()
            return self.run_test(*arguments)

        self.runner.run.side_effect = run
        session = Session(self.config())

        # WHEN
        with session.run() as result:
            # THEN
            self.assertEqual(list(result.coverage), [])

    def test_unverifiable_cache_is_not_treated_as_empty(self):
        # GIVEN
        original_stat = os.stat

        def run(*arguments):
            result = self.run_test(*arguments)
            _, env, _ = self.runner_class.call_args.args
            cache = Path(env["GOCACHE"]) / "fuzz" / PACKAGE / "FuzzA"

            def stat(path, **kwargs):
                if isinstance(path, (str, Path)) and Path(path) == cache:
                    raise PermissionError("access denied")
                return original_stat(path, **kwargs)

            self.enterContext(patch("os.stat", side_effect=stat))
            self.enterContext(
                patch(
                    "os.lstat",
                    side_effect=lambda path, **kwargs: stat(
                        path, follow_symlinks=False, **kwargs
                    ),
                )
            )
            return result

        self.runner.run.side_effect = run
        session = Session(self.config())

        # WHEN / THEN
        with self.assertRaises(FuzzingError), session.run():
            self.fail("An unverifiable coverage cache must not yield a result")

        # THEN
        self.assertEqual(list(self.root.glob("go-fuzz-work-*")), [])

    def test_invalid_corpus_entries_are_rejected_at_construction(self):
        for setting in ("coverage_corpus", "error_corpus"):
            with (
                self.subTest(setting=setting),
                tempfile.TemporaryDirectory(dir=self.root) as directory,
            ):
                # GIVEN
                root = Path(directory)
                folder = root / "corpus"
                (folder / "invalid").mkdir(parents=True)
                self.resolver.reset_mock()
                self.runner.run.reset_mock()
                with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
                    config = self.config(**{setting: folder})

                    # WHEN / THEN
                    with self.assertRaises(CorpusError):
                        Session(config)

                # THEN
                self.resolver.assert_not_called()
                self.runner.run.assert_not_called()
                self.assertEqual(list(root.glob("go-fuzz-work-*")), [])
                self.assertEqual(list(root.glob("go-fuzz-results-*")), [])


class TestFailureReferenceResolution(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.target = Target(
            TargetSelector("example.org/a", "FuzzA"), self.root, self.root
        )
        self.target.seed_directory.mkdir(parents=True)

    def test_resolve_failure_reference_returns_native_file_or_no_file(self):
        # GIVEN
        source = self.target.seed_directory / "abc"
        source.write_bytes(b"native corpus")
        for reference, expected in (("abc", File(source)), ("seed#0", None)):
            with self.subTest(reference=reference):
                # WHEN
                entry = _resolve_failure_corpus_file(self.target, reference)

                # THEN
                self.assertEqual(entry, expected)
                self.assertEqual(source.read_bytes(), b"native corpus")

    def test_rejects_ambiguous_native_seed_reference(self):
        # GIVEN
        existing = self.target.seed_directory / "seed#0"
        existing.write_bytes(b"native corpus")
        dangling = self.target.seed_directory / "seed#1"
        dangling.symlink_to(self.root / "missing")
        for reference in ("seed#0", "seed#1"):
            # WHEN / THEN
            with (
                self.subTest(reference=reference),
                self.assertRaisesRegex(FuzzingError, "Ambiguous native seed reference"),
            ):
                _resolve_failure_corpus_file(self.target, reference)

        # THEN
        self.assertEqual(existing.read_bytes(), b"native corpus")
        self.assertTrue(dangling.is_symlink())

    def test_rejects_unverifiable_native_seed_reference(self):
        # GIVEN
        # WHEN / THEN
        with (
            patch("os.stat", side_effect=PermissionError("access denied")),
            patch("os.lstat", side_effect=PermissionError("access denied")),
            self.assertRaises(FuzzingError),
        ):
            _resolve_failure_corpus_file(self.target, "seed#0")

    def test_rejects_path_references_even_when_external_file_exists(self):
        # GIVEN
        external = self.root / "outside"
        external.write_bytes(b"native corpus")
        for reference in (str(external), "../../../outside", "../outside", ".", ".."):
            # WHEN / THEN
            with (
                self.subTest(reference=reference),
                self.assertRaisesRegex(FuzzingError, "Invalid Go failure reference"),
            ):
                _resolve_failure_corpus_file(self.target, reference)

        # THEN
        self.assertEqual(external.read_bytes(), b"native corpus")

    def test_propagates_failure_to_load_referenced_corpus_file(self):
        # GIVEN
        reference = "missing"

        # WHEN / THEN
        with self.assertRaisesRegex(CorpusError, "Cannot read native corpus file"):
            _resolve_failure_corpus_file(self.target, reference)
