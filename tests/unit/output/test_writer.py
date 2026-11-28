"""Persist complete results and enforce the Action-owned write boundary."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from go_fuzz.config import Config, ResultsFormat
from go_fuzz.corpus import File, Snapshot
from go_fuzz.fuzzing import Finding, Findings, SessionResult
from go_fuzz.native_go import Target, TargetSelector
from go_fuzz.output.error import OutputError
from go_fuzz.output.writer import AnalysisResult, ResultWriter


class TestResultWriter(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.source = self.root / "source"
        self.source.mkdir()
        self.target = Target(
            TargetSelector("example.com/a", "FuzzA"), self.source, self.source
        )

        self.enterContext(patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}))

    def config(self, **overrides):
        return Config(
            **{
                "workspace": self.source,
                "package": "example.com/a",
                "target": "FuzzA",
                **overrides,
            }
        )

    def result(self):
        log = self.root / "log"
        log.write_bytes(b"new report")
        return SessionResult(Snapshot(), Findings(self.target), (log,))

    def test_complete_results_persist_native_bytes_and_deduplicated_errors(self):
        # GIVEN
        good = self.root / "good"
        good.write_bytes(b"good bytes")
        bad = self.root / "bad"
        bad.write_bytes(b"bad bytes")
        entry = File(bad)
        result = self.result()
        result.findings.add(Finding(self.target, "bad", "failure", None, entry))
        result.findings.add(Finding(self.target, "seed#0", "failure", None))
        result = SessionResult(Snapshot((File(good),)), result.findings, result.logs)
        with ResultWriter(self.config()).open() as writer:
            # WHEN
            output = writer.write(result)

        # THEN
        self.assertIsInstance(output, AnalysisResult)
        self.assertEqual(output.findings_count, 2)
        self.assertEqual(
            (output.coverage_corpus / "good").read_bytes(),
            good.read_bytes(),
        )
        self.assertEqual(
            (output.error_corpus / entry.digest).read_bytes(),
            bad.read_bytes(),
        )
        self.assertEqual(
            list(output.error_corpus.iterdir()),
            [output.error_corpus / entry.digest],
        )
        self.assertEqual(output.results_file.read_bytes(), b"new report")

    def test_failure_removes_partial_outputs(self):
        # GIVEN
        result = self.result()
        result.logs[0].unlink()

        writer = ResultWriter(self.config())

        # WHEN / THEN
        with self.assertRaises(FileNotFoundError), writer.open():
            writer.write(result)

        # THEN
        self.assertEqual(list(self.root.glob("go-fuzz-results-*")), [])

    def test_each_analysis_creates_a_separate_owned_output_directory(self):
        # GIVEN
        existing = self.root / "results.jsonl"
        existing.write_bytes(b"existing report")
        writer = ResultWriter(self.config())
        result = self.result()
        with writer.open():
            first = writer.write(result)

        result.logs[0].write_bytes(b"second report")

        # WHEN
        with writer.open():
            second = writer.write(result)

        # THEN
        self.assertNotEqual(first.results_file.parent, second.results_file.parent)
        for output in (first, second):
            directory = output.results_file.parent
            self.assertEqual(directory.parent, self.root)
            self.assertEqual(output.results_file, directory / "results.jsonl")
            self.assertEqual(output.coverage_corpus, directory / "coverage")
            self.assertEqual(output.error_corpus, directory / "error")
            self.assertTrue(output.coverage_corpus.is_dir())
            self.assertTrue(output.error_corpus.is_dir())
        self.assertEqual(first.results_file.read_bytes(), b"new report")
        self.assertEqual(second.results_file.read_bytes(), b"second report")
        self.assertEqual(existing.read_bytes(), b"existing report")

    def test_only_owned_report_files_can_be_published(self):
        for kind in ("foreign", "symlink", "missing"):
            with (
                self.subTest(kind=kind),
                tempfile.TemporaryDirectory(dir=self.root) as directory,
            ):
                # GIVEN
                root = Path(directory)
                original = self.source / f"{kind}.go"
                original.write_bytes(b"original")
                result = self.result()

                def report(directory, logs, findings, kind=kind, original=original):
                    if kind == "foreign":
                        return original
                    path = directory / "results.jsonl"
                    if kind == "symlink":
                        path.symlink_to(original)
                    return path

                with (
                    patch.dict(os.environ, {"RUNNER_TEMP": str(root)}),
                    patch(
                        "go_fuzz.output.writer.JsonlReportWriter.write",
                        side_effect=report,
                    ),
                ):
                    writer = ResultWriter(self.config())

                    # WHEN / THEN
                    with self.assertRaises(OutputError), writer.open():
                        writer.write(result)

                # THEN
                self.assertEqual(original.read_bytes(), b"original")
                self.assertEqual(list(root.glob("go-fuzz-results-*")), [])

    def test_result_directory_is_removed_if_session_cleanup_fails(self):
        # GIVEN
        writer = ResultWriter(self.config())
        result = self.result()

        with self.assertRaisesRegex(OSError, "session cleanup failed"), writer.open():
            output = writer.write(result)

            report_exists = output.results_file.is_file()

            # WHEN / THEN
            # Simulate a failure during session cleanup as the writer context exits.
            raise OSError("session cleanup failed")

        # THEN
        self.assertTrue(report_exists)
        self.assertFalse(output.results_file.exists())
        self.assertEqual(list(self.root.glob("go-fuzz-results-*")), [])

    def test_construction_does_not_create_output_root(self):
        # GIVEN
        root = self.root / "not-yet-created"
        with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
            config = self.config()

        # WHEN
        ResultWriter(config)

        # THEN
        self.assertFalse(root.exists())

    def test_write_requires_open_context(self):
        for previously_open in (False, True):
            with self.subTest(previously_open=previously_open):
                # GIVEN
                writer = ResultWriter(self.config())
                result = self.result()
                if previously_open:
                    with writer.open():
                        writer.write(result)

                # WHEN / THEN
                with self.assertRaisesRegex(OutputError, "not open"):
                    writer.write(result)

    def test_nested_writer_context_is_rejected(self):
        # GIVEN
        writer = ResultWriter(self.config())
        # WHEN / THEN
        with (
            writer.open(),
            self.assertRaisesRegex(OutputError, "already open"),
            writer.open(),
        ):
            self.fail("Nested writer context must be rejected")

    def test_selected_report_format_is_used(self):
        # GIVEN
        result = self.result()
        with ResultWriter(
            self.config(results_format=ResultsFormat.SARIF)
        ).open() as writer:
            # WHEN
            output = writer.write(result)

        # THEN
        self.assertEqual(output.results_file.suffix, ".sarif")
        self.assertEqual(output.findings_count, 0)
