"""The CLI exposes a GitHub-independent JSON result and exit status."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from go_fuzz import AnalysisResult, Config, ResultsFormat
from go_fuzz.cli import main
from go_fuzz.native_go import NativeGoError


class TestCli(unittest.TestCase):
    def test_success_returns_typed_json_without_writing_github_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            # GIVEN
            root = Path(directory)
            output = root / "github-output"
            (root / "input").mkdir()
            result = AnalysisResult(
                root / "report",
                2,
                root / "coverage",
                root / "error",
            )
            with (
                patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                patch("go_fuzz.cli.FuzzAnalyzer", autospec=True) as analysis,
                redirect_stdout(io.StringIO()) as stdout,
                redirect_stderr(io.StringIO()) as stderr,
            ):
                analysis.return_value.run.return_value = result

                arguments = [
                    "--workspace",
                    str(root),
                    "--package=example.com/a",
                    "--target=FuzzA",
                    "--results-format=sarif",
                    "--error-corpus",
                    str(root / "input"),
                ]

                # WHEN
                status = main(arguments)

                # THEN
                self.assertEqual(status, 0)
                config = analysis.call_args.args[0]

                analysis.return_value.run.assert_called_once_with()
                self.assertIsInstance(config, Config)
                self.assertEqual(config.error_corpus, root / "input")
                self.assertIsNone(config.coverage_corpus)
                self.assertIs(config.results_format, ResultsFormat.SARIF)

            self.assertFalse(output.exists())
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(
                json.loads(stdout.getvalue()),
                {
                    "results_file": str(result.results_file),
                    "findings_count": 2,
                    "coverage_corpus": str(result.coverage_corpus),
                    "error_corpus": str(result.error_corpus),
                },
            )

    def test_failure_has_no_json_result(self):
        # GIVEN
        with patch("go_fuzz.cli.FuzzAnalyzer", autospec=True) as analysis:
            analysis.return_value.run.side_effect = NativeGoError("Analysis failed")

            with (
                redirect_stdout(io.StringIO()) as stdout,
                redirect_stderr(io.StringIO()) as stderr,
            ):
                arguments = ["--package=example.com/a", "--target=FuzzA"]

                # WHEN
                status = main(arguments)

            # THEN
            self.assertEqual(status, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Analysis failed", stderr.getvalue())

    def test_invalid_config_does_not_construct_analyzer(self):
        # GIVEN
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("go_fuzz.cli.FuzzAnalyzer", autospec=True) as analysis,
            redirect_stdout(io.StringIO()) as stdout,
            redirect_stderr(io.StringIO()) as stderr,
        ):
            arguments = [
                "--workspace",
                directory,
                "--package=example.com/a",
                "--target=FuzzA",
                "--coverage-corpus",
                str(Path(directory) / "missing"),
            ]

            # WHEN
            status = main(arguments)

            # THEN
            self.assertEqual(status, 1)
            analysis.assert_not_called()
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Corpus input", stderr.getvalue())

    def test_caller_cannot_set_report_destination(self):
        # GIVEN
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("go_fuzz.cli.FuzzAnalyzer", autospec=True) as analysis,
            redirect_stdout(io.StringIO()) as stdout,
            redirect_stderr(io.StringIO()) as stderr,
        ):
            root = Path(directory)
            workspace = root / "project"
            workspace.mkdir()
            destination = root / "existing"
            destination.write_text("original")
            analysis.return_value.run.return_value = AnalysisResult(
                root / "report", 0, root / "coverage", root / "error"
            )
            arguments = [
                "--workspace",
                str(workspace),
                "--package=example.com/a",
                "--target=FuzzA",
                "--results-file",
                str(destination),
            ]

            # WHEN / THEN
            with self.assertRaises(SystemExit) as error:
                main(arguments)

            # THEN
            self.assertEqual(error.exception.code, 2)
            analysis.assert_not_called()
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("unrecognized arguments: --results-file", stderr.getvalue())
            self.assertEqual(destination.read_text(), "original")
