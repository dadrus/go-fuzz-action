"""Configuration is validated at construction; native syntax belongs to Go."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from go_fuzz.config import Config, ConfigError, ResultsFormat
from go_fuzz.corpus import CorpusError
from go_fuzz.filesystem import FilesystemError


class TestConfig(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / "project"
        self.workspace.mkdir()
        self.temp_root = self.root / "temporary"

        env = patch.dict(os.environ, {"RUNNER_TEMP": str(self.temp_root)})
        env.start()
        self.addCleanup(env.stop)

    def config(self, **overrides):
        return Config(
            **{
                "workspace": self.workspace,
                "package": "example.com/a",
                "target": "FuzzA",
                **overrides,
            },
        )

    def test_defaults(self):
        # GIVEN
        # Use the minimal configuration provided by the fixture.

        # WHEN
        config = self.config()

        # THEN
        self.assertIs(config.results_format, ResultsFormat.JSONL)
        self.assertEqual(config.fuzztime, "30s")
        self.assertIsNone(config.error_corpus)
        self.assertIsNone(config.coverage_corpus)
        self.assertEqual(config.selector.package, "example.com/a")
        self.assertEqual(config.selector.name, "FuzzA")

    def test_report_format_is_normalized_to_enum(self):
        # GIVEN
        for value, expected in (
            ("sarif", ResultsFormat.SARIF),
            ("jsonl", ResultsFormat.JSONL),
        ):
            with self.subTest(value=value):
                # WHEN
                config = self.config(results_format=value)

                # THEN
                self.assertIs(config.results_format, expected)

        # GIVEN
        unsupported_format = "xml"

        # WHEN / THEN
        with self.assertRaises(ConfigError):
            self.config(results_format=unsupported_format)

    def test_budget_is_not_parsed_by_configuration(self):
        # GIVEN
        for budget in ("30s", "250x", "+1s", "nope", "-1s", "-run=.*"):
            with self.subTest(budget=budget):
                # WHEN
                config = self.config(fuzztime=budget)

                # THEN
                self.assertEqual(config.fuzztime, budget)

        # GIVEN
        unsafe_budget = "1s\0"

        # WHEN / THEN
        with self.assertRaises(ConfigError):
            self.config(fuzztime=unsafe_budget)

    def test_missing_or_non_directory_workspace_is_rejected_at_construction(self):
        # GIVEN
        file = self.root / "file"
        file.touch()

        loop = self.root / "loop"
        loop.symlink_to(loop)

        for path in (file, self.root / "missing", loop):
            # WHEN / THEN
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(ConfigError, "Workspace is not a directory"),
            ):
                self.config(workspace=path)

        # THEN
        self.assertFalse(self.temp_root.exists())

    def test_relative_paths_and_temporary_root_are_fixed_at_construction(self):
        # GIVEN
        corpus = self.root / "corpus"
        corpus.mkdir()

        # WHEN
        config = self.config(
            workspace=Path(os.path.relpath(self.workspace)),
            coverage_corpus=Path(os.path.relpath(corpus)),
            error_corpus=Path(os.path.relpath(corpus)),
        )

        # THEN
        self.assertEqual(config.workspace, self.workspace)
        self.assertEqual(config.coverage_corpus, corpus)
        self.assertEqual(config.error_corpus, corpus)
        self.assertFalse(self.temp_root.exists())

        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.workspace)}):
            self.assertEqual(config.temporary_root, self.temp_root)

    def test_workspace_alias_is_normalized(self):
        # GIVEN
        alias = self.root / "checkout-alias"
        alias.symlink_to(self.workspace, target_is_directory=True)

        # WHEN
        config = self.config(workspace=alias)

        # THEN
        self.assertEqual(config.workspace, self.workspace)

    def test_invalid_corpus_directories_are_rejected_at_construction(self):
        for setting in ("coverage_corpus", "error_corpus"):
            # GIVEN
            path = self.root / "missing"

            # WHEN / THEN
            with self.subTest(setting=setting), self.assertRaises(CorpusError):
                self.config(**{setting: path})

        # THEN
        self.assertFalse(self.temp_root.exists())

    def test_temporary_root_cannot_be_in_protected_directories(self):
        # GIVEN
        coverage = self.root / "coverage"
        errors = self.root / "errors"
        coverage.mkdir()
        errors.mkdir()
        for path in (self.workspace, coverage, errors):
            # WHEN / THEN
            with (
                self.subTest(path=path),
                patch.dict(os.environ, {"RUNNER_TEMP": str(path)}),
                self.assertRaisesRegex(FilesystemError, "inside"),
            ):
                self.config(coverage_corpus=coverage, error_corpus=errors)

        # THEN
        self.assertEqual(list(self.workspace.iterdir()), [])
        self.assertEqual(list(coverage.iterdir()), [])
        self.assertEqual(list(errors.iterdir()), [])

    def test_invalid_temporary_root_is_rejected_at_construction(self):
        # GIVEN
        file = self.root / "file"
        file.touch()

        # WHEN / THEN
        with (
            patch.dict(os.environ, {"RUNNER_TEMP": str(file)}),
            self.assertRaisesRegex(
                FilesystemError, "Temporary root must be a directory"
            ),
        ):
            self.config()
