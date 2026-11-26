"""The analysis coordinates the session and output lifecycles."""

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from go_fuzz import AnalysisResult, Config, FuzzActionError, FuzzAnalyzer
from go_fuzz.corpus import Snapshot
from go_fuzz.fuzzing import Findings, SessionResult
from go_fuzz.native_go import NativeGoError, Target
from go_fuzz.output import OutputError


class TestFuzzAnalyzer(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = Config(self.root, "example.com/a", "FuzzA")
        self.target = Target(self.config.selector, self.root, self.root)

        session = patch("go_fuzz.analyzer.Session", autospec=True)
        self.session_class = session.start()
        self.session = self.session_class.return_value
        self.addCleanup(session.stop)

        output = patch("go_fuzz.analyzer.ResultWriter", autospec=True)
        self.output_class = output.start()
        self.output = (
            self.output_class.return_value.open.return_value.__enter__.return_value
        )
        self.output_class.return_value.open.return_value.__exit__.return_value = False
        self.addCleanup(output.stop)

    def test_output_is_written_before_session_resources_are_released(self):
        # GIVEN
        log = self.root / "log"
        native = SessionResult(Snapshot(), Findings(self.target), (log,))
        expected = AnalysisResult(
            self.root / "report",
            0,
            self.root / "coverage",
            self.root / "error",
        )

        @contextmanager
        def run():
            log.touch()
            try:
                yield native
            finally:
                log.unlink()

        resource_available = []

        def write(result):
            resource_available.append(log.is_file())

            return expected

        self.session.run.side_effect = run
        self.output.write.side_effect = write

        analyzer = FuzzAnalyzer(self.config)

        # WHEN
        result = analyzer.run()

        # THEN
        self.assertEqual(result, expected)
        self.assertEqual(self.output.write.call_args.args[0], native)
        self.assertEqual(resource_available, [True])
        self.assertFalse(log.exists())

    def test_technical_failure_does_not_publish_results(self):
        # GIVEN
        self.session.run.side_effect = NativeGoError("incomplete native test")

        analyzer = FuzzAnalyzer(self.config)

        # WHEN / THEN
        with self.assertRaisesRegex(FuzzActionError, "incomplete native test"):
            analyzer.run()

        # THEN
        self.output.write.assert_not_called()

    def test_publication_error_closes_session(self):
        # GIVEN
        log = self.root / "log"

        @contextmanager
        def run():
            log.touch()
            try:
                yield SessionResult(Snapshot(), Findings(self.target), (log,))
            finally:
                log.unlink()

        self.session.run.side_effect = run
        self.output.write.side_effect = OutputError("cannot publish")

        analyzer = FuzzAnalyzer(self.config)

        # WHEN / THEN
        with self.assertRaisesRegex(FuzzActionError, "cannot publish"):
            analyzer.run()

        # THEN
        self.assertFalse(log.exists())
