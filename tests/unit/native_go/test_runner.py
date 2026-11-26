"""Native process execution, without session or finding semantics."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from go_fuzz.native_go.error import NativeGoError
from go_fuzz.native_go.runner import Runner


class TestRunner(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.env = {"GOCACHE": str(self.root / "cache")}
        self.runner = Runner(self.root, self.env, self.root)
        command = patch("go_fuzz.native_go.runner.subprocess.run", autospec=True)
        self.command = command.start()
        self.addCleanup(command.stop)

    def test_run_preserves_arguments_context_and_native_result(self):
        # GIVEN
        for arguments in (
            ("-run", "^FuzzA$/^abc$"),
            ("-run", "^$", "-fuzz", "^FuzzA$", "-fuzztime=-run=.*"),
        ):

            def execute(args, *, cwd, env, stdout, stderr, check):
                stdout.write(b'{"Action":"fail"}\n')
                stderr.write(b"private diagnostics\n")
                return subprocess.CompletedProcess(args, 1)

            self.command.side_effect = execute
            with self.subTest(arguments=arguments):
                # WHEN
                result = self.runner.run(*arguments)

                # THEN
                self.assertEqual(
                    self.command.call_args.args[0],
                    ["go", "test", "-json", "-count=1", "-fullpath", *arguments],
                )
                context = self.command.call_args.kwargs
                self.assertEqual(context["cwd"], self.root)
                self.assertEqual(context["env"], self.env)
                self.assertFalse(context["check"])
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout.read_bytes(), b'{"Action":"fail"}\n')
                self.assertEqual(result.stderr.read_bytes(), b"private diagnostics\n")

        self.assertEqual(len(list(self.root.iterdir())), 2)

    def test_start_failure_does_not_echo_raw_error(self):
        # GIVEN
        for failure in (
            OSError("private diagnostics"),
            ValueError("private diagnostics"),
        ):
            self.command.side_effect = failure

            # WHEN / THEN
            with (
                self.subTest(failure=type(failure)),
                self.assertRaisesRegex(
                    NativeGoError,
                    "^Could not start native Go command$",
                ),
            ):
                self.runner.run("-run", "^FuzzA$")
