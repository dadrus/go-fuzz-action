"""Exercise the actual Action shell adapter with a fake CLI, without Go."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class TestActionAdapter(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.output = self.root / "github-output"
        self.output.write_text("existing=value\n")

        action = Path(__file__).resolve().parents[2]
        self.shell = (action / "action.yaml").read_text().split("      run: |\n", 1)[1]
        (self.root / "__main__.py").write_bytes((action / "__main__.py").read_bytes())

        # Replace only the CLI at the adapter boundary. Run Bash and jq for real.
        package = self.root / "go_fuzz"
        package.mkdir()
        (package / "__init__.py").touch()
        (package / "cli.py").write_text(
            "import os\n"
            "import sys\n"
            "def main():\n"
            '    if "GITHUB_OUTPUT" in os.environ:\n'
            "        return 99\n"
            '    if any(arg.partition("=")[0] == "--results-file"\n'
            "           for arg in sys.argv[1:]):\n"
            "        return 98\n"
            '    print(os.environ["TEST_CLI_RESULT"], end="")\n'
            '    return int(os.environ["TEST_CLI_STATUS"])\n'
        )

        self.env = {
            **os.environ,
            "GITHUB_ACTION_PATH": str(self.root),
            "GITHUB_WORKSPACE": str(self.root),
            "GITHUB_OUTPUT": str(self.output),
            "GO_FUZZ_PACKAGE": "example.org/project",
            "GO_FUZZ_TARGET": "FuzzA",
            "GO_FUZZ_TIME": "30s",
            "GO_FUZZ_RESULTS_FORMAT": "sarif",
            "GO_FUZZ_COVERAGE_CORPUS": "",
            "GO_FUZZ_ERROR_CORPUS": "",
        }

        self.result = {
            "results_file": "/tmp/report = a.sarif",
            "findings_count": 3,
            "coverage_corpus": "/tmp/coverage",
            "error_corpus": "/tmp/error",
        }

    def execute(self, payload, status=0):
        return subprocess.run(
            ["bash", "-c", self.shell],
            cwd=self.root,
            env={
                **self.env,
                "TEST_CLI_RESULT": payload,
                "TEST_CLI_STATUS": str(status),
            },
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )

    def test_valid_result_maps_to_four_outputs(self):
        # GIVEN
        self.env["GO_FUZZ_RESULTS_FILE"] = str(self.output)
        payload = json.dumps(self.result)

        # WHEN
        completed = self.execute(payload)

        # THEN
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(
            self.output.read_text(),
            "existing=value\n"
            "results-file=/tmp/report = a.sarif\n"
            "findings-count=3\n"
            "coverage-corpus=/tmp/coverage\n"
            "error-corpus=/tmp/error\n",
        )

    def test_failed_cli_cannot_publish_even_a_valid_result(self):
        # GIVEN
        payload = json.dumps(self.result)

        # WHEN
        completed = self.execute(payload, status=1)

        # THEN
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(self.output.read_text(), "existing=value\n")

    def test_invalid_json_cannot_publish_partial_outputs(self):
        for payload in (
            "",
            "not JSON",
            json.dumps(self.result) + "\nnot JSON",
        ):
            with self.subTest(payload=payload):
                # GIVEN
                self.output.write_text("existing=value\n")

                # WHEN
                completed = self.execute(payload)

                # THEN
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(self.output.read_text(), "existing=value\n")
