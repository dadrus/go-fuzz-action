"""Run the actual Composite Action shell adapter against a Go fixture."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(shutil.which("go"), "Go toolchain not installed")
class TestCliEntrypoint(unittest.TestCase):
    def test_action_adapter_writes_outputs_and_uses_its_own_code(self):
        # GIVEN
        action_path = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "source"
            project.mkdir()
            (project / "go.mod").write_text(
                "module example.com/entrypointfixture\n\ngo 1.23\n"
            )
            (project / "fuzz_test.go").write_text(
                'package fixture\nimport "testing"\n'
                "func FuzzSafe(f *testing.F) {\n"
                ' f.Add("hello")\n'
                " f.Fuzz(func(t *testing.T, s string) {})\n"
                "}\n"
            )

            # The consuming project and PYTHONPATH must not shadow the Action.
            (project / "go_fuzz.py").write_text('raise RuntimeError("wrong module")\n')

            output = root / "github.outputs"
            env = dict(os.environ)
            env.update(
                {
                    "GITHUB_ACTION_PATH": str(action_path),
                    "PYTHONPATH": str(project),
                    "GITHUB_WORKSPACE": str(project),
                    "RUNNER_TEMP": str(root),
                    "GITHUB_OUTPUT": str(output),
                    "GO_FUZZ_PACKAGE": "example.com/entrypointfixture",
                    "GO_FUZZ_TARGET": "FuzzSafe",
                    "GO_FUZZ_TIME": "300ms",
                    "GO_FUZZ_RESULTS_FORMAT": "jsonl",
                    "GO_FUZZ_COVERAGE_CORPUS": "",
                    "GO_FUZZ_ERROR_CORPUS": "",
                }
            )

            # The adapter contains a single literal shell block and no later steps.
            shell = (
                (action_path / "action.yml").read_text().split("      run: |\n", 1)[1]
            )

            # WHEN
            completed = subprocess.run(
                ["bash", "-c", shell],
                cwd=project,
                env=env,
                capture_output=True,
                check=False,
                text=True,
                timeout=180,
            )

            # THEN
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )

            outputs = dict(
                line.split("=", 1) for line in output.read_text().splitlines()
            )

            self.assertEqual(outputs["findings-count"], "0")
            self.assertTrue(Path(outputs["results-file"]).is_file())
            self.assertTrue(Path(outputs["coverage-corpus"]).is_dir())
            self.assertEqual(list(Path(outputs["error-corpus"]).iterdir()), [])
            self.assertFalse((project / "testdata").exists())


if __name__ == "__main__":
    unittest.main()
