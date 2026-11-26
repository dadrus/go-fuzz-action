"""Execute native Go fuzz tests and preserve their original process results."""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .error import NativeGoError


@dataclass(frozen=True)
class TestResult:
    """Exit status and original log paths of one native Go test process."""

    returncode: int
    stdout: Path
    stderr: Path


class Runner:
    """Execute Go tests in the resolved package and retain their native logs."""

    def __init__(
        self,
        directory: Path,
        env: dict[str, str],
        logs: Path,
    ) -> None:
        self._directory = directory
        self._env = env.copy()
        self._logs = logs

    def run(self, *arguments: str) -> TestResult:
        logs = Path(tempfile.mkdtemp(prefix="go-", dir=self._logs))
        stdout = logs / "stdout"
        stderr = logs / "stderr"

        try:
            with stdout.open("wb") as output, stderr.open("wb") as errors:
                result = subprocess.run(
                    ["go", "test", "-json", "-count=1", "-fullpath", *arguments],
                    cwd=self._directory,
                    env=self._env,
                    stdout=output,
                    stderr=errors,
                    check=False,
                )
        except (OSError, ValueError) as exc:
            # Do not echo potentially sensitive environment, arguments or Go output.
            raise NativeGoError("Could not start native Go command") from exc

        return TestResult(result.returncode, stdout, stderr)
