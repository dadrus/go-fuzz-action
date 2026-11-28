"""Own a temporary fuzzing session and its native corpus/finding lifecycle."""

import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ..config import Config
from ..corpus import File, Snapshot
from ..native_go import SEED_NAME, Runner, Target, TestOutcome
from .error import FuzzingError
from .finding import Finding
from .findings import Findings


@dataclass(frozen=True)
class SessionResult:
    """File-backed results remain valid until the session context exits."""

    coverage: Snapshot
    findings: Findings
    logs: tuple[Path, ...]


def _resolve_failure_corpus_file(target: Target, reference: str) -> File | None:
    if SEED_NAME.fullmatch(reference):
        # A file of this name would make the native seed reference ambiguous.
        path = target.seed_directory / reference
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise FuzzingError("Could not inspect native seed reference") from exc

        raise FuzzingError("Ambiguous native seed reference")

    if Path(reference).name != reference or reference in {".", ".."}:
        raise FuzzingError("Invalid Go failure reference")

    return File(target.seed_directory / reference)


class Session:
    """Own a temporary single-target Go fuzzing run and its file-backed results."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._coverage = Snapshot.load(config.coverage_corpus)
        self._errors = Snapshot.load(config.error_corpus)

    @contextmanager
    def run(self) -> Iterator[SessionResult]:
        temp_root = self._config.path_guard.resolve_directory(
            self._config.temporary_root,
        )
        temp_root.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(
            prefix="go-fuzz-work-",
            dir=temp_root,
        ) as temporary:
            work = Path(temporary)
            project = work / "project"
            cache = work / "cache"
            logs = work / "logs"

            # Preserve project symlinks: a temporary copy is not a sandbox.
            try:
                shutil.copytree(
                    self._config.workspace,
                    project,
                    symlinks=True,
                    ignore=shutil.ignore_patterns(".git", ".hg", ".svn"),
                )
            except (OSError, shutil.Error) as exc:
                raise FuzzingError("Could not copy project workspace") from exc

            cache.mkdir()
            logs.mkdir()

            env = dict(os.environ, GOCACHE=str(cache))
            target = Target.resolve(self._config.selector, project, env, logs)
            runner = Runner(target.directory, env, logs)

            findings = Findings(target)
            test_logs = [
                self._replay_input(runner, findings, entry) for entry in self._errors
            ]

            cache_directory = target.build_coverage_path(cache)
            self._coverage.copy_to(cache_directory, excluded=findings.file_hashes)

            test_logs.append(self._fuzz_target(runner, findings))

            try:
                cache_directory.lstat()
            except FileNotFoundError:
                native = Snapshot()
            except OSError as exc:
                raise FuzzingError("Could not inspect native coverage cache") from exc
            else:
                native = Snapshot.load(cache_directory)

            excluded = findings.file_hashes
            coverage = Snapshot(
                tuple(entry for entry in native if entry.digest not in excluded)
            )

            yield SessionResult(coverage, findings, tuple(test_logs))

    def _replay_input(
        self,
        runner: Runner,
        findings: Findings,
        entry: File,
    ) -> Path:
        target = findings.target

        with entry.stage_for_replay(target.seed_directory) as staged:
            result = runner.run("-run", target.selector.build_test_pattern(staged.name))

            outcome = TestOutcome.classify(
                result.stdout,
                result.returncode,
                target,
                f"{target.selector.name}/{staged.name}",
            )

        if outcome.failed:
            findings.add(
                Finding.from_outcome(target, entry.path.name, outcome, entry),
            )

        return result.stdout

    def _fuzz_target(self, runner: Runner, findings: Findings) -> Path:
        target = findings.target

        result = runner.run(
            "-run",
            "^$",
            "-fuzz",
            target.selector.build_test_pattern(),
            f"-fuzztime={self._config.fuzztime}",
        )

        outcome = TestOutcome.classify(
            result.stdout,
            result.returncode,
            target,
            target.selector.name,
        )

        if outcome.failed:
            if len(outcome.references) != 1:
                raise FuzzingError(
                    "Fuzz failure without one attributable input or seed"
                )

            reference = next(iter(outcome.references))
            corpus = _resolve_failure_corpus_file(target, reference)
            findings.add(
                Finding.from_outcome(target, reference, outcome, corpus),
            )

        return result.stdout
