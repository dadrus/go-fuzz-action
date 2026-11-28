"""Resolved local Go target and native paths."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from .error import NativeGoError
from .target_selector import TargetSelector


@dataclass(frozen=True)
class Target:
    selector: TargetSelector
    directory: Path
    project: Path

    def __post_init__(self) -> None:
        project = self.project.resolve()
        directory = self.directory.resolve()

        if not directory.is_dir() or not directory.is_relative_to(project):
            raise NativeGoError("Package is not uniquely inside the project")

        object.__setattr__(self, "project", project)
        object.__setattr__(self, "directory", directory)

    @classmethod
    def resolve(
        cls,
        selector: TargetSelector,
        project: Path,
        env: dict[str, str],
        logs: Path,
    ) -> Self:
        stdout = logs / "package.json"
        stderr = logs / "package.stderr"

        try:
            with stdout.open("xb") as output, stderr.open("xb") as errors:
                result = subprocess.run(  # noqa: S603 -- validated exact package, argv only
                    ["go", "list", "-json", selector.package],  # noqa: S607 -- caller-provided Go toolchain
                    cwd=project,
                    env=env,
                    stdout=output,
                    stderr=errors,
                    check=False,
                )
        except (OSError, ValueError) as exc:
            raise NativeGoError("Could not start native Go command") from exc

        if result.returncode != 0:
            raise NativeGoError("Go could not resolve the requested package")

        try:
            with stdout.open(encoding="utf-8") as stream:
                metadata = json.load(stream)

            if (
                not isinstance(metadata, dict)
                or metadata.get("ImportPath") != selector.package
            ):
                raise ValueError("unexpected import path")

            directory = Path(metadata["Dir"])
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise NativeGoError("Package is not uniquely inside the project") from exc

        return cls(selector, directory, project)

    @property
    def seed_directory(self) -> Path:
        return self.directory / "testdata" / "fuzz" / self.selector.name

    def build_coverage_path(self, cache: Path) -> Path:
        return cache / "fuzz" / self.selector.package / self.selector.name

    def resolve_source_location(self, raw: str, line: int) -> tuple[str, int] | None:
        path = Path(raw)
        if line <= 0 or not path.is_absolute():
            return None

        path = path.resolve()
        if path.is_relative_to(self.project) and path.is_file():
            return path.relative_to(self.project).as_posix(), line

        return None
