"""Resolved local target, native paths and repository-relative locations."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from go_fuzz.native_go.error import NativeGoError
from go_fuzz.native_go.target import Target
from go_fuzz.native_go.target_selector import TargetSelector


class TestTarget(unittest.TestCase):
    def test_seed_directory_is_target_specific(self):
        # GIVEN
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            package = project / "internal/a"
            package.mkdir(parents=True)
            selector = TargetSelector("example.org/a", "FuzzA")

            # WHEN
            target = Target(selector, package, project)

            # THEN
            self.assertEqual(target.seed_directory, package / "testdata/fuzz/FuzzA")

    def test_coverage_path_is_package_and_target_specific(self):
        # GIVEN
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            target = Target(TargetSelector("example.org/a", "FuzzA"), project, project)
            cache = project / "cache"

            # WHEN
            coverage = target.build_coverage_path(cache)

            # THEN
            self.assertEqual(coverage, project / "cache/fuzz/example.org/a/FuzzA")

    def test_locations_are_repository_relative(self):
        # GIVEN
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            source = project / "fuzz_test.go"
            source.write_text("package a\nfunc FuzzA(f *testing.F) {}\n")
            helper = project / "helper" / "helper.go"
            helper.parent.mkdir()
            helper.touch()
            external = root / "other.go"
            external.touch()
            linked = project / "linked.go"
            linked.symlink_to(external)
            target = Target(TargetSelector("example.org/a", "FuzzA"), project, project)

            for filename, line, expected in (
                (str(source), 2, ("fuzz_test.go", 2)),
                (str(helper), 1, ("helper/helper.go", 1)),
                (str(external), 1, None),
                (str(linked), 1, None),
                (str(project / "missing.go"), 1, None),
                ("fuzz_test.go", 1, None),
                (str(source), 0, None),
                (str(source), -1, None),
                ("missing.go", 1, None),
            ):
                with self.subTest(filename=filename, line=line):
                    # WHEN
                    location = target.resolve_source_location(filename, line)

                    # THEN
                    self.assertEqual(location, expected)

    def test_rejects_package_outside_project_or_missing_directory(self):
        # GIVEN
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            selector = TargetSelector("example.org/a", "FuzzA")
            for package in (root, project / "missing"):
                # WHEN / THEN
                with (
                    self.subTest(package=package),
                    self.assertRaisesRegex(
                        NativeGoError, "not uniquely inside the project"
                    ),
                ):
                    Target(selector, package, project)


PACKAGE = "example.com/project"


class TestTargetResolution(unittest.TestCase):
    def test_resolution_requires_exact_local_package(self):
        # GIVEN
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            package = project / "nested"
            package.mkdir(parents=True)
            selector = TargetSelector(PACKAGE, "FuzzA")
            env = {"GOCACHE": str(root / "cache")}
            local = json.dumps({"ImportPath": PACKAGE, "Dir": str(package)})
            other = json.dumps({"ImportPath": "example.com/other", "Dir": str(package)})
            outside = json.dumps({"ImportPath": PACKAGE, "Dir": str(root)})

            for index, (payload, code, valid) in enumerate(
                (
                    (local, 0, True),
                    (other, 0, False),
                    (outside, 0, False),
                    ("{}", 0, False),
                    ("[]", 0, False),
                    ("{}", 1, False),
                    ("{}{}", 0, False),
                )
            ):
                with self.subTest(payload=payload, code=code):
                    # GIVEN
                    logs = root / f"logs-{index}"
                    logs.mkdir()

                    def run(
                        args,
                        *,
                        cwd,
                        env,
                        stdout,
                        stderr,
                        check,
                        payload=payload,
                        code=code,
                    ):
                        stdout.write(payload.encode())
                        return subprocess.CompletedProcess(args, code)

                    with patch(
                        "go_fuzz.native_go.target.subprocess.run",
                        side_effect=run,
                    ) as command:
                        if valid:
                            # WHEN
                            target = Target.resolve(selector, project, env, logs)

                            # THEN
                            self.assertEqual(target.selector, selector)
                            self.assertEqual(target.directory, package)
                            self.assertEqual(target.project, project)
                        else:
                            # WHEN / THEN
                            with self.assertRaises(NativeGoError):
                                Target.resolve(selector, project, env, logs)

                    # THEN
                    self.assertEqual(
                        command.call_args.args[0], ["go", "list", "-json", PACKAGE]
                    )
                    self.assertEqual(command.call_args.kwargs["cwd"], project)
                    self.assertEqual(command.call_args.kwargs["env"], env)
                    self.assertFalse(command.call_args.kwargs["check"])

    def test_native_command_start_failure_is_technical(self):
        # GIVEN
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            logs = project / "logs"
            logs.mkdir()
            selector = TargetSelector(PACKAGE, "FuzzA")

            # WHEN / THEN
            with (
                patch(
                    "go_fuzz.native_go.target.subprocess.run",
                    side_effect=OSError("cannot start Go"),
                ),
                self.assertRaisesRegex(
                    NativeGoError, "Could not start native Go command"
                ),
            ):
                Target.resolve(selector, project, {}, logs)
