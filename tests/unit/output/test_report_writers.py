"""Stable target rule, input identities and byte-exact JSONL assembly."""

import json
import tempfile
import unittest
from pathlib import Path

from go_fuzz.corpus import File
from go_fuzz.fuzzing import Finding, Findings
from go_fuzz.native_go import Target, TargetSelector
from go_fuzz.output.jsonl_report_writer import JsonlReportWriter
from go_fuzz.output.sarif_report_writer import SarifReportWriter


class TestReportWriters(unittest.TestCase):
    def test_sarif_file_and_seed_identity(self):
        # GIVEN
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "internal/a"
            package.mkdir(parents=True)
            target = Target(TargetSelector("example.org/a", "FuzzA"), package, root)
            location = ("internal/a/fuzz_test.go", 2)
            first, second = root / "one", root / "two"
            first.write_bytes(b'go test fuzz v1\nstring("1")\n')
            second.write_bytes(b'go test fuzz v1\nstring("2")\n')
            inputs = [
                Finding(target, path.name, "failure", location, File(path))
                for path in (first, second)
            ]
            inputs.append(Finding(target, "seed#0", "panic: failure", location))
            findings = Findings(target)
            for finding in inputs:
                findings.add(finding)
            writer = SarifReportWriter()
            logs = [root / "missing-log"]

            # WHEN
            report = writer.write(root, logs, findings)

            # THEN
            self.assertEqual(report, root / "results.sarif")

            sarif = json.loads(report.read_text())
            run = sarif["runs"][0]

            self.assertEqual(run["tool"]["driver"]["name"], "Go Fuzzing")
            self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)

            results = run["results"]

            self.assertEqual(
                len(
                    {
                        r["partialFingerprints"]["primaryLocationLineHash"]
                        for r in results
                    }
                ),
                3,
            )
            self.assertEqual(len({r["ruleId"] for r in results}), 1)
            self.assertEqual(
                len(
                    {
                        r["locations"][0]["physicalLocation"]["region"]["startLine"]
                        for r in results
                    }
                ),
                1,
            )

            seed = next(
                r for r in results if r["properties"]["goFuzzInputKind"] == "seed"
            )

            self.assertIn("seed#0", seed["message"]["text"])
            self.assertNotIn("goFuzzInputSHA256", seed["properties"])

    def test_sarif_report_is_stable_under_finding_order(self):
        # GIVEN
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = Target(TargetSelector("example.org/a", "FuzzA"), root, root)
            first, second = root / "one", root / "two"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            inputs = [
                Finding(target, path.name, "failure", None, File(path))
                for path in (first, second)
            ]
            inputs.append(Finding(target, "seed#0", "seed failure", None))
            findings = Findings(target)
            reverse = Findings(target)
            for finding in inputs:
                findings.add(finding)
            for finding in reversed(inputs):
                reverse.add(finding)
            writer = SarifReportWriter()
            expected = json.loads(writer.write(root, [], findings).read_text())
            reverse_dir = root / "reverse"
            reverse_dir.mkdir()

            # WHEN
            report = writer.write(reverse_dir, [], reverse)

            # THEN
            self.assertEqual(json.loads(report.read_text()), expected)

    def test_empty_sarif_contains_target_rule_and_no_results(self):
        # GIVEN
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = Target(TargetSelector("example.org/a", "FuzzA"), root, root)
            findings = Findings(target)
            writer = SarifReportWriter()

            # WHEN
            report = writer.write(root, [], findings)

            # THEN
            run = json.loads(report.read_text())["runs"][0]
            self.assertEqual(run["results"], [])
            self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)

    def test_append_jsonl_preserves_bytes(self):
        # GIVEN
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            first.write_bytes(b'{"Action": "run"}\n')
            second.write_bytes(b'{"Action":"pass"}\r\n')
            target = Target(TargetSelector("example.org/a", "FuzzA"), root, root)
            writer = JsonlReportWriter()
            findings = Findings(target)
            logs = [first, second]

            # WHEN
            report = writer.write(root, logs, findings)

            # THEN
            self.assertEqual(report, root / "results.jsonl")
            self.assertEqual(
                report.read_bytes(),
                first.read_bytes() + second.read_bytes(),
            )

    def test_sarif_preserves_only_evidenced_locations(self):
        # GIVEN
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = Target(TargetSelector("example.org/a", "FuzzA"), root, root)
            (root / "fuzz_test.go").write_text(
                "package a\nfunc FuzzA(f *testing.F) {}\n"
            )

            for location, expected in (
                (
                    ("fuzz_test.go", 8),
                    [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "fuzz_test.go"},
                                "region": {"startLine": 8},
                            }
                        }
                    ],
                ),
                (
                    ("fuzz_test.go", None),
                    [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "fuzz_test.go"}
                            }
                        }
                    ],
                ),
                (None, []),
            ):
                with (
                    self.subTest(location=location),
                    tempfile.TemporaryDirectory(dir=root) as output,
                ):
                    # GIVEN
                    findings = Findings(target)
                    finding = Finding(
                        target, "seed#0", "context\nactual failure", location
                    )
                    findings.add(finding)
                    writer = SarifReportWriter()

                    # WHEN
                    report = writer.write(Path(output), [], findings)

                    # THEN
                    result = json.loads(report.read_text())["runs"][0]["results"][0]
                    self.assertEqual(result.get("locations", []), expected)
                    self.assertIn("actual failure", result["message"]["text"])
                    self.assertIn("context", result["message"]["text"])
                    self.assertEqual(
                        result["partialFingerprints"]["primaryLocationLineHash"],
                        finding.fingerprint,
                    )
                    self.assertIn("seed#0", result["message"]["text"])

    def test_neither_writer_overwrites_an_existing_file(self):
        for writer, name in (
            (JsonlReportWriter(), "results.jsonl"),
            (SarifReportWriter(), "results.sarif"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                # GIVEN
                root = Path(directory)
                target = Target(TargetSelector("example.org/a", "FuzzA"), root, root)
                original = root / "original"
                original.write_bytes(b"original")
                (root / name).symlink_to(original)
                findings = Findings(target)

                # WHEN / THEN
                with self.assertRaises(FileExistsError):
                    writer.write(root, [], findings)

                # THEN
                self.assertEqual(original.read_bytes(), b"original")
