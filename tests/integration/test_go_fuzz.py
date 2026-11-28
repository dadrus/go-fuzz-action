"""End-to-end tests using the native Go toolchain and flat corpora."""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from go_fuzz import Config, FuzzActionError, FuzzAnalyzer, ResultsFormat

PACKAGE = "example.com/fixture/internal/a"
NATIVE = b"go test fuzz v1\n"


@unittest.skipUnless(shutil.which("go"), "Go toolchain not installed")
class TestNativeGo(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.project = self.root / "project"
        self.nested = self.project / "internal/a"
        self.nested.mkdir(parents=True)
        (self.project / "go.mod").write_text("module example.com/fixture\n\ngo 1.23\n")
        (self.nested / "fuzz_test.go").write_text("""package a
import (
    "fmt"
    "testing"
)
func FuzzKnown(f *testing.F) {
    f.Add("ok")
    f.Fuzz(func(t *testing.T, s string) {
        if s == "known-bad-one" || s == "known-bad-two" { t.Fatal("known failure") }
        if s == "panic-known" {
            t.Run("child", func(t *testing.T) {
                t.Log("nested panic context")
                panic("known panic")
            })
        }
    })
}
func FuzzSeed(f *testing.F) {
    f.Add("bad")
    f.Fuzz(func(t *testing.T, s string) { if s == "bad" { t.Fatal("bad seed") } })
}
func FuzzGenerated(f *testing.F) {
    f.Add("a")
    f.Fuzz(func(t *testing.T, s string) { if len(s) > 1 { t.Fatal("generated failure") } })
}
func FuzzSafe(f *testing.F) {
    f.Add("ok")
    f.Fuzz(func(t *testing.T, s string) {})
}
func FuzzOther(f *testing.F) { panic("must not be executed") }
func FuzzSetupFailure(f *testing.F) {
    fmt.Println("failure while testing seed corpus entry: FuzzSetupFailure/seed#0")
    f.Fatal("setup failed before any input")
}
func FuzzLogged(f *testing.F) {
    f.Add("bad")
    f.Fuzz(func(t *testing.T, s string) {
        t.Log("normal context, not a failure")
        if s == "bad" { t.Fatal("actual failure") }
    })
}
func FuzzNoLocation(f *testing.F) {
    f.Add("bad")
    f.Fuzz(func(t *testing.T, s string) { t.Fail() })
}
""")

        self.errors = self.root / "error-input"
        self.coverage = self.root / "coverage-input"
        self.errors.mkdir()
        self.coverage.mkdir()

        self.enterContext(patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}))

    def run_target(self, target, **kwargs):
        return FuzzAnalyzer(
            Config(
                **{
                    "workspace": self.project,
                    "package": PACKAGE,
                    "target": target,
                    "fuzztime": "1x",
                    "results_format": ResultsFormat.SARIF,
                    **kwargs,
                }
            )
        ).run()

    def input(self, folder, name, value):
        data = NATIVE + f'string("{value}")\n'.encode()
        (folder / name).write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def results(self, outputs):
        return json.loads(outputs.results_file.read_text())["runs"][0]

    def test_known_replays_panic_dedup_and_coverage_exclusion(self):
        # GIVEN
        first = self.input(self.errors, "one", "known-bad-one")
        second = self.input(self.errors, "two", "known-bad-two")
        panic = self.input(self.errors, "panic", "panic-known")
        self.input(self.errors, "duplicate", "known-bad-one")
        self.input(self.errors, "resolved", "fixed")
        self.input(self.coverage, "known-bad", "known-bad-one")
        safe = self.input(self.coverage, "safe", "safe")

        # WHEN
        outputs = self.run_target(
            "FuzzKnown",
            coverage_corpus=self.coverage,
            error_corpus=self.errors,
        )

        # THEN
        self.assertEqual(outputs.findings_count, 3)

        results = self.results(outputs)

        self.assertEqual(len(results["tool"]["driver"]["rules"]), 1)
        self.assertEqual(
            {r["properties"]["goFuzzInputSHA256"] for r in results["results"]},
            {first, second, panic},
        )
        panic_result = next(
            r
            for r in results["results"]
            if r["properties"]["goFuzzInputSHA256"] == panic
        )
        self.assertIn("panic: known panic", panic_result["message"]["text"])
        self.assertEqual(
            {p.name for p in outputs.error_corpus.iterdir()},
            {first, second, panic},
        )

        output_hashes = {
            hashlib.sha256(p.read_bytes()).hexdigest()
            for p in outputs.coverage_corpus.iterdir()
        }

        self.assertIn(safe, output_hashes)
        self.assertNotIn(first, output_hashes)
        self.assertEqual(len(list(self.errors.iterdir())), 5)
        self.assertFalse((self.nested / "testdata").exists())
        self.assertIn("nested panic context", panic_result["message"]["text"])

    def test_independent_process_failure_invalidates_analysis(self):
        # GIVEN
        (self.nested / "main_test.go").write_text("""package a
import (
    "os"
    "testing"
)
func TestMain(m *testing.M) {
    code := m.Run()
    if code == 1 {
        os.Exit(2)
    }
    os.Exit(code)
}
""")
        self.input(self.errors, "known", "known-bad-one")
        for target, errors in (("FuzzKnown", self.errors), ("FuzzSeed", None)):
            with self.subTest(target=target):
                previous = set(self.root.glob("go-fuzz-results-*"))

                # WHEN / THEN
                with self.assertRaises(FuzzActionError):
                    self.run_target(target, error_corpus=errors)

                # THEN
                self.assertEqual(set(self.root.glob("go-fuzz-results-*")), previous)

    def test_signal_termination_after_finding_invalidates_analysis(self):
        # GIVEN
        (self.nested / "main_test.go").write_text("""package a
import (
    "os"
    "syscall"
    "testing"
)
func TestMain(m *testing.M) {
    code := m.Run()
    if code == 1 {
        if err := syscall.Kill(syscall.Getpid(), syscall.SIGKILL); err != nil {
            panic(err)
        }
    }
    os.Exit(code)
}
""")
        self.input(self.errors, "known", "known-bad-one")
        for target, errors in (("FuzzKnown", self.errors), ("FuzzSeed", None)):
            with self.subTest(target=target):
                previous = set(self.root.glob("go-fuzz-results-*"))

                # WHEN / THEN
                with self.assertRaisesRegex(
                    FuzzActionError, "Abnormal native Go test process exit"
                ):
                    self.run_target(target, error_corpus=errors)

                # THEN
                self.assertEqual(set(self.root.glob("go-fuzz-results-*")), previous)

    def test_nested_failure_diagnostics_and_location_survive_replay(self):
        # GIVEN
        helper = self.project / "helper"
        helper.mkdir()
        (helper / "helper.go").write_text("""package helper
import "testing"
func Fail(t *testing.T) { t.Fatal("nested helper failure") }
""")
        (self.nested / "helper.go").write_text("package a\n")
        (self.nested / "nested_test.go").write_text("""package a
import (
    "testing"
    "example.com/fixture/helper"
)
func FuzzNested(f *testing.F) {
    f.Fuzz(func(t *testing.T, s string) {
        if s == "bad" {
            t.Run("child", func(t *testing.T) {
                t.Run("grandchild", func(t *testing.T) { helper.Fail(t) })
            })
        }
    })
}
""")
        seeds = self.nested / "testdata/fuzz/FuzzNested"
        seeds.mkdir(parents=True)
        digest = self.input(seeds, "checked-in", "bad")
        runner = self.root / "runner with spaces"
        runner.mkdir()
        expected = {
            "artifactLocation": {"uri": "helper/helper.go"},
            "region": {"startLine": 3},
        }

        with patch.dict(os.environ, {"RUNNER_TEMP": str(runner)}):
            # WHEN
            first = self.run_target("FuzzNested")

            # THEN
            self.assertEqual(first.findings_count, 1)
            first_result = self.results(first)["results"][0]
            self.assertIn("nested helper failure", first_result["message"]["text"])
            with self.subTest(phase="initial location"):
                self.assertEqual(
                    first_result["locations"], [{"physicalLocation": expected}]
                )
            self.assertEqual(
                (first.error_corpus / digest).read_bytes(),
                (seeds / "checked-in").read_bytes(),
            )

            # GIVEN
            errors = first.error_corpus

            # WHEN
            second = self.run_target("FuzzNested", error_corpus=errors)

            # THEN
            self.assertEqual(second.findings_count, 1)
            second_result = self.results(second)["results"][0]
            with self.subTest(phase="replay diagnostic"):
                self.assertIn("nested helper failure", second_result["message"]["text"])
            with self.subTest(phase="replay location"):
                self.assertEqual(
                    second_result["locations"], [{"physicalLocation": expected}]
                )
            self.assertEqual(
                first_result["partialFingerprints"],
                second_result["partialFingerprints"],
            )
            self.assertEqual(
                (second.error_corpus / digest).read_bytes(),
                (errors / digest).read_bytes(),
            )
            self.assertEqual(list(seeds.iterdir()), [seeds / "checked-in"])

    def test_source_seed_failure_needs_no_file(self):
        # GIVEN
        target = "FuzzSeed"

        # WHEN
        outputs = self.run_target(target, fuzztime="1s")

        # THEN
        self.assertEqual(outputs.findings_count, 1)
        self.assertEqual(list(outputs.error_corpus.iterdir()), [])

        result = self.results(outputs)["results"][0]

        self.assertEqual(result["properties"]["goFuzzInputReference"], "seed#0")
        self.assertIn("bad seed", result["message"]["text"])
        self.assertFalse((self.nested / "testdata").exists())

    def test_setup_failure_is_not_a_seed_finding(self):
        # GIVEN
        target = "FuzzSetupFailure"

        # WHEN / THEN
        with self.assertRaisesRegex(FuzzActionError, "attributable input or seed"):
            self.run_target(target, fuzztime="1s")

        # THEN
        self.assertEqual(list(self.root.glob("go-fuzz-results-*")), [])

    def test_sarif_retains_the_native_diagnostic_without_guessing_a_line(self):
        # GIVEN
        target = "FuzzLogged"

        # WHEN
        outputs = self.run_target(target, fuzztime="1s")

        # THEN
        result = self.results(outputs)["results"][0]
        self.assertEqual(outputs.findings_count, 1)
        self.assertIn("normal context, not a failure", result["message"]["text"])
        self.assertIn("actual failure", result["message"]["text"])
        self.assertEqual(
            result["locations"][0]["physicalLocation"],
            {"artifactLocation": {"uri": "internal/a/fuzz_test.go"}},
        )

    def test_missing_location_preserves_finding_in_both_formats(self):
        # GIVEN
        target = "FuzzNoLocation"
        for results_format in (ResultsFormat.SARIF, ResultsFormat.JSONL):
            with self.subTest(results_format=results_format):
                # WHEN
                outputs = self.run_target(
                    target, fuzztime="1s", results_format=results_format
                )

                # THEN
                self.assertEqual(outputs.findings_count, 1)
                self.assertEqual(list(outputs.error_corpus.iterdir()), [])
                self.assertTrue(outputs.coverage_corpus.is_dir())
                if results_format is ResultsFormat.SARIF:
                    result = self.results(outputs)["results"][0]
                    self.assertFalse(result.get("locations"))
                    self.assertEqual(
                        result["properties"]["goFuzzInputReference"], "seed#0"
                    )
                else:
                    self.assertIn(
                        "failure while testing seed corpus entry",
                        outputs.results_file.read_text(),
                    )

    def test_generated_failure_is_saved(self):
        # GIVEN
        target = "FuzzGenerated"

        # WHEN
        outputs = self.run_target(target, fuzztime="3s")

        # THEN
        self.assertEqual(outputs.findings_count, 1)

        files = list(outputs.error_corpus.iterdir())

        self.assertEqual(len(files), 1)
        self.assertStartsWith(files[0].read_bytes(), NATIVE)
        self.assertEqual(
            files[0].name,
            hashlib.sha256(files[0].read_bytes()).hexdigest(),
        )
        self.assertFalse((self.nested / "testdata").exists())

    def test_checked_in_seed_is_identified_without_modifying_source(self):
        # GIVEN
        seeds = self.nested / "testdata/fuzz/FuzzKnown"
        seeds.mkdir(parents=True)
        digest = self.input(seeds, "checked-in", "known-bad-one")

        # WHEN
        outputs = self.run_target("FuzzKnown", fuzztime="1s")

        # THEN
        self.assertEqual(outputs.findings_count, 1)

        result = self.results(outputs)["results"][0]

        self.assertEqual(result["properties"]["goFuzzInputReference"], "checked-in")
        self.assertEqual(result["properties"]["goFuzzInputSHA256"], digest)
        self.assertEqual(list(seeds.iterdir()), [seeds / "checked-in"])

    def test_bad_coverage_input_becomes_finding_and_is_removed_from_coverage(self):
        # GIVEN
        self.input(self.coverage, "bad-cache-input", "known-bad-one")

        # WHEN
        outputs = self.run_target(
            "FuzzKnown",
            fuzztime="2s",
            coverage_corpus=self.coverage,
        )

        # THEN
        self.assertEqual(outputs.findings_count, 1)

        failed = {
            hashlib.sha256(p.read_bytes()).hexdigest()
            for p in outputs.error_corpus.iterdir()
        }
        remaining = {
            hashlib.sha256(p.read_bytes()).hexdigest()
            for p in outputs.coverage_corpus.iterdir()
        }

        self.assertTrue(failed)
        self.assertTrue(failed.isdisjoint(remaining))

    def test_malformed_coverage_follows_native_cache_behavior(self):
        # GIVEN
        broken = self.coverage / "broken"
        broken.write_bytes(b"not a Go corpus")
        # Go ignores both malformed content and mismatched types in its cache.
        (self.coverage / "wrong-type").write_bytes(NATIVE + b"int(1)\n")

        # WHEN
        outputs = self.run_target(
            "FuzzSafe",
            fuzztime="+300ms",
            coverage_corpus=self.coverage,
        )

        # THEN
        self.assertEqual(outputs.findings_count, 0)
        self.assertEqual(list(outputs.error_corpus.iterdir()), [])
        # The Action exports the cache, not a second independently parsed corpus.
        for name in ("broken", "wrong-type"):
            self.assertEqual(
                (outputs.coverage_corpus / name).read_bytes(),
                (self.coverage / name).read_bytes(),
            )

    def test_malformed_error_corpus_is_technical_failure(self):
        # GIVEN
        broken = self.errors / "broken"
        broken.write_bytes(b"not a Go corpus")

        # WHEN / THEN
        with self.assertRaises(FuzzActionError):
            self.run_target("FuzzSafe", error_corpus=self.errors)

        # THEN
        self.assertEqual(broken.read_bytes(), b"not a Go corpus")

    def test_invalid_budget_is_technical_failure(self):
        # GIVEN
        budget = "-run=.*"

        # WHEN / THEN
        with self.assertRaises(FuzzActionError):
            self.run_target("FuzzSafe", fuzztime=budget)

    def test_missing_target_is_technical_failure(self):
        # GIVEN
        target = "FuzzMissing"

        # WHEN / THEN
        with self.assertRaises(FuzzActionError):
            self.run_target(target)
