"""Write a standalone SARIF report for one target."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..fuzzing import Findings


class SarifReportWriter:
    def write(self, directory: Path, _logs: Iterable[Path], findings: Findings) -> Path:
        """Write a standalone SARIF analysis for this target."""
        target = findings.target
        selector = target.selector
        rule_id = f"go-fuzz/{selector.package}/{selector.name}"

        rule = {
            "id": rule_id,
            "name": selector.name,
            "shortDescription": {
                "text": f"Go fuzz target {selector.package}/{selector.name}"
            },
        }

        results: list[dict[str, Any]] = []
        for finding in sorted(findings, key=lambda f: f.key):
            reference = finding.reference

            message = [
                finding.message,
                f"Package: {selector.package}",
                f"Target: {selector.name}",
                f"Go input reference: {reference}",
            ]

            properties = {
                "goFuzzPackage": selector.package,
                "goFuzzTarget": selector.name,
                "goFuzzInputKind": finding.input_kind,
                "goFuzzInputReference": reference,
            }

            if finding.corpus is not None:
                reference = finding.corpus.digest
                properties["goFuzzInputSHA256"] = reference
                properties["goFuzzCorpusFilename"] = reference

                seed_path = (
                    target.seed_directory.relative_to(target.project) / reference
                ).as_posix()
                message.extend(
                    [
                        f"SHA-256: {reference}",
                        f"Copy error-corpus file {reference} to {seed_path} for reproduction.",
                    ]
                )

            message.append(f"Reproduce: {finding.reproduction_command}")

            locations: list[dict[str, Any]] = []
            if finding.location is not None:
                uri, line = finding.location
                physical: dict[str, Any] = {"artifactLocation": {"uri": quote(uri)}}
                if line is not None:
                    physical["region"] = {"startLine": line}
                else:
                    message.append(
                        "Location is diagnostic context; Go output does not identify one failure line."
                    )
                locations.append({"physicalLocation": physical})

            results.append(
                {
                    "ruleId": rule_id,
                    "kind": "fail",
                    "level": "error",
                    "message": {"text": "\n".join(message)},
                    "locations": locations,
                    "partialFingerprints": {
                        "primaryLocationLineHash": finding.fingerprint
                    },
                    "properties": properties,
                }
            )

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Go Fuzzing", "rules": [rule]}},
                    "results": results,
                }
            ],
        }

        path = directory / "results.sarif"

        with path.open("x", encoding="utf-8") as stream:
            json.dump(sarif, stream, indent=2, ensure_ascii=False)
            stream.write("\n")

        return path
