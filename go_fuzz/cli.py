"""Command-line interface with a machine-readable JSON result."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import FuzzAnalyzer
from .config import Config, ResultsFormat
from .errors import FuzzActionError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reusable native Go fuzz runner")
    parser.add_argument("--workspace", default=str(Path.cwd()))
    parser.add_argument("--package", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--fuzztime", default="30s")
    parser.add_argument("--results-format", default="jsonl", choices=["jsonl", "sarif"])
    parser.add_argument("--coverage-corpus", default="")
    parser.add_argument("--error-corpus", default="")

    args = parser.parse_args(argv)

    try:
        config = Config(
            workspace=Path(args.workspace),
            package=args.package,
            target=args.target,
            fuzztime=args.fuzztime,
            results_format=ResultsFormat(args.results_format),
            coverage_corpus=Path(args.coverage_corpus)
            if args.coverage_corpus
            else None,
            error_corpus=Path(args.error_corpus) if args.error_corpus else None,
        )

        result = FuzzAnalyzer(config).run()

        print(
            json.dumps(
                {
                    "results_file": str(result.results_file),
                    "findings_count": result.findings_count,
                    "coverage_corpus": str(result.coverage_corpus),
                    "error_corpus": str(result.error_corpus),
                }
            ),
            flush=True,
        )
    except (FuzzActionError, OSError, ValueError) as exc:
        message = (
            str(exc)
            if isinstance(exc, FuzzActionError)
            else "Filesystem or configuration error"
        )

        print(f"[go-fuzz] ERROR: {message}", file=sys.stderr, flush=True)

        return 1

    return 0
