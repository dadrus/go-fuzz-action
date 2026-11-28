[![CI](https://github.com/dadrus/go-fuzz-action/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dadrus/go-fuzz-action/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/dadrus/go-fuzz-action/branch/main/graph/badge.svg)](https://codecov.io/gh/dadrus/go-fuzz-action)

# Go Fuzz Action

This action enables continuous fuzzing workflows for Go projects (Go 1.21 or newer) using Go's [native fuzzing support](https://go.dev/doc/security/fuzz/) by:

- Replaying previously discovered failing inputs (*error corpus*) to identify persistent bugs.
- Reusing inputs retained by Go for further exploration (*coverage corpus*), excluding inputs that still fail.
- Exploring the selected fuzz target using the restored coverage corpus and the project's own seeds.
- Exporting updated corpora for subsequent runs.
- Providing reports in JSONL or SARIF format for further processing and integration with e.g., GitHub Code Scanning.

Each invocation analyzes a single fuzz target in a temporary copy of the project with a dedicated Go cache.

The action is stateless, requires neither additional Python packages nor additional infrastructure, and runs entirely on the workflow runner. Go toolchain setup, target selection, execution frequency, corpus persistence and handling of findings are controlled by the consuming workflow.

## Prerequisites

The action runs on Linux runners with Python 3.14 or newer (available as `python3`), Bash, and `jq`. GitHub-hosted runners based on Ubuntu 26.04 or newer meet these requirements out of the box. On runners with an older Python version, the consuming workflow must provide the required Python version.

## Configuration

### Inputs

```yaml
- uses: dadrus/go-fuzz-action@<commit-sha>
  id: fuzz
  with:
    # Exact import path of the Go package.
    # Required.
    package: example.org/project/parser

    # Exact name of the fuzz function within the package.
    # Required.
    target: FuzzParse

    # Native Go fuzzing budget, e.g. '5m' or '10000x'.
    # Replay and compilation take additional time.
    # Default: '30s'
    fuzztime: '30s'

    # Report format: 'jsonl' for native Go test events
    # or 'sarif' for structured findings.
    # Default: 'jsonl'
    results-format: jsonl

    # Path to an existing, readable, flat directory containing
    # native Go coverage corpus files for the selected target.
    # The directory, its ancestors and entries must be symlink-free.
    # Entries must be regular files with names matching
    # [A-Za-z0-9_.+#-]+, excluding native source seed references.
    # Default: '' (empty corpus)
    coverage-corpus: './fuzz/coverage'

    # Path to the corpus of previously discovered failing inputs.
    # Same directory and file requirements as for coverage-corpus.
    # Default: '' (empty corpus)
    error-corpus: './fuzz/error'
```

### Outputs

The following outputs are available to subsequent steps via `${{ steps.fuzz.outputs.<name> }}`.

| Name | Description | Example |
|---|---|---|
| `results-file` | Absolute path to the generated JSONL or SARIF report. | `/tmp/go-fuzz-results-a1b2c3d4/results.sarif` |
| `findings-count` | Number of distinct currently failing file inputs and source seeds. File inputs are deduplicated by content. | `3` |
| `coverage-corpus` | Absolute path to the updated coverage corpus. Original filenames are preserved and failing inputs are excluded. | `/tmp/go-fuzz-results-a1b2c3d4/coverage` |
| `error-corpus` | Absolute path to the corpus of persistent and newly discovered failing file inputs, named by their SHA-256 content hashes. | `/tmp/go-fuzz-results-a1b2c3d4/error` |

Each completed analysis provides all four outputs in a fresh result directory under `RUNNER_TEMP` (or the system's temporary directory). Both corpus directories exist even if empty. Technical failures fail the action, while findings are returned as analysis results.

## Usage

### A simple setup

The following workflow runs a fuzz target for 30 seconds on demand and uses the `findings-count` output to fail the workflow if any findings are reported.

```yaml
name: Fuzz

on:
  workflow_dispatch:

permissions: {}

jobs:
  fuzz:
    runs-on: ubuntu-26.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<commit-sha>
        with:
          persist-credentials: false

      - uses: actions/setup-go@<commit-sha>
        with:
          go-version-file: go.mod
          cache: false

      - uses: dadrus/go-fuzz-action@<commit-sha>
        id: fuzz
        with:
          package: example.org/project/parser
          target: FuzzParse

      - name: Fail on findings
        if: steps.fuzz.outputs.findings-count > 0
        run: exit 1
```

### Continuous fuzzing

The following workflow discovers fuzz targets, maintains their individual corpora across runs and publishes findings to GitHub Code Scanning.

The example workflow assumes that the `FUZZ_CORPUS_KEY` environment variable contains the passphrase used to encrypt and decrypt failing inputs and reports.

```yaml
name: Continuous fuzzing

on:
  schedule:
    - cron: '0 2 * * *'
  push:
    branches: [main]
  workflow_dispatch:

permissions: {}

concurrency:
  group: go-fuzz-${{ github.ref }}
  cancel-in-progress: false

defaults:
  run:
    shell: bash

jobs:
  discover:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    outputs:
      targets: ${{ steps.discover.outputs.targets }}

    steps:
      - uses: actions/checkout@<commit-sha>
        with:
          persist-credentials: false

      - uses: actions/setup-go@<commit-sha>
        with:
          go-version-file: go.mod
          cache: false

      # Discover targets and derive unique artifact names.
      - name: Discover targets
        id: discover
        run: |
          targets="$(go test -json -count=1 -list '^Fuzz($|[^a-z])' ./... |
            jq -cs '
              [.[] | select(.Action == "output" and .Test == null and .Package != null)
                | select(.Output | test("^Fuzz[\\p{L}\\p{Nd}_]*\n$"))
                | {package: .Package, target: (.Output | rtrimstr("\n"))}
                | . + {id: ((.package + "/" + .target) | @uri)}]
              | unique
            ')"
          echo "targets=$targets" >> "$GITHUB_OUTPUT"

  fuzz:
    needs: discover
    if: needs.discover.outputs.targets != '[]'
    runs-on: ubuntu-26.04
    timeout-minutes: 30
    permissions:
      contents: read
      actions: read
    strategy:
      fail-fast: false
      matrix:
        include: ${{ fromJSON(needs.discover.outputs.targets) }}

    steps:
      - uses: actions/checkout@<commit-sha>
        with:
          persist-credentials: false

      - uses: actions/setup-go@<commit-sha>
        with:
          go-version-file: go.mod
          cache: false

      # Restore the latest available corpora for this target.
      - uses: dawidd6/action-download-artifact@<commit-sha>
        with:
          workflow: fuzz.yaml
          branch: main
          workflow_conclusion: completed
          search_artifacts: true
          allow_forks: false
          name: corpus-${{ matrix.id }}
          name_is_regexp: false
          path: ${{ runner.temp }}/corpora
          if_no_artifact_found: ignore

      # Decrypt failing inputs and initialize missing corpora.
      - name: Restore corpora
        env:
          FUZZ_CORPUS_KEY: ${{ secrets.FUZZ_CORPUS_KEY }}
        run: |
          umask 077
          mkdir -p "$RUNNER_TEMP/corpora/"{coverage,error}

          if [[ -f "$RUNNER_TEMP/corpora/error.tar.gz.gpg" ]]; then
            gpg --batch --no-symkey-cache --pinentry-mode loopback \
              --passphrase-fd 3 --decrypt \
              "$RUNNER_TEMP/corpora/error.tar.gz.gpg" \
              3<<< "$FUZZ_CORPUS_KEY" |
              tar -xz -C "$RUNNER_TEMP/corpora/error"
          fi

      # Replay known failures and explore new inputs.
      - uses: dadrus/go-fuzz-action@<commit-sha>
        id: fuzz
        with:
          package: ${{ matrix.package }}
          target: ${{ matrix.target }}
          fuzztime: 2m
          results-format: sarif
          coverage-corpus: ${{ runner.temp }}/corpora/coverage
          error-corpus: ${{ runner.temp }}/corpora/error

      # Prepare the updated corpora and protect sensitive results.
      - name: Prepare artifacts
        env:
          FUZZ_CORPUS_KEY: ${{ secrets.FUZZ_CORPUS_KEY }}
          COVERAGE: ${{ steps.fuzz.outputs.coverage-corpus }}
          ERROR: ${{ steps.fuzz.outputs.error-corpus }}
          REPORT: ${{ steps.fuzz.outputs.results-file }}
        run: |
          umask 077
          : "${FUZZ_CORPUS_KEY:?Missing encryption passphrase}"
          mkdir "$RUNNER_TEMP/snapshot"
          mv "$COVERAGE" "$RUNNER_TEMP/snapshot/coverage"

          tar -czf - -C "$ERROR" . |
            gpg --batch --no-symkey-cache --pinentry-mode loopback \
              --passphrase-fd 3 --symmetric --cipher-algo AES256 \
              --output "$RUNNER_TEMP/snapshot/error.tar.gz.gpg" \
              3<<< "$FUZZ_CORPUS_KEY"

          gpg --batch --no-symkey-cache --pinentry-mode loopback \
            --passphrase-fd 3 --symmetric --cipher-algo AES256 \
            --output "$RUNNER_TEMP/results.sarif.gpg" \
            "$REPORT" 3<<< "$FUZZ_CORPUS_KEY"

      # Persist the corpora for subsequent runs.
      - uses: actions/upload-artifact@<commit-sha>
        with:
          name: corpus-${{ matrix.id }}
          path: ${{ runner.temp }}/snapshot/
          retention-days: 5
          include-hidden-files: true
          overwrite: true

      # Transfer the report to the publishing job.
      - uses: actions/upload-artifact@<commit-sha>
        with:
          name: sarif-${{ matrix.id }}-${{ github.run_attempt }}
          path: ${{ runner.temp }}/results.sarif.gpg
          retention-days: 1
          compression-level: 0

  publish:
    needs: [discover, fuzz]
    if: ${{ !cancelled() && needs.discover.result == 'success' && needs.discover.outputs.targets != '[]' }}
    runs-on: ubuntu-24.04
    permissions:
      security-events: write
    strategy:
      fail-fast: false
      matrix:
        include: ${{ fromJSON(needs.discover.outputs.targets) }}

    steps:
      # Retrieve the report from the corresponding fuzzing job.
      - uses: actions/download-artifact@<commit-sha>
        with:
          name: sarif-${{ matrix.id }}-${{ github.run_attempt }}
          path: ${{ runner.temp }}/report

      - name: Decrypt report
        env:
          FUZZ_CORPUS_KEY: ${{ secrets.FUZZ_CORPUS_KEY }}
        run: |
          umask 077
          gpg --batch --no-symkey-cache --pinentry-mode loopback \
            --passphrase-fd 3 --decrypt \
            --output "$RUNNER_TEMP/report/results.sarif" \
            "$RUNNER_TEMP/report/results.sarif.gpg" 3<<< "$FUZZ_CORPUS_KEY"

      # Publish findings under a stable category per target.
      - uses: github/codeql-action/upload-sarif@<commit-sha>
        with:
          sarif_file: ${{ runner.temp }}/report/results.sarif
          category: go-fuzz/${{ matrix.package }}/${{ matrix.target }}
```

## If you ...

- ... find the action useful, a :star: is appreciated.
- ... encounter a problem or have an idea for an improvement, feel free to open an [issue](https://github.com/dadrus/go-fuzz-action/issues).
- ... would like to contribute, take a look at the [contributing guide](./CONTRIBUTING.md).

## License

[MIT License](LICENSE).
