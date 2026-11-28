# Contributing to Go Fuzz Action

Thank you for your interest in contributing to Go Fuzz Action! Contributions of all kinds are welcome.

## How to Contribute

- Give the project a star if you find it useful.
- Improve documentation, examples, or tests.
- Help resolve [open issues](https://github.com/dadrus/go-fuzz-action/issues).
- Report bugs or suggest improvements. Please check for existing issues before opening a new one.

Before starting substantial changes, please discuss your proposal in a GitHub issue.

## Development Environment

The project uses [uv](https://docs.astral.sh/uv/) to manage Python versions, dependencies, and builds.

Fork and clone the repository, install `uv`, and set up the development environment:

```bash
uv sync --locked
```

## Validation

Run the following checks before submitting code changes:

```bash
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync mypy go_fuzz
uv run --no-sync python -m unittest discover -s tests/unit -t . -v
uv run --no-sync python -m unittest discover -s tests/integration -t . -v
uv build
```

## Pull Requests

1. Create a branch based on `main`.
2. Make your changes and update relevant tests and documentation.
3. Ensure that all relevant checks pass.
4. Open a pull request targeting `main` and describe your changes.

> [!NOTE]
> All commits must be [signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits) and verified by GitHub.

Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages and pull request titles, as releases and changelogs are generated automatically.

Please be patient during the review process. This project is maintained on a voluntary basis.

## Licensing

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](./LICENSE).