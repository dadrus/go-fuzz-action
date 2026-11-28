# AGENTS.md

Development and maintenance rules for the Go Fuzz Action. `README.md` documents the public Action contract and usage; this file specifies development conventions and internal invariants.

**Review every change for security implications. Correctness and security take precedence over convenience, abstraction purity, allocation reduction, and performance.**

## Working conventions

- Before editing, read the relevant code, tests, `README.md`, `action.yaml`, and project configuration. Establish intended behavior from documented contracts and actual behavior from code and tests. Investigate discrepancies rather than assuming either is correct.
- Trace affected data and error paths, transformations, fallbacks, trust boundaries, and callers before changing behavior. If Git history is available, compare against the appropriate baseline and distinguish regressions from pre-existing issues.
- Make the smallest coherent change; report unrelated findings separately. Do not bundle unrelated fixes, refactorings, formatting, documentation, dependency updates, or optimizations. Analysis-only requests do not authorize edits or patches.
- Preserve documented Action, CLI, and public Python contracts unless explicitly asked otherwise. Assess, document, and test compatibility changes. Do not turn incidental behavior into a public contract or add unsolicited compatibility aliases.
- Manage minimum and development Python versions deliberately, not through routine dependency updates. Do not change Python requirements, project configuration, lockfiles, or Go toolchain settings merely to accommodate a local environment.

## Design

- Keep `go_fuzz/` independent of GitHub Actions, `action.yaml` a thin adapter, and workflow orchestration outside the Action. Do not add GitHub API calls or target discovery to the core.
- Apply SOLID pragmatically, with **KISS before DRY**. Introduce abstractions only for a concrete responsibility or demonstrable simplification, not structural uniformity or speculative reuse. Choose functions and classes by responsibility, not method count or presence of state.
- Organize modules and subpackages by cohesive domain responsibilities. Keep related result types, alternative constructors, and supporting operations with their owners. Avoid generic utility packages and duplicate domain definitions; extract cohesive shared components when justified. Keep configuration independent of the components it configures.
- Keep package and module dependencies explicit and acyclic, including type-only imports. A package may depend on its own subpackages and sibling packages, never on functionality from a parent package. Each production package declares its interface in `__init__.py` with explicit `__all__`; export only what consumers need, including relevant result and exception types. Import across package boundaries through these interfaces and within packages directly from owning modules. Define cohesive types in `__init__.py` when separate modules offer no structural benefit.
- Define package-specific exceptions for owned failures and keep the common public exception base in a dependency-free sibling package. Propagate dependency failures without homogenizing their types.
- Keep state, behavior, and invariants together. Validate configuration and domain values at construction; represent absence explicitly. Enforce static and context-dependent checks at their respective owners, not only in outer wrappers or optional callers. Avoid redundant validation; use pure functions for genuinely stateless transformations.
- Encapsulate execution context and resource lifecycles rather than threading parameters through helpers. Express the domain sequence in orchestration, not low-level paths, event details, or encoding. Prefer named, typed domain results over anonymous tuples or transport dictionaries. Keep filesystem, subprocess, CLI, and GitHub output boundaries independently testable.
- Follow established conventions. Use nouns for classes, verbs for operations, and responsibility-based module and test names. Avoid repeating enclosing package context; use docstrings for domain meaning and invariants. Preserve descriptive public API names.

## Security

- Treat repository content, package and target names, corpus paths and bytes, Go output, workflow inputs, and environment-derived values as untrusted until validated. Reject malformed, ambiguous, unsafe, or unverifiable inputs rather than silently falling back.
- Enforce the documented corpus restrictions and reject traversal. Protect the original checkout and input corpora from Action-owned writes, including via symlink-resolved temporary roots. Do not accept caller-supplied report destinations or overwrite existing reports.
- Preserve project symlinks. Do not attempt to sandbox project code, police project-owned writes, defend against subsequent tampering by project code or other runner processes (including concurrent manipulation), or guess and scrub arbitrary environment variables. These threat-model boundaries do not relax Action-owned input and write validation.
- Invoke Go with argument vectors, never shell interpolation; retain stdout, stderr, and exit status for classification. Preserve least privilege and the repository's CI and release security controls.
- Prevent structured-output injection: reject NUL, CR, and LF in original and resolved output paths, use fixed output names within a validated result directory, and return an integer finding count. Only the shell adapter translates the CLI result into GitHub outputs; rely on the core's guarantees rather than duplicating validation. Invoke the checkout using `python3 -I "$GITHUB_ACTION_PATH"`, exclude `GITHUB_OUTPUT` from the CLI and its children, and prepare all output lines before writing them.
- Keep console diagnostics useful but free of confidential payloads and secrets. Preserve required report contents without dumping native test output, corpus bytes, or reports to logs. Use no real secrets or private data in fixtures or examples. Handle sensitive evidence carefully; do not disclose vulnerabilities externally or publish advisories unless explicitly asked.

## Implementation invariants

- Delegate Go grammar, native corpus validation, and execution semantics to Go. Do not scan source to discover targets or derive locations, set fixed worker counts, validate the coverage cache separately, or impose additional process timeouts.
- Resolve the exact local package and prove execution of the requested target and replay inputs. An absent target or unproven execution is a technical error. Remove known failures only after demonstrably successful targeted replay; do not replay newly evidenced failures redundantly.
- Preserve project seeds and report native source-seed references without inventing files. Exclude proven failing file inputs from coverage exploration and coverage output by serialized content, not filename. Honor Go's handling of unusable cache entries; malformed error inputs are technical replay failures.
- Classify from native events and process context, never exit status, isolated failure events, or diagnostic text alone. Require a concrete attributable input for findings; ignore irrelevant events. Fail closed on missing or inconsistent required evidence, incomplete execution, or independently evidenced technical errors even when a finding is proven. Do not reconstruct internal Go engine states or attempt to detect deliberately forged output.
- Deduplicate findings by package, target, input kind, and SHA-256 of serialized file bytes or native source-seed reference. When copying corpus files, hash the bytes actually copied, reject identity changes, and discard partial copies without an additional full read.
- Preserve native JSONL events unchanged in execution order. Use one stable SARIF rule per target and a stable, finding-specific `primaryLocationLineHash`. Retain associated native failure diagnostics and reproduction references without ranking messages as presumed causes or inferring security severity. Derive locations only from absolute native paths to existing repository files: use a line number for one distinct evidenced source position, otherwise the first evidenced file without a line. Retain findings without locations; never invent positions.
- The CLI emits exactly one typed JSON object on stdout on complete analysis, no JSON result on technical or incomplete analysis, and diagnostics on stderr. Preserve the documented distinction between findings and technical failures in exit status.

## Python style and resources

- Use `pyproject.toml` as the source of truth for Python compatibility, Ruff, and mypy. Use `uv` for development, tests, and builds only. Do not add runtime Python dependencies without explicit justification and approval.
- Write idiomatic, explicit, typed Python supported by the minimum version. Prefer native language and standard-library facilities, `pathlib`, clear names, cohesive functions, and straightforward control flow.
- Follow configured formatting. Prefer one argument per line with a trailing comma for long calls. Group related statements and separate logical stages by a single blank line, including in tests.
- Refactor genuine complexity rather than raising configured limits or introducing broad suppressions. Justify narrow security exceptions at the relevant code.
- Stream Go output and corpus bytes through files; retain only required classification and reporting metadata. Hash and copy in blocks, not by loading entire corpora or event streams. Avoid premature optimization; measure representative workloads before performance-sensitive changes.

## Tests

- Test the project's observable contracts, not incidental calls, generated methods, or dependency behavior. Test integration with dependencies only where it affects those contracts.
- Mirror production responsibility boundaries in `tests/unit/`. Use `tests/integration/` for interactions between real components or external tools (including the shell adapter and native Go), even when individual dependencies are replaced. Tests may access the owning internal module for testing or patching; otherwise use package interfaces.
- Use one test method per invariant, covering meaningful positive and negative cases. Use subtests or tables only when they improve clarity. Prefer simple fixtures and local fakes or mocks; higher-level tests cover orchestration and error propagation without duplicating component checks.
- Structure tests with `# GIVEN` (setup), `# WHEN` (one invocation), and `# THEN` (assertions); repeat phases for separate scenarios or subtests. Use `assertRaises`/`assertRaisesRegex` with `# WHEN / THEN` for the combined invocation and exception check, and THEN for additional postconditions. Keep live-resource assertions inside their contexts. Do not add helpers or assertions merely to separate phases.
- Move tests with their owning responsibility and remove obsolete overlap. Extend existing tests where clearer; add tests for new behavior, regressions, or uncovered edges. For fixes, reproduce the regression before fixing it when practical.
- Test security invariants at their enforcing component, including valid controls and relevant malformed, missing, duplicate, ambiguous, escaping, symlinked, adversarial, or incomplete inputs.
- Keep tests deterministic, with small native fuzzing fixtures, bounded runtimes, and explicit failure/timeout expectations. Investigate hangs rather than retrying to hide them. Use coverage diagnostically to inspect meaningful branches, not to chase percentages.
- Never weaken validation, reporting, or assertions, or skip, delete, or broadly mock tests merely to obtain a passing run.

## Validation and delivery

- Maintain affected documentation and examples with contract changes. Verify examples against actual interfaces and documented platform contracts; distinguish illustrative examples from tested guarantees. Keep examples out of active repository workflows and do not invent unsupported options.
- Use the declared toolchain and checks in `pyproject.toml` and `.github/workflows/ci.yml`. Run focused tests first, then relevant CI checks when possible, including lint, format, typing, unit and integration tests, and build. Synchronize dependencies in locked mode and avoid implicit resynchronization during checks. Run configured dependency and workflow-security audits for corresponding changes; passing checks are not proof of security.
- For documentation-only changes, check references, commands, and the diff. When Git is available, inspect `git diff` and run `git diff --check`. Review scope, compatibility, security, test ownership, formatting, and generated files.
- Investigate failures before calling them environmental or pre-existing. Report changes, consequential decisions, security and compatibility implications, actual check results, and remaining verification gaps. Do not claim unexecuted checks passed or create routine `TEST_REPORT.md` files.
- Provide patches against the agreed baseline when requested. Do not commit or publish unless explicitly asked.
