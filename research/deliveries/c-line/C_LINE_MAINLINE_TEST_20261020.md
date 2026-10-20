# C-line mainline integration test closeout — 2026-10-20

## Snapshots

- Baseline main: `4b0e16576a45a111b4fad7e8f82819a47ed472f5`
- Baseline tree: `a73b7aafcca12e8e76fd96eca8684ef505a38b37`
- Developer integration commit: `eb43f462769b315e87f7716f237c58b66f058acd`
- Independent cherry-pick: `aca80291c` (same tree as developer commit: `5482258a9f6cd30761f50710c580a29c96489be9`)
- Test branch: `codex/c-mainline-test-closeout-20261020`

The developer commit has the requested baseline as its sole parent. Its 86 changed paths are confined to the Ark Runtime detector, detector Catalog, shared Runner applicability-selector support, and Ark Runtime/source-binding tests and fixtures. No parser implementation or unrelated shared platform code was included.

## Baseline and integrated results

Windows Python 3.13.9 baseline command:

```text
python -m unittest discover -s tests/detectors/ark_runtime -t .
Ran 149 tests; 1 failure; 3 skipped.
```

The only baseline failure was `ArkRuntimeCatalogTests.test_static_candidate_is_explicit_and_default_off`: the existing assertion expected `research_only_explicit_selection`, while baseline Catalog metadata already said `explicit_selection_required: exact C1 repository/commit/target/creator blob profile only; partial or unsupported source remains unknown`. This failure predates the C integration.

After the cherry-pick, the same Windows command ran 212 tests: all passed, 3 skipped. The updated Catalog assertion now matches its explicit-selection metadata.

For D104/source-identity/parser and public compatibility coverage, used a separate Python 3.12.15 WSL venv with `tree-sitter`, `tree-sitter-c`, and `tree-sitter-cpp`. Because this worktree is registered through a Windows absolute `.git` pointer, the Linux test invocation supplied `GIT_DIR` and `GIT_WORK_TREE` so subprocesses could inspect the same Git object database.

Baseline and integrated command:

```text
python -m unittest tests.test_contract_v2_source_binding tests.test_ohscanner_contract tests.test_audit_plan tests.detectors.test_known_case_corpus tests.detectors.ark_runtime.test_catalog tests.detectors.ark_runtime.test_parser_owner tests.detectors.ark_runtime.test_detector_cases
```

- Baseline: 95 tests, 1 failure, 1 skipped. Its sole failure is the same pre-existing Catalog reason-string assertion.
- Integrated: 97 tests, all passed, 1 skipped. The 2 additional tests are integration tests added by the C commit.

Thus D104 known-case/source identity, Catalog, parser ownership, public contract/Runner, audit-plan behavior, and detector fixture behavior pass in the integrated snapshot. The focused tests cover default-off admission, explicit selection, exact source binding, and Runner applicability selection.

An initial Windows-only run of the 97-test command could not create a symlink in `test_fixture_symlink_is_rejected` due to Windows error 1314. The Linux venv run completed the same suite successfully; the Windows environment limitation is not an implementation failure.

## Runtime boundary

These results establish static integration and test-suite behavior only. No Ark VM/component runtime execution is counted as either pass or failure here. The separate component build/runtime investigation remains not run to completion and must stay reported as a runtime limitation.

## Reproduction setup

The Linux-compatible baseline checkout was a temporary detached worktree at the baseline SHA and was removed after the baseline run. The integrated test worktree is clean apart from this report before its report-only commit.
