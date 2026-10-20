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

## Catalog marker correction and final replay

The baseline failure was returned to the development line. Its follow-up commit, `764f7698f6babdcccb2cd68eba75ed1b0afefc9e`, is based on the same main baseline and changes the Catalog admission marker, the matching C Catalog assertion, and adds the mainline integration report. I cherry-picked it onto the independent test branch as `4f01d4336`; the resulting code tree is `d424746401212024b3fd3dcc0b25b05d87095bba`. The Catalog remains default-off and explicit-selection-only; the admission reason now includes the baseline marker expected by the original test.

On that final code tree:

```text
python -m unittest tests.detectors.ark_runtime.test_catalog.ArkRuntimeCatalogTests.test_static_candidate_is_explicit_and_default_off
Ran 1 test; OK.

python -m unittest discover -s tests/detectors/ark_runtime -t .
Ran 212 tests; OK; 3 skipped.

python -m unittest tests.test_contract_v2_source_binding tests.test_ohscanner_contract tests.test_audit_plan tests.detectors.test_known_case_corpus tests.detectors.ark_runtime.test_catalog tests.detectors.ark_runtime.test_parser_owner tests.detectors.ark_runtime.test_detector_cases
Ran 97 tests; OK; 1 skipped.
```

The last command ran in the isolated Python 3.12.15 WSL venv with the Git environment described above. It confirms the corrected marker clears the baseline failure while Runner applicability, exact source binding, D104 known-case identity, Catalog, and parser ownership remain passing. `git diff --check` passed for the complete integrated code at `4f01d4336`.

## Independent replay on the current test branch

On 2026-10-20, I reran the suites from test-branch commit `1314902796d4a9f50347a36563281de989eb333a` (tree `1ffe9d57a952a9fc817c3f2ea727465ab01b2c28`). The only difference from code tree `d424746401212024b3fd3dcc0b25b05d87095bba` is report documentation; no production or test source paths changed.

Environment: WSL Python 3.12.15, `/tmp/ohscanner-c-mainline-test-venv`, with `GIT_DIR=/mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit/.git/worktrees/c-mainline-test-closeout-20261020` and `GIT_WORK_TREE=/mnt/d/openHarmonyScanner/worktrees/c-mainline-test-closeout-20261020` so source identity tests read the shared Windows-host Git object database.

Results:

```text
python -B -m unittest discover -s tests/detectors/ark_runtime -t . -q
Ran 212 tests; OK; 3 skipped.

python -B -m unittest tests.test_contract_v2_source_binding tests.test_ohscanner_contract tests.test_audit_plan tests.detectors.test_known_case_corpus tests.detectors.ark_runtime.test_catalog tests.detectors.ark_runtime.test_parser_owner tests.detectors.ark_runtime.test_detector_cases -q
Ran 97 tests; OK; 1 skipped.
```

The three Ark skips are the exact historical exception-guard replay and receiver-guard replay (their pinned Ark Git stores were not supplied), plus parser-owner's bound TypedArray repository case (`OHSCANNER_ARK_REPO` was not configured). Those results remain skipped, not passes. No component runtime execution or accuracy measurement was performed. The applicable synthetic tests cover exact source binding, default-off/explicit Catalog selection, wrong identities, fixed and safe controls, and unknown/partial outcomes.

## Exact developer SHA replay

At the developer line's request, I checked out exact commit `4e1268a980fd103326c7dbaa6ca2e78d2ba43e69` detached in this isolated test worktree and ran the same suites. The tested commit tree is `0495b0db7d05f02e2ce4e48149f7571c8bdd8023`; its first parent is C integration report fix `764f7698f6babdcccb2cd68eba75ed1b0afefc9e`, and its second parent is `origin/main` snapshot `c380a474718e8ec4497aff55b18a1dd38bafa13f`.

```text
python -B -m unittest discover -s tests/detectors/ark_runtime -t . -q
Ran 212 tests; OK; 3 skipped.

python -B -m unittest tests.test_contract_v2_source_binding tests.test_ohscanner_contract tests.test_audit_plan tests.detectors.test_known_case_corpus tests.detectors.ark_runtime.test_catalog tests.detectors.ark_runtime.test_parser_owner tests.detectors.ark_runtime.test_detector_cases -q
Ran 97 tests; OK; 1 skipped.
```

Environment and skip reasons match the preceding replay: Python 3.12.15 WSL venv; two pinned historical Ark Git replay cases skipped because no local pinned source store was supplied, and one repository-bound TypedArray case skipped because `OHSCANNER_ARK_REPO` was unset. No implicit source fetch occurred. `git diff --check` on the exact commit's integration patch passed. This independently confirms the latest-main integration preserves source-bound admission, fixed/wrong-identity controls, partial/unknown handling, and Runner applicability without promoting candidates or treating zero findings as safe.
