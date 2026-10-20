# Limitations and fail-closed boundaries

## Source and dependency binding

- Exact target parent/fix commits, trees, blobs and source SHA-256 values are locally available and verified.
- Required C4 creator dependency `ecmascript/compiler/new_object_stub_builder.cpp` blob `05dda56de74949f07a241942be6465beaf94b52a` is named by both C4 commits but the blob body is absent locally. The source-bound rule replay is retained as local evidence, while the overall replay gate remains `blocked`.
- The model's effect-summary sources are only partially present in the local partial clone. Missing source bodies are explicitly recorded in `raw-results.json`; they are not silently treated as verified.
- No target working tree was restored. All exact source bytes were read from Git objects.

## Scanner behavior

- Type-origin vulnerable parent is `unknown`, not `hit`. This is a scanner gap and is not converted to `miss` or safe.
- Type-origin fixed source is also `unknown`; zero candidate is not a clean fixed-miss result.
- Exception-guard parent is a local `hit` with two candidates. These remain `candidate/unassessed`.
- Exception-guard fixed source is `miss` in replay classification with two matched guard observations. `miss` here means no rule candidate, not product safety.
- Safe/unrelated/unknown synthetic controls pass behaviorally. Synthetic controls do not prove product exploitability or accuracy.

## Metrics and security claims

- No independent reliable truth set was used.
- Precision, Recall, FP, FN, TN and zero-error claims are not computed.
- No product entry/permission boundary, trigger condition, concrete CIA impact, authorized PoC, affected product version, CWE/CVE closure or fix revalidation is claimed.
- `validated_vulnerability=0`.

## Environment

- Windows path and bundled Python are used.
- Peak RSS is `PROCESS_MEMORY_COUNTERS.PeakWorkingSetSize` polled at 5 ms.
- Token and monetary cost are unknown because no reliable local meter is available.
- The shell startup profile emits an unrelated missing `openclaw.ps1` warning. Commands and Python exit codes are recorded independently.

## Git-operation deviation

During initial inspection, a broad multi-file `git diff` on the partial-clone target caused Git to attempt a lazy object fetch to GitHub. The connection failed and no fetch completed. No target worktree files were restored or modified. All subsequent target reads explicitly used `GIT_NO_LAZY_FETCH=1`, `GIT_ALLOW_PROTOCOL=`, `GIT_NO_REPLACE_OBJECTS=1`, and exact local object requests. This failed implicit lazy-fetch attempt is retained here as an operational deviation, not hidden.

## Output scope

Only `research/experiments/ark_runtime/c9_current_history_replay_20261019/` was added in the specified worktree. Existing c8 evidence, Detectors, contracts, Runner, Catalog, historical IDs, fixtures and manifests were not modified.

## Test scope

- The focused c9 suite contains 9 tests and passes.
- The Ark Runtime discovery suite contains 121 tests. The measured run has 2 failures and 2 errors:
  - 2 failures are the exact type-origin known-parent scanner gap documented in `scanner-gap.md`.
  - 2 errors are environmental/input-scope limitations: a current-component commit is absent from the supplied partial object store, and a test attempts to read a deleted target working-tree file rather than the pinned blob.
- The missing current-component object and deleted target worktree are preserved fail-closed; no fetch or restore was performed.
- Syntax validation uses in-memory `compile()` through `compile_check.py` to avoid Windows `PYTHONPYCACHEPREFIX` path-length errors and to avoid writing bytecode outside the c9 evidence directory.
