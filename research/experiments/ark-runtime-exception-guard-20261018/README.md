# Current issue and executed plan

## Problem

In the pinned TypedArray fix, `NewTypedArray` can raise a pending exception, but `GetObjectType(LoadHClass(newArray))` appears before the `HasPendingException` branch. The v0.2.0 type-origin analysis treated the eventual same-origin store token as `matched`, while leaving this exception-state condition unresolved.

## Plan executed

1. Keep the v0.2.0 exact-source evidence immutable and verify its parent/fix source bindings.
2. Track objects returned by the modeled `NewTypedArray` as exception-sensitive.
3. Permit a type read only after a false `HasPendingException` branch on the current generated path. Any unknown call invalidates the guard fact.
4. Preserve the parent candidate; classify the fixed pre-guard read as `unknown`; confirm a post-guard read remains `matched`.
5. Recheck safe `Set`, unrelated `Map`, and a post-guard unknown-call control; save raw results, commands, and hashes.

## Result

Detector/model version is now 0.3.0. The frozen parent remains `candidate`; the exact fixed source now yields `unknown` with reason `new_typed_array_type_read_before_exception_check`; the analysis also exports this line and reason through coverage limitations. A derived version with the type read after the false exception branch remains `matched`. A later unknown call invalidates that guard and returns to `unknown`. `Set` remains `matched`; `Map` remains without a rule observation.

All exact-source runs remain `limited/partial` because the whole file has parser/dependency limitations and the C lane is not production-admitted. The exception-propagation patch's separate rule is still research-only and not implemented in the formal C Detector. No product build, runtime validation, impact confirmation, or component-wide safety claim is made.

## Verification

Focused command: `python -m unittest research.tests.test_ark_runtime_exception_guard -v` (5 tests). The tests cover exact parent/fix, pre-guard unknown, post-guard safe path, unknown-call invalidation, and safe/unrelated controls. `replay_guard_fix.py` rechecks the actual pinned blobs and hashes before emitting `raw-results.json`.

The exact source IDs, trees, blob OIDs, SHA-256 values, Detector/rule/model/profile/config, limitations and obligations are in `raw-results.json`. `commands.txt` contains replay commands. `hash-manifest.json` includes experiment artifacts, modified C-lane sources, and the focused test file; its detached digest is `hash-manifest.sha256`.

