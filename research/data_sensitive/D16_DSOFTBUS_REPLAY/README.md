# D16 current DSoftBus fixed-profile replay

Run date: 2026-10-18

## Scope

The existing DSoftBus source model was executed twice using the offline `research.data_sensitive.replay` path and the exact 9-file `source_manifest.json` scope at `openharmony/communication_dsoftbus@0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132` (tree `bd915661eedd139df17f249191e2a691e76f7565`). All selected source blobs were checked against the manifest before execution.

The machine reports are in this folder: `first.json`, `replay.json`, and `summary.json`. The two runs had the same snapshot hash, diagnostic identities, and coverage. Combined execution was 2.59 seconds with peak RSS 32,892 KiB in the recorded Linux Python 3.10.12 / Tree-sitter environment.

## Result

The detector retained one `data.sensitive.unresolved-escape` candidate at `core/authentication/src/auth_hichain.c:136`: `OnSessionKeyReturned` passes the modeled session key to unresolved `AuthSessionSaveSessionKey`. It has no CWE assignment and carries callee-binding, sink-behavior, runtime visibility, and impact obligations. The call site does not itself show a log operation. Treat it as a review candidate, not a logging vulnerability.

Aggregate status is `completed_with_limitations`; per-file coverage is partial: 3/9 files partially inspected and 6/9 not analyzed. No file is complete. The repeated zero-delta comparison means only that two runs of the same version on one frozen input agree; it is not an algorithm comparison or an independent holdout. `validated_vulnerability=0`.

## Follow-up call-chain check

A local copy of `core/authentication/src/auth_session_fsm.c` was compared to the exact 0e0c commit tree: size 92,341 bytes, Git blob `94c1e8af277df3a214298a92f55ef85ce601df93`, SHA-256 `7efaa39d841ea752c342e7233161029694c7ec6725f4eb6ce0285fad686cbcc4`; all identities match. At lines 2153-2160, `AuthSessionSaveSessionKey` posts an `FSM_MSG_SAVE_SESSION_KEY` event. Its handler at lines 2334-2349 copies into a local `SessionKey`, calls `AuthManagerSetSessionKey`, derives HKDF material, and zeroes the local copy. These lines show a state-storage path, but the exact-revision implementation of `AuthManagerSetSessionKey` and its deeper callees has not been bound and reviewed here. The unresolved candidate therefore remains; no safe summary or suppression was added.

## Next analysis

The exact-revision callee binding was completed as a follow-up in [D17](../D17_DSOFTBUS_CALLEE_BINDING.md): the bounded path stores the key in the in-memory session-key list and the inspected functions do not log key bytes. The scanner candidate remains visible because there is no reviewed cross-file summary and downstream readers/product behavior remain unreviewed. Expand parse coverage for the six not-analyzed files and test the source model against independently labelled positive, fixed, safe, and unrelated examples before claiming recall or commercial readiness.
