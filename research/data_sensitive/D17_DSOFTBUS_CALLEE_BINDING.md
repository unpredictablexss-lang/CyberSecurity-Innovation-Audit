# D17 — DSoftBus exact-revision callee binding

Date: 2026-10-18

## Scope and evidence identity

This follow-up resolves the callee-binding obligation left open by the D16 replay. The target remains `openharmony/communication_dsoftbus@0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132`, tree `bd915661eedd139df17f249191e2a691e76f7565`. Source files were fetched from immutable raw URLs for that commit and compared against the commit tree before review:

| Source file | Matching Git blob | Size | SHA-256 |
|---|---|---:|---|
| `core/authentication/src/auth_hichain.c` | `1aadc4dafe81bc42f9916b9bd7aa3f9f0a616c2d` | 22,279 | `4132e6577e6d736a7f922b0344fbcb2002d533f079ee332494ffdf007ec47e7b` |
| `core/authentication/src/auth_session_fsm.c` | `94c1e8af277df3a214298a92f55ef85ce601df93` | 92,341 | `7efaa39d841ea752c342e7233161029694c7ec6725f4eb6ce0285fad686cbcc4` |
| `core/authentication/src/auth_manager.c` | `9e8cd2d56fe5b47b4e550be2e3aca48054278a56` | 100,548 | `5cf888bbf1c89fe5db703446476b6a737f38150b91e31a4bb95a1394dacb4a56` |
| `core/authentication/src/auth_session_key.c` | `0569ee21db9bf2a3ccfd10c020b3c0d45c01cc50` | 23,151 | `5dc2f567cd127876aaaf35f7373c4b5a802a5802607eb7d05e34f62d5870701f` |

Review links: [auth_hichain.c](https://github.com/openharmony/communication_dsoftbus/blob/0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132/core/authentication/src/auth_hichain.c#L120-L140), [auth_session_fsm.c](https://github.com/openharmony/communication_dsoftbus/blob/0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132/core/authentication/src/auth_session_fsm.c#L1893-L1917), [auth_manager.c](https://github.com/openharmony/communication_dsoftbus/blob/0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132/core/authentication/src/auth_manager.c#L784-L831), and [auth_session_key.c](https://github.com/openharmony/communication_dsoftbus/blob/0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132/core/authentication/src/auth_session_key.c#L248-L275).

## Bounded call-chain result

At `auth_hichain.c:136`, `OnSessionKeyReturned` passes the session-key bytes to `AuthSessionSaveSessionKey`. In the same exact revision, that function posts `FSM_MSG_SAVE_SESSION_KEY`; the message helper creates a message parameter from the supplied data and submits it to the auth FSM. The save-event handler copies the bytes into a local `SessionKey` and calls `AuthManagerSetSessionKey`.

`AuthManagerSetSessionKey` validates and resolves the auth manager, then passes the key to `ProcessSessionKey`. `ProcessSessionKey` calls `AddSessionKey`; `auth_session_key.c:248-275` allocates a `SessionKeyItem` and copies the full `SessionKey` into its in-memory list node. The inspected functions log key length, IDs, indices, type, and status metadata, but do not pass key bytes to a logging macro. Old-key removal explicitly zeroes the key field before freeing the node (`auth_session_key.c:64-68`).

This supports an internal session-key storage interpretation for this bounded path. It does not prove whole-component absence of disclosure, audit every reader of the stored key, establish product build/runtime reachability, or measure operational logging behavior.

## Assessment

- Static scanner output: one `data.sensitive.unresolved-escape` **candidate** remains at `auth_hichain.c:136` because the current detector has no cross-file summary for this storage path.
- Logging-vulnerability hypothesis for this bounded call chain: **not supported by the reviewed exact-revision code**; no key-content argument reaches a logging macro in the inspected chain.
- Product vulnerability status: **not confirmed**. Product impact and full downstream behavior remain **unknown**.
- No candidate was upgraded to confirmed, and no product-level safe status was inferred from a component-only source review.

This is a manual evidence follow-up, not a detector suppression or a recall claim. Keep the candidate visible until a reviewed call summary and downstream-reader coverage are implemented and independently tested.

## Reproduction

The D16 fixed-profile replay remains reproducible with the command and frozen scope recorded in [D16](D16_DSOFTBUS_REPLAY/README.md). This review added an exact-tree/blob comparison and a source-level call-chain check; it did not run an OpenHarmony product build, device test, or runtime log capture.
