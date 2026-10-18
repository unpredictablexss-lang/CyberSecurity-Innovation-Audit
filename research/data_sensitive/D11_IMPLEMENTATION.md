# D11 bounded sensitive-member flow and historical replay

## Detector change

Detector `ohscanner.data.sensitive_exposure` is version 0.7.0. The local flow model recognizes a direct `object.field` lvalue only when the object's declared type is an explicitly modeled sensitive record, the field is the configured sensitive field, and the type is not shadowed. It propagates modeled copy/output/assignment flows through that member. Pointer-member destinations such as `out->key`, aliases, and unmodeled types remain unresolved.

This removes the two D10 local crypto-copy findings where `EncryptData` and `DecryptData` copy key material into local `cipherKey.key` and pass it to crypto routines without reaching a public-log sink in the reviewed function. The call through `AuthSessionSaveSessionKey` remains one unresolved cross-file candidate.

## D4 historical source replay

`d11_d4_historical_replay.py` provides a separately labeled, manifest-bound replay for D4's old and post-log-hardening source profiles. Network access is disabled unless `--fetch-upstream` is supplied. It verifies GitHub commit/tree metadata, then verifies each selected source file against its manifest size, SHA-256, and Git blob SHA-1 before invoking the research detector directly.

Current replay: both fixed revisions supplied 11 D4-manifest source files (10 model-required files plus the pinned listener source) and passed all byte checks. Each parsed as 5 complete / 6 partial and therefore remains blocked. The older revision produced 1 historical sensitive-log candidate; the later revision produced 0. This is a reproduced static candidate delta only. It does not prove the product used either build, that runtime logs contained the synthetic or real secret, that an unauthorized reader could access them, or that the source deletion was an effective deployed fix.

The replay evidence is in `D11_D4_HISTORICAL_REPLAY.json`. Downloaded pinned files and API responses are kept in the ignored local `/tmp/ohscanner-d11-d4-source-cache/` directory and are not committed.

## Validation

- D-specific Python suite: 50 tests passed.
- Full Python suite: 884 tests run, 879 passed, 5 skipped.
- DSoftBus D10 current-source replay: 10/10 manifest files and 3 HiLog API headers verified; 9 source files scanned; status blocked with 1 candidate.
- D4 historical replay: 11 manifest source files verified per revision; old 1 candidate / newer 0; both blocked.
- `git diff --check` passed.
- Docker integration is unavailable in this WSL environment. The extracted-function experiment is recorded in `D5_COMPONENT_HARNESS.json`; product H01-H08 remain `not_run`.

## D5 extracted-function component experiment

A separate harness compiled the exact pinned `ProcessReceivedData` bodies from the two D4 revisions and ran three synthetic cases in a rootless no-network namespace and tmpfs chroot. The pre-hardening body sent the synthetic `SESSION_KEY` marker to the logger stub; the post-hardening body did not. Ordinary request/reply processing continued in the stub, and decrypt failure returned an error without exposing the marker. All assertions passed. Source, generated C, binary hashes, and observations are recorded in `D5_COMPONENT_HARNESS.json`.

This is component-only evidence with deterministic stubs. The product H01–H08 matrix remains `not_run`; this does not prove product logs, readers, versions, impact, or a deployed fix. `validated_vulnerability=0`.
## Limits and next gate

The direct replays are not public Git Runner/API/Worker integration, an independent labeled holdout, or a product build/runtime PoC. Product impact and reader access remain unknown. Neither candidate is a confirmed product vulnerability. The D line remains research-only and does not meet mainline admission gates. Before M0, compare against current main in a clean checkout, run latest-main CI and frontend validation, and complete the source/license/security review. H01-H08 require an approved disposable runtime with a pinned image digest; absence of Docker is not a pass.
