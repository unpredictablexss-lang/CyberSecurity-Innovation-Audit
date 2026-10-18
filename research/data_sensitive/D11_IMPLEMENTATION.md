# D11 bounded sensitive-member flow

## Change

Detector `ohscanner.data.sensitive_exposure` is now version 0.7.0. The local flow model recognizes a direct `object.field` lvalue only when the object's declared type is an explicitly modeled sensitive record, the field is the configured sensitive field, and the type is not shadowed. It propagates modeled copy/output/assignment flows through that member. Pointer-member destinations such as `out->key`, aliases, and unmodeled types remain unresolved.

This removes the two D10 local crypto-copy findings where `EncryptData` and `DecryptData` copy key material into local `cipherKey.key` and pass it to crypto routines without reaching a public-log sink in the reviewed function. The call through `AuthSessionSaveSessionKey` remains one unresolved cross-file candidate.

The D10 replay now reads cached pinned source/API data by default. Network retrieval requires the explicit `--fetch-upstream` flag. Tests cover missing cache, cached reads, and missing API metadata without network access.

## Validation

- Full Python suite: 881 tests run, 876 passed, 5 skipped.
- DSoftBus manifest-bound replay: 10/10 manifest files verified; 9 source files scanned; 3 HiLog API headers verified.
- Parse status: 3 complete, 6 partial. Detector status: blocked. Candidate findings: 1. `validated_vulnerability=0`.
- `git diff --check` passed.

## Limits

This is direct selected-file detector invocation, not complete Git Runner/API/Worker integration, an independent labeled holdout, or a product build/runtime PoC. Product impact and reader access remain unknown. The remaining candidate is not a confirmed product vulnerability. The D line remains research-only and does not meet mainline admission gates.
