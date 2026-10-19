# D12 conservative candidate retention for same-name sensitive types

## Change

Detector `ohscanner.data.sensitive_exposure` is now 0.8.0; the source model is 0.2.0. The detailed local flow previously dropped a modeled field whenever a same-name local type declaration made record identity ambiguous. It now preserves a candidate for the configured sensitive field and attaches a `type_identity` evidence obligation. This keeps the uncertainty visible to later review instead of silently treating the possible flow as clean.

The model explicitly records `SessionKey.len` as non-sensitive metadata. A same-name `SessionKey::len` read therefore does not become a secret-material candidate. Other fields remain uncertain and are propagated only when the object itself is already tainted. The detector still does not infer compiler type identity, aliasing, or product impact.

Regression coverage includes:

- A modeled `SessionKey*` parameter in a function other than the reviewed callback reaches a public HiLog sink and remains a candidate.
- The same parameter at a private sink and an unrelated `const char*` at a public sink produce no sensitive-material finding.
- A same-name `SessionKey` declaration with a public `value` sink retains one candidate with `type_identity` obligation and partial coverage.
- The same-name type's explicit `len` metadata field remains non-sensitive.

The D5 semantic manifest adds an override for the new shadow-type candidate. The D1 fixture manifest and its frozen SHA-256 history were left unchanged.

## Replays

`D12_REAL_SOURCE_REPLAY.json` verifies all 10 D10 DSoftBus manifest files and three HiLog API headers, scans nine C/C++ files, and reproduces 3 complete / 6 partial with one candidate: the unresolved cross-file `AuthSessionSaveSessionKey` call at `auth_hichain.c:136`. The added field-identity rule did not add a candidate to this real-source profile.

`D12_D4_HISTORICAL_REPLAY.json` replays 11 manifest-bound source files per D4 revision. Both revisions remain blocked at 5 complete / 6 partial; the old body yields one candidate and the post-log-hardening body zero. This is a static candidate delta, not a product vulnerability or deployed fix proof.

## Validation and limits

D data suite: 53 tests passed. Full Python suite: 887 tests, 882 passed / 5 skipped / 0 failed. Web suite: 16/16 passed; TypeScript and production build passed using the project Linux Node 22 runtime. `npm ci` from the locked manifest reported 0 vulnerabilities. `compileall` and `git diff --check` passed. `validated_vulnerability=0`; product impact and affected releases remain unknown. Product H01–H08 remain `not_run`; no independent blind holdout, public Git Runner integration, default Catalog registration, or one-click enablement is claimed. See the immutable stage reports for exact source, tree, blob, and result hashes.
