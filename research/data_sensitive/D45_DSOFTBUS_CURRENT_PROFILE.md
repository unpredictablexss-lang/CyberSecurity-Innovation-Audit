# D45 current DSoftBus profile replay

Date: 2026-10-19

## Scope and identity

This is a development compatibility replay for the exact `openharmony/communication_dsoftbus` commit `9f922677e147b939d6db899bde181d609d64711b`, tree `4b114179868d96c69eedc4520037552ddc3d65dd`. Git operations read pinned objects with lazy fetch and network disabled. No checkout/ref was changed.

The source contract was checked at the pinned tree: `SessionKey.value` and AES key fields contain key material; `SoftBusGenerateSessionKey` writes through argument 0; `OnSessionKeyReturned` receives the session key at argument 1; and `AUTH_LOGI` preserves the format argument position. This justifies exact-commit profile eligibility. It does not establish that a deployed product logs or exposes the key.

Five source files were read by commit:path and bound by tree, blob IDs, byte sizes, and SHA-256 in [D45_DSOFTBUS_CURRENT_PROFILE.json](D45_DSOFTBUS_CURRENT_PROFILE.json). The snapshot digest is `a12f8757440bdf91d4c4eab09b53412312068060b617eeeeccbafb06f7890bcd`.

## Replay

Detector `ohscanner.data.sensitive_exposure` 0.19.0, source model 0.4.0, profile catalog 0.2.0, sink model 0.8.0 ran twice against the same five files. Both runs had the same one finding and the same coverage:

- one `data.sensitive.unresolved-escape` candidate at `core/authentication/src/auth_hichain.c:136`;
- source is `OnSessionKeyReturned` argument 1; unresolved call is `AuthSessionSaveSessionKey`;
- all five selected files are `partial`; aggregate detector status is `blocked`;
- replay times were 0.0252 s and 0.0213 s; process peak RSS was 25,520 KiB.

The candidate keeps four open obligations: exact callee binding, callee sink behavior, runtime log visibility, and concrete security impact. It does not claim a log sink or an exploitable product issue. `validated_vulnerability=0`.

## Interpretation and limits

The new exact-commit profile and regression test make this newer DSoftBus source snapshot eligible for the reviewed component model. The paired synthetic regression also checks that logging raw `sessionKey` can emit a candidate while logging only `sessionKeyLen` does not. These are compatibility and rule-regression checks, not independent holdout labels, product PoCs, or a TP/FP/recall measurement.

The page integration was already present on main: the repository audit page exposes the D sensitive-flow detector as a separate opt-in research option; D44 exercised selection, plan, Worker, evidence, and report rendering with a synthetic fixed Git fixture. D45 adds no new panel route or product-semantic coverage. The detector remains research-only and default-off.

No confirmed product vulnerability was established in this replay, so no product vulnerability PoC or product remediation report is warranted from this evidence. M2 (independent labeled holdout and accuracy/coverage evaluation) and M3 (product entry, impact, reproducible product PoC, affected versions, and fixed-product retest) remain unmet.
