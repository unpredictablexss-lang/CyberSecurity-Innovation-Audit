# C-line admission metadata sync request

Date: 2026-10-19 (Asia/Shanghai)
Scope: owner-only metadata follow-up; this request does not change admission or Runner behavior.

## Current authoritative research state

- `research/full_scan_20261018/lanes/c/model.py` is frozen as 0.3.8. The research adapter requires Git-object provenance, binds exact repository, commit, target path, creator and 40 declared source objects per historical profile, and rejects analyzed units outside the pinned target path. The refreshed manifest verifies 40/40 bindings on each profile.
- The C1 product source pin has a separate 33/33 source-only binding manifest covering the sink chain, method/macro registration, inheritance, creator API, selected types, root/compiler GN graph and imported runtime config. The verifier also matches the current checkout against all 33 pinned Git objects. The static graph links the builder source through the host stub compiler to `stub.an` and package dependencies, while product-target condition resolution remains unknown. It does not verify the active HiHope build, compiler/preprocessor settings, a binary, or runtime behavior.
- The current partial research replay preserves one parent `candidate` and one fix `unknown`; both are `partial` with parse-dependency contamination and production-not-admitted limitations.
- The official ETS Frontend blind applicability frame has 21 samples and remains 0 reviewed; labels, unknown reasons and root causes are unavailable.

## Suggested metadata refresh

For `ohscanner.ark.runtime.type_safety` in `src/ohscanner/detectors/admission.py`:

1. Replace the stale “28 semantic dependency blobs” statement with “40 exact declared source blobs per historical profile; 33/33 C1 source/declaration/build-graph objects verified separately.” Link the corresponding research manifests and keep their source-only limitation explicit.
2. Add the 0.3.8 partial replay result as research evidence: parent `candidate`, fix `unknown`, both `partial`; include same-name unbound-path, fixture-provenance and partial-content-mismatch controls as adapter binding controls. Do not present any as public Runner output.
3. Retain `admission_status=blocked` and `execution_enabled=false`.
4. Retain outstanding requirements for complete target AST/build profile, product binary/runtime species behavior, independent blind labels, reachable product entry, attacker control and concrete security impact.

The C-line change scope permits research delivery files but does not grant ownership of shared admission metadata. Apply these suggestions only through the shared-owner integration path.
