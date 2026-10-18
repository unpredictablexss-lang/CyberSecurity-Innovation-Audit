# D5 readiness re-evaluation (2026-10-19)

This refresh separates the D sensitive-data-flow detector from the newer disclosed-CVE detector. The original M0-M3 gates remain in force; mainline registration and a green CI run are not evidence of commercial readiness or a confirmed product vulnerability.

| Gate | Status | Current evidence and remaining conditions |
|---|---|---|
| M0: default-off isolated module | **Partially met** | Both `ohscanner.data.sensitive_exposure` and `ohscanner.known_disclosed_cves` are Catalog research candidates with `default_enabled=false`; current `main` contains the D scanner and explicit page options. This turn's full Python suite on `5eeb7f44634fecd74f243d8822a4b0a4417473b8` passed 925 tests (920 passed, 5 skipped), and front-end tests passed 18/18 with TypeScript checking. Remaining: independent code/security and dependency/license review plus owner signoff; sensitive-flow analysis still has blocked/partial source coverage.
| M1: explicit experimental registration and report path | **Met for the disclosed-CVE opt-in path; partial for sensitive-data-flow** | The repository audit page has separate opt-in checkboxes; the detector IDs flow into scan planning. D22 previously exercised the libpng archive through API/Worker/report/source view. D32 completed two full replay rounds through API/Worker/report/hash-checked source viewer on five fixed component snapshots (20 scan jobs total); both rounds retained the same nine diagnostics across eight CVE identifiers and all returned source hashes matched. D32 preserves blocked/partial statuses. The sensitive-flow detector still has profile and AST-coverage limits. |
| M2: default one-click scan with measured accuracy and performance | **Not met** | The disclosed-CVE detector has 12 narrow source signatures for 12 of the 17 independent CVE entries in the review record; five entries have no reliable positive rule mapping. These are development and historical samples, not an independent labeled holdout. TP/FP/FN/TN/unknown and an end-to-end runtime/RSS benchmark remain unavailable. No recall or precision claim is made.
| M3: confirmed product vulnerability | **Not met** | D25 cJSON, D30 libpng, and D31 libtiff have component-level reproductions and fix comparisons. Their scanner outputs remain candidates. Product build provenance, real caller/permission path, attacker control, product impact, affected-release mapping, and product-fixed-build retest are not established. `validated_vulnerability=0`. |

## Current operating boundary

The scanner can be selected from the repository audit page and preserves candidate findings when parser coverage is partial, while marking the run blocked or completed-with-limitations. The CVE detector is narrow and opt-in; it is not a whole-project CVE inventory and does not turn public advisories or component Harness results into product findings.

D32's libpng archive replay also emits two distinct CVE-2026-33636 function findings even though the mirror build metadata lists a patch. Since D32 scans the archived upstream source, patch application and product inclusion remain unknown; this is a candidate requiring build-manifest review, not a false-negative/false-positive verdict.

The original D4/D5 holdout requirement remains open: freeze detector/model hashes before collecting a separately labeled real-source set, record unknown labels honestly, then measure TP/FP/FN/unknown and runtime/RSS. Until M2 and M3 evidence exists, D is suitable for opt-in research triage only, not a commercial-readiness claim.
