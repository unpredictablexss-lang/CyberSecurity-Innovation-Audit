# D19 unreviewed-source candidate fallback

Updated: 2026-10-19 (Asia/Shanghai)

## Purpose and boundary

D19 explores whether an unknown repository or commit can still produce useful high-recall review candidates instead of returning no findings solely because it lacks an exact source profile. It does not mark an unknown scan clean. Unknown-source runs stay `blocked`, and all parsed files stay `partial`; findings remain candidates with unresolved source, callee, sink behavior, reader reachability, and impact obligations. This work is on `feat/d-commercial-expansion-20261018`, based on main merge `4593a7c9b6977eb81172d01b46cc59daf46f5d45`. Detector version is 0.14.0. The main branch remains on the previously merged 0.13.0 implementation until a separately reviewed change is accepted.

The fallback recognizes strong credential-like identifier, field, and return-call names, then retains tentative value flow through the detector's existing modeled logging sinks and unresolved calls. Names alone do not establish that a value is secret. The fallback may flag certificate/proxy configuration passed to ordinary setters or parsers; those are review candidates, not demonstrated disclosures. It does not add a second scanner, alter the shared frontend, or write product vulnerability status.

## Fixed-source experiment

The offline same-scope replay used local Git objects for `openharmony/communication_netstack` at commit `77ba82dbc3c2adaf3722674fd9dfdfc709ca69c6`, tree `cbc222bc41121fd1b764c03c6ec6da00ebff427e`. It selected 515 tracked C/C++ files (3,766,195 source bytes in the indexed manifest); the detector reported 472 scope files / 88,696 LOC after its own applicability filters. The source snapshot SHA-256 is `fe2a8cf4a366be35be28c89759b20fb706334c4970def882f48db877e4dd4079`.

The initial broad substring classifier produced 76 candidates. Source inspection showed clear name-only noise from `HTTP_API_KEY_FETCH` (an exported API-name constant) and `WSI_TOKEN_HTTP` (a protocol constant). The classifier was tightened to word/phrase shapes, while preserving password, passwd, secret, credential, named key families, and explicit bearer/auth/access/refresh/session/security token names. On the same pinned scope, this reduced the set to 59 candidates. Both runs on the corrected detector produced the same finding identities and coverage. Two-run wall time was 10.8969 seconds and peak RSS was 83,096 KiB. The exact first/replay JSON and hashes are in `D19_NETSTACK_REPLAY/summary.json`.

The 59 remaining results are all `data.sensitive.unresolved-escape` candidates. Manual spot checks include credential/configuration values passed into TLS, proxy, and request parsing APIs. Their call semantics and eventual destinations are unresolved; no checked example establishes a log disclosure. `validated_vulnerability` is 0. The detector status is `blocked`, task status is `completed_with_limitations`, and source coverage is partial. The candidate count is not a measured false-positive rate.

This experiment is a repeatability check on one fixed source snapshot, not an independent labeled holdout. It does not estimate TP/FP/FN, recall, precision, supported-version coverage, or vulnerability prevalence. A zero-result unknown-source scan would still be blocked/partial and would not imply safety. No product build, runtime reader, unauthorized access, impact, affected-version range, or remediation validation was tested.

## Regression and delivery status

The D data detector suite passes 65 tests after the classifier change, including positive checks for password/session/private/API-key shapes and negative controls for token identifiers, `keyCount`, `HTTP_API_KEY_FETCH`, and `WSI_TOKEN_HTTP`. The final full Python suite passes 900 tests with 5 skipped; Web tests pass 17/17, TypeScript `--noEmit`, production build, `compileall`, and `git diff --check` pass. The D19 API -> Worker -> report test retains a synthetic unknown-source log candidate as candidate-only and verifies blocked status and `validated_vulnerability=0`. The D19 branch is not yet pushed or merged.

Acceptance status against D4/D5 gates:

| Gate | Status | Evidence |
|---|---|---|
| M0: isolated default-off research module | Met for merged D 0.13.0 | PR #17 merged to main; exact PR-head CI and local regression passed; catalog remains opt-in. D19 fallback itself is still unreviewed and unpublished. |
| M1: explicit panel candidate path | Met for merged D 0.13.0 narrow scope | Panel task `568dc8b265df41108f03ce2aed14dfce` carried one partial candidate through API/Worker/report, with blocked coverage and zero confirmed. D19 unknown-source behavior has not yet been panel-tested. |
| M2: default one-click commercial scan | Not met | No independent frozen labeled holdout, no per-family TP/FP/FN/unknown evaluation, no broad version matrix, and no complete product coverage evidence. D19's 59 candidates are not an accuracy measurement. |
| M3: confirmed product vulnerability | Not met | No validated product entry, unauthorized reader, concrete impact, affected release, controlled product PoC, or fixed-build revalidation. `validated_vulnerability=0`. |

The source mirror reported tracked modifications when inspected. This task read pinned Git objects and wrote experiment outputs only into this D worktree; it did not reset, clean, or edit the mirror. Because there was no before-state snapshot, those modifications are not attributed to this task.
