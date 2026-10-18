# D5 main readiness

| Gate | Status | Current evidence / remaining condition |
|---|---|---|
| M0: default-off isolated module | **Not met** | D data suite 55/55; full Python suite 889 (884 passed, 5 skipped); D13 verified both historical Git commits, trees, and all 44 D4 source-manifest rows offline. D5 exact 10-file replay reproduces 1 old / 0 post-hardening candidates, but both runs are blocked with 4 complete / 6 partial. D14 retains private/default-private sensitive flows as conditional candidates. Public Runner was not used for historical replay; latest PR-head CI and dependency/license review remain unverified. The D branch stays unregistered. |
| M1: explicit experimental registration | **Not met** | Shared partial-AST admission, report/UI integration, and an explicit experiment switch remain owner work. Public Runner still withholds partial D files. |
| M2: default one-click scan | **Not met** | The model remains limited to reviewed DSoftBus sources and exact historical profiles. There is no second independent real source/API family, no independent labeled holdout, no TP/FP/FN/unknown evaluation, and no end-to-end runtime/RSS benchmark. |
| M3: confirmed product vulnerability | **Not met** | Component stubs and historical source replay do not prove a product build, actual product log output, unauthorized reader, validated remediation build, affected release, or product impact. validated_vulnerability=0. |

Recommendation: continue D as research-only. D14 moves the static layer toward high recall by preserving privacy-masked flows for review; it does not relax public Runner partial admission. Next detector work must broaden independently reviewed source families and then evaluate against a frozen real-source holdout. No Catalog registration, default enablement, PR Ready, or merge is approved by these results.
