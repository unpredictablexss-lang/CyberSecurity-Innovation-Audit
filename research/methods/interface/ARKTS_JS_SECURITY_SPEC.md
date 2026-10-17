# B-ARK-01 JS/TS/ArkTS security specification

Status: bounded lexical research rules, not mature ArkTS/JS semantic analysis.

## Frontend

`src/ohscanner/language.py` reports `complete`, `partial` or `failed` syntax/outline coverage for `.js`, `.ts` and `.ets`. It masks comments/literals, checks delimiter balance and records function/class/call outlines. It does not resolve types, modules, manifests, access control or runtime dispatch.

## Rules

| Rule | Candidate shape | CWE | Required proof still missing |
|---|---|---|---|
| `ohscanner.js.dangerous-eval-candidate-001` | `eval`, `new Function`, string `setTimeout` | CWE-95 | source trust, sandbox, reachability |
| `ohscanner.js.path-taint-candidate-002` | request/want/path-like source to file/URL sink | CWE-22 | cross-module taint, permission, normalize/guard dominance |
| `ohscanner.oh.arkts.component-exposure-candidate-003` | exported Ability/Extension entry | CWE-749 | manifest/profile exposure and access policy |
| `ohscanner.oh.arkts.webview-bridge-candidate-004` | JS bridge plus remote URL/loadUrl | CWE-749 | origin trust and bridge permission |
| `ohscanner.oh.native-bridge-candidate-005` | N-API binding plus memory/Parcel-like operation | CWE-20 | binding map, parameter length and runtime reachability |

All findings are `candidate/unassessed`. A fixed/safe/unrelated/unknown control matrix is in `tests/detectors/test_script_security_detector.py`. The pinned scan is `research/evidence/cpp/script_security_scan_20261017/`; zero candidates there is not a safe verdict.
