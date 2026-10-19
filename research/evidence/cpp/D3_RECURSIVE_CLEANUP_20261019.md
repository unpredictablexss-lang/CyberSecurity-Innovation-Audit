# D3 recursive cleanup callback candidate

Date: 2026-10-19 (Asia/Shanghai)
Scanner base: `8ec5f56a12e90bba56953b39eb17faa20e154da9`
Detector: `ohscanner.cpp.resource_lifetime` `0.3.0`
Rule: `ohcpp-resource-lifetime-recursive-cleanup-candidate-003`

## Finding and limits

The change adds a same-translation-unit, bounded may-call candidate for resource teardown cycles through registered member callbacks. It requires a callback registration, a matching callback invocation, a callback path back to a resource releaser, and a child-iteration cleanup path. It suppresses a candidate when the releaser visibly detaches that callback or has a simple explicit depth guard. It does not prove callback binding, reachability, attacker-controlled nesting, or availability impact. It does not alter parser, Catalog, contracts, or public APIs.

## Pinned curl replay

The T1 before replay at scanner base `8ec5f56a12e90bba56953b39eb17faa20e154da9` produced 0 findings on the vulnerable curl source with complete parsing (`resource_lifetime` `0.1.0`, 0.027536 s). D3 replayed the exact local Git objects with the updated detector, `light-ast`, explicit scope `lib/mime.c`:

| Input | Commit | Tree | Blob `lib/mime.c` | File SHA-256 | Parse | Finding | Time |
|---|---|---|---|---|---|---|---:|
| Vulnerable curl | `01346829096c61b372692f6dc43ffa778c6caccd` | `6ae23d9333713707a02588b44ed238a50e8b3bde` | `600437576581be08f9026881c39178857a1c5939` | `1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d` | complete | 1 CWE-674 candidate at `lib/mime.c:1118` (`curl_mime_free`) | 0.042193 s |
| Fixed curl (previous 0.2.0 replay; current source object unavailable in this worktree) | `d7546809d5bd548b69ec49fca26565c8f6f0d344` | `52a8416729366487cdd3b6012071f5f8370e769f` | `3522679a16e2fa560c581413bf946d38e332bea4` | `ea7f9adccf81b578d97e8b6e115535e043b7f8c589177a2597963a4f12462b81` | complete | 0 same-root candidates | 0.042737 s |

The source diff changes recursive MIME deletion to iterative deletion; the candidate is source-root evidence only. The report does not establish an OpenHarmony product build, product call path, or product impact. Exact raw CLI reports are `d3_curl_recursive_cleanup_vuln.json` and `d3_curl_recursive_cleanup_fixed.json` in this directory.

## Other D3 cases

- libpng CVE-2026-46675 remains `PARTIAL`: the T1 vulnerable/fix-parent/fixed/OH snapshots all parse the selected target file as partial. The independent component PoC binds libpng 1.6.55 archive SHA-256 `71a2c5b1218f60c4c6d2f1954c7eb20132156cae90bdb90b566c24db002782a6` and upstream fix `aa77ef38c17ab2fc1b41bec09fb973c6a386641d`, but the current parser provides no complete static target for this cross-function sequence.
- libpng CVE-2026-33416 remains `PARTIAL`: T1 replayed vulnerable/fixed sources, but all four selected source units were partial and no resource-lifetime candidate was produced.
- cJSON CVE-2026-67215 remains `PARTIAL/BLOCK`: D3 reran the exact OH source commit `105eaddbf0d0110b07d16bdefc81ffc796e1444a` / tree `3c07134d5a05aa546b15739e32503a2ca192d258` with the updated rule; `cJSON_Utils.c` parsed complete, `cJSON.c` parsed partial, the run was blocked with 0 findings, and no trusted fixed source is bound. Its root cause is JSON Patch tree amplification followed by direct recursive deletion, not the callback-cycle rule introduced here.
- cJSON CVE-2026-67216 remains `PARTIAL/BLOCK` on the same exact source commit/tree: `cJSON.c` parsed partial and the run was blocked with 0 findings. No trusted fixed source is bound; exponential comparison cost is a separate root cause outside this resource-lifetime rule.

The updated cJSON CLI report is `d3_cjson_67215_67216_vuln.json` / `.md`. It now retains two separate bounded candidates: `ohcpp-resource-exhaustion-tree-amplification-candidate-004` at `cJSON_Utils.c:861`, and `ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005` at `cJSON.c:3161`. The latter TU remains partial; the run is blocked and both findings retain partial identity. There is no trusted fixed source, so neither case has a fixed-source pass. Synthetic positive cases and safe/unrelated controls exercise each rule identity; they do not establish product exploitability. The report has 2 candidates, 1 complete and 1 partial source parse, no runtime validation, and no safe conclusion.

## D3 follow-up: cJSON resource exhaustion

Version `0.3.0` adds independent bounded shapes for recursive tree amplification after repeated patch mutations and recursive comparison cost from two directional sibling scans with per-element lookup. It does not key off project, CVE, or function names. Partial translation units are listed as inspected for emitted partial candidates, while the run remains `blocked`. Local tests include one positive and a safe compare control, plus a multi-file tree amplification positive and an unrelated recursive cleanup control. There is no trusted fixed source for either cJSON CVE.

The current cJSON object identity is commit `105eaddbf0d0110b07d16bdefc81ffc796e1444a`, tree `3c07134d5a05aa546b15739e32503a2ca192d258`; `cJSON.c` blob `152b2caa479c9f448001652913c980a6dafb82e0`, `cJSON_Utils.c` blob `8fa24f8e9bf452cf1ba49d1325c85423ce742c74`.

## Regression and delivery checks

- Synthetic hash-bound fixtures cover callback-cycle positive, callback-detached fixed control, unrelated direct recursive cleanup, existing allocation/UAF/double-free controls, and partial input.
- `python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v`: 8 tests passed.
- `python -m unittest discover -s tests/detectors -p 'test_cpp_*.py'`: 145 tests passed.
- `python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp`: no violations.
- `git diff --check`: passed.
