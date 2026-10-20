# D34 — libpng CVE-2026-46675 generic lifecycle-model assessment

Date: 2026-10-24 (Asia/Shanghai)
Evaluation baseline: `1cb2178c88715b6c8f908ac7826cb684a35730f7`
Detector: `ohscanner.cpp.resource_lifetime` `0.4.2`
Disposition: **No rule change; case remains PARTIAL/BLOCK.**

## Result

The exact pinned vulnerable and fixed commits were scanned through the current production CLI. Both one-file scopes (`pngrutil.c`) report one partial parse, detector status `blocked`, partial coverage, and zero findings. The exact seven-function fragment replay reports six complete fragments and one partial `png_handle_iCCP` fragment for each version; all fragments emit zero findings. These results do not establish a vulnerable/fixed differential or a safe/fixed pass.

| Variant | Commit / tree | `pngrutil.c` blob / SHA-256 | CLI parse / detector / finding | Fragment parse / findings |
|---|---|---|---|---|
| Vulnerable | `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` / `e01f5780f93eaa6d74cca003bb39b427c8f1e910` | `a4eda54c8cb3d36cf1651dba159067b65030e3aa` / `b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e` | partial / blocked / 0 | 6 complete, 1 partial / 0 |
| Fixed | `aa77ef38c17ab2fc1b41bec09fb973c6a386641d` / `4c64b5f18cef7d129adee3b403fc4be93f82e30d` | `482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a` / `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e` | partial / blocked / 0 | 6 complete, 1 partial / 0 |

## Source model and parser boundary

Pinned source review confirms a plausible common-object lifecycle sequence. `pngstruct.h` declares `zowner` and `z_stream zstream` on `png_struct`. The relevant functions receive `png_structrp png_ptr` and read/write `png_ptr->zstream.next_in` / `avail_in`. Vulnerable `png_decompress_chunk` releases `zowner` without detaching those input fields after processing a chunk buffer; the downstream IDAT reader refills only when `avail_in == 0`, otherwise it continues with the retained stream state. `png_read_info` dispatches chunk handlers, and `png_read_end` calls `png_read_finish_IDAT`, which drains via `png_read_IDAT_data`. The fixed source adds `png_inflate_detach_buffers` at ownership/release transitions.

This is corroborating source structure, not a parser-proven interprocedural finding. On the current parser, `pngrutil.c`, `pngread.c`, `pngstruct.h`, and `pngpriv.h` all parse partial. The production CLI scope contains only `pngrutil.c`; caller code and struct/type declarations are outside that scan. `AstIndex.CallSite` exposes callee text, argument text, and location, but no enclosing-function identity, resolved callee/type identity, object-field SSA/alias state, or cross-function call ordering. Six isolated fragments parse completely but omit the declaration context; the iCCP fragment remains partial. A rule based only on repeated `png_ptr` spelling, known function names, CVE identity, repository name, or source hash would not establish same-object field reuse and is rejected.

Therefore the current model does not expose enough parser facts to prove the release-to-IDAT reuse relation without an unsupported naming heuristic. No `resource_lifetime` rule change is justified from these results.

## Next generic capability

The reusable follow-on is a bounded, reviewed interprocedural resource-state model: resolve parameter types and stable object identity; associate call sites with enclosing functions; propagate field writes/clears and ownership transitions along bounded direct-call paths; and retain parse/context unknowns. Validate it on multiple independent lifecycle examples and positive/fixed/safe/unrelated/renamed/partial controls before enabling findings. Keep the exact 46675 pair as a holdout after rule design.

Product build/configuration, malformed-chunk trigger feasibility, application reachability, runtime behavior, and impact remain untested. This case remains **PARTIAL/BLOCK**; the fixed zero result is not a safety conclusion.

## Reproduction

With the pinned upstream objects in a local bare mirror:

```powershell
python research/evidence/cpp/d34_libpng46675_model_assessment_20261024.py `
  --source-git-dir D:/openHarmonyScanner/tmp/t34-libpng46675-source-20261023.git
python research/evidence/cpp/verify_d34_libpng46675_model_assessment.py `
  --source-git-dir D:/openHarmonyScanner/tmp/t34-libpng46675-source-20261023.git
```

Machine results are in [the D34 evidence JSON](d34_libpng46675_model_assessment_20261024.json); exact fragment records are embedded in that JSON. The replay script adds no upstream source files to the repository.
