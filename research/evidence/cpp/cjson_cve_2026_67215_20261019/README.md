# cJSON CVE-2026-67215 evidence note

Verification date: 2026-10-19. Lane: A_CPP.

## Root-cause card

- Public disclosure: Red Hat describes an application that applies attacker-controlled RFC 6902 JSON Patch through `cJSONUtils_ApplyPatches()` (or case-sensitive variant). Add/copy can graft duplicated subtrees, growing nesting beyond the parser limit; recursive `cJSON_Delete()` then risks stack exhaustion. Red Hat says applications that do not process untrusted JSON Patch are not affected and reports no upstream fix as of cJSON 1.7.19. This verifies the disclosure statement, not the OpenHarmony product.
- Attacker-controlled data / unknowns: the patch document and its operations are attacker-controlled only if a caller exposes this API to untrusted input. Product callers, trust boundary, invocation and stack limits are unknown.
- Flow: patch operations select/copy a source value, duplicate it recursively, and attach it under a destination; later recursive deletion traverses the resulting tree. Advisory/source structure support this flow, but no component runtime reproduction was done.
- Vulnerable invariant / remediation: an operation-level duplication/depth or total resulting-tree bound would be needed to ensure recursive cleanup cannot exceed a safe stack bound. No upstream fix was found, so no patch invariant can be asserted.
- Static proof obligations: establish data reaches JSON Patch API from an untrusted boundary; add/copy grows tree depth across operations; resulting cleanup invokes recursive delete; and the growth bound exceeds safe stack depth. This engine does not prove cross-operation tree shape, caller trust, or runtime stack impact.
- Similar safe code: merely calling `cJSON_Delete`, using JSON Patch internally on trusted bounded patches, or calling recursive parse/duplicate under fixed depth controls is insufficient evidence of a vulnerability.

## Source/build identity

The local OpenHarmony source declares cJSON 1.7.19. Local source Git object metadata recorded in the component inventory: commit `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`, tree `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856`.

- `cJSON.c`: blob `152b2caa479c9f448001652913c980a6dafb82e0`; SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`.
- `cJSON_Utils.c`: blob `8fa24f8e9bf452cf1ba49d1325c85423ce742c74`; SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`.
- `BUILD.gn`: `cJSON_Utils.c` is included only under `ohos_lite`; the standard branch builds `cJSON.c` alone. Actual product profile is unknown.
- At the first baseline the submodule Git config was unreadable. A later direct read of `.git/HEAD` confirmed commit `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`; tree/blob identities remain those in the component inventory, while file hashes were independently verified.

A synthetic snapshot was made solely for pinned production scanning (not an upstream commit): commit `461676384f5d25c47042ddfccd7a89134d5f45d2`, tree `3c07134d5a05aa546b15739e32503a2ca192d258`, snapshot SHA-256 `c0482c314ead7b9131426e7aa74f1073f734341c2ac56fb9a2578efecb51b3e7`. It contains only the two byte-identical C files. The initial empty snapshot attempt failed due to a relative-path error and is not evidence; it was preserved under workspace `tmp`.

## Production baseline

Command, from scanner root:

```powershell
python -m src.cli ohscan-run --repo-dir tmp\cjson-oh-baseline-20261019-retry --repository OpenHarmony/OpenHarmony-4f3ca19c0cae --commit 461676384f5d25c47042ddfccd7a89134d5f45d2 --include third_party/cjson/cJSON.c --include third_party/cjson/cJSON_Utils.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/cjson_cve_2026_67215_20261019/baseline.json --md-out research/evidence/cpp/cjson_cve_2026_67215_20261019/baseline.md
```

OHScanner v0.1.9 reported 0 diagnostics, detector status `blocked`, and partial coverage. `cJSON_Utils.c` parsed/analyzed completely; `cJSON.c` was partial with parser errors at lines 158-173 and missing nodes at 3152/3169; detector analysis reason was `detector_model_incomplete`. Direct `parse_source` replay reproduces the eight C-parser issues. The errors are on `CJSON_CDECL`-decorated function-pointer typedef/callback declarations (lines 158-173); the configured parser consumes raw source and does not preprocess that macro from `cJSON.h`. Forcing the same translation unit through the C++ grammar is worse (84 issues), so changing the language label is not a valid workaround. Therefore this is not a valid reproduced detector miss, static positive, or safety result. At the time of the initial baseline this note had no runtime reproduction; the later isolated runtime section below supersedes that specific status. No fixed sample or static rule was available.

## Evidence and next action

Red Hat CVE record: https://access.redhat.com/security/cve/cve-2026-67215. It states there is no upstream fix as of 1.7.19. GitHub PR #1092 is a distinct MergePatch UAF change, not a recursion fix for this case: https://github.com/DaveGamble/cJSON/pull/1092. Do not use it as a fixed control.

Historical next action (superseded by the later runtime update): assess a generic owned parser integration for compile-time macro context, then continue with another pinned A-line pair. Current production-parser prerequisite remains pending shared-owner review.

## Isolated component reproduction (2026-10-19)

Red Hat's record identifies the sequence: a JSON Patch using `add`/`copy` duplicates subtrees and increases document depth beyond the parser's `CJSON_NESTING_LIMIT`, after which recursive `cJSON_Delete()` can exhaust the application thread stack. It requires an application to apply untrusted JSON Patch through cJSON-Utils. The upstream cJSON issue #1073 is an open remediation request with no associated branch/PR or confirmed fix version; it is not a fixed sample. The record also says there is no upstream fix as of 1.7.19.

I built the byte-hash-matched local OpenHarmony `cJSON.c` and `cJSON_Utils.c` with WSL GCC 16.2.0 (`-O0 -g -Wall -Wextra -pthread`). The harness constructs a valid JSON document with two independently parsed branches of depth 700 (each below `CJSON_NESTING_LIMIT=1000`) and parses a shallow, attacker-shaped JSON Patch `copy` operation from `/source` to a leaf beneath `/dest`. It measures generated depth with an iterative test helper, then invokes `cJSON_Delete(root)` on a fresh pthread with an explicit stack size. It makes no network calls.

| Input and deletion-thread stack | Parsed | After patch | Deletion result |
|---|---:|---:|---|
| Two branches depth 400, 64 KiB | yes | maximum tree depth 802 | cleanup completed |
| Two branches depth 700, 256 KiB | yes | maximum tree depth 1402 | cleanup completed |
| Two branches depth 700, 128 KiB | yes | maximum tree depth 1402 | cleanup completed |
| Two branches depth 700, 64 KiB (five repeats) | yes | maximum tree depth 1402 | SIGSEGV in delete thread, 5/5, exit 139 |
| Two branches depth 700, 32 KiB | yes | maximum tree depth 1402 | SIGSEGV in delete thread, process exit 139 |

The positive input starts from branches the parser accepts independently; a single valid `copy` grows the resulting tree beyond the parser's 1000-level bound. The low-stack crash is localized after the “deleting root” marker. This is a component reproduction under an explicitly constrained thread stack, not evidence that an OpenHarmony product exposes this API or that its thread has the same stack limit. At 128 and 256 KiB the delete completes; 64 and 32 KiB fail for the 1402-depth tree. A separate 802-depth tree passes at 64 KiB. These are local thread-stack conditions, not an application default.

An earlier exploratory harness repeatedly copied the entire root. At 12 copies it crashed during `cJSONUtils_ApplyPatches`/deep duplication, before reaching the delete marker. That result is retained as an exploratory failure, not used as the CVE reproduction. A `setrlimit` experiment on the already-running main thread did not provide a valid constrained-stack control; those PASS results are retained but excluded. Use the fresh-pthread runs above as the valid deletion-path results.

Source hashes match the local component inventory: `cJSON.c` `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`; `cJSON_Utils.c` `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`; local `cJSON.h` SHA-256 `25b0145150d500498e4d209cec69c18c42cf818bffcc54690be3b895a2a16dee`. Harness sources, run logs, compiler/toolchain conditions, and executable hashes are saved alongside this note.

**Status:** runtime source-root-cause evidence improved. No detector rule was added: production M2 still has `cJSON.c` partial due `CJSON_CDECL` preprocessing context, and `cJSON_Utils.c` complete alone cannot prove the linked recursive delete semantics. There is no upstream fixed version/control, no fixed regression, no independent mechanism holdout, and no product caller evidence. Do not call the current zero-diagnostic scan a miss or safe result.


## rk3568 product source-route check (2026-10-19)

The resolved local product config identifies rk3568 as `os_level=standard`; the product config inherits `rich.json`, which includes the cJSON component. In `third_party/cJSON/BUILD.gn`, the `ohos_lite` branch includes both `cJSON.c` and `cJSON_Utils.c`, while the other branch builds only `cJSON.c`. The shared build config defines `is_lite_system = is_mini_system || is_small_system` and imports the file that defines `ohos_lite=true` only for `is_lite_system`. Thus the available source configuration points to the standard branch, which omits JSON Patch functions from this cJSON target.

This is source-route evidence, not final-link proof: rk3568 `args.gn`, generated `global_parts_info`, `build.ninja`, compile commands and link manifest are absent. HB stopped before GN generation because `prebuilts/build-tools/linux-x86/bin/ninja` is missing. Therefore product confirmation remains **unknown**; do not claim the product is affected or not affected. Hashes of each inspected product/build file and the exact missing artifacts are in `rk3568-product-source-route.json`.

### Reproduction commands

Run from WSL with core dumps disabled. The source paths are the exact hash-bound files listed in `runtime-hashes.txt`; output binary is in workspace `tmp` and does not modify the component source.

```bash
gcc -O0 -g -Wall -Wextra -pthread \
  -I/mnt/d/openHarmonyScanner/openharmony/third_party/cJSON \
  /mnt/d/openHarmonyScanner/openharmony/third_party/cJSON/cJSON.c \
  /mnt/d/openHarmonyScanner/openharmony/third_party/cJSON/cJSON_Utils.c \
  /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit/research/evidence/cpp/cjson_cve_2026_67215_20261019/runtime_json_patch_delete.c \
  -o /mnt/d/openHarmonyScanner/tmp/cjson-runtime-cve-2026-67215-20261019/cjson-oh-delete-thread
(ulimit -c 0; /mnt/d/openHarmonyScanner/tmp/cjson-runtime-cve-2026-67215-20261019/cjson-oh-delete-thread 400 64)
(ulimit -c 0; /mnt/d/openHarmonyScanner/tmp/cjson-runtime-cve-2026-67215-20261019/cjson-oh-delete-thread 700 128)
(ulimit -c 0; /mnt/d/openHarmonyScanner/tmp/cjson-runtime-cve-2026-67215-20261019/cjson-oh-delete-thread 700 64)
(ulimit -c 0; /mnt/d/openHarmonyScanner/tmp/cjson-runtime-cve-2026-67215-20261019/cjson-oh-delete-thread 700 32)
```



### cJSON CVE-2026-67215 current upstream status and production replay (2026-10-19)

- Rechecked official status: Red Hat still says no upstream fix as of 1.7.19; GHSA patched versions remain unknown; upstream issue #1073 is open with no linked PR. PR #1064 addresses MergePatch recursion under issue #995; PR #1078 guards recursive comparison paths and is open. Neither fixes JSON Patch `add`/`copy` tree amplification followed by recursive `cJSON_Delete`; neither is a valid fixed control.
- Current production CLI replay used a new synthetic Git snapshot made from byte-hash-matched local OH cJSON source after the prior temporary repo path proved absent. Snapshot tree and byte-snapshot digest match the previously recorded two-file snapshot; synthetic commit is not represented as upstream identity. M2 `ohscanner.cpp.resource_lifetime` v0.1.9: 0 diagnostics, 1 complete / 1 partial, blocked, 0.10035 s. This is not a valid static miss or safety result.
- The component stack-exhaustion reproduction is prior saved evidence and was not rerun this turn. No detector code change, fixed source, or product call-site evidence was added.
- Detailed source IDs, report, exact failure/recovery, upstream links and proof obligations are in `upstream-status-and-current-replay-20261019.md` and this case README.
- Exact next operation: inspect the two existing parser-context prerequisite requests for current review state; add this exact cJSON baseline (file hashes, `CJSON_CDECL` missing context, 1/2 partial production result) to the A-line request if absent. Completion condition: owner can reproduce complete source-mapped parse without hardcoded CVE/path symbols; then replay the same production scope. If the shared prerequisite remains pending, keep cJSON static status blocked and proceed with a complete-parse disclosed root family that has a verified fix pair.
