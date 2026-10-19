# T4 Independent Review — IBS5YG product profile

**Disposition: BLOCKED.** This review verifies source-object identity, but finds no evidence tying an IBS5YG source revision to a successful OpenHarmony 5.0.2 Ark Runtime build, preprocessed TU, or shipped device binary.

## Claim results

| Claim | Result | Evidence / limit |
|---|---|---|
| IBS5YG parent/fix commit, tree, path blob, byte length and SHA-256 | PASS | Recomputed against the local bare Git object database; values match the profile manifest. |
| IBS5YG fix descends from declared parent | PASS | Fix commit's parent is `2ea501258...`; `merge-base --is-ancestor` exits 0. |
| A specific IBS5YG product component revision | UNKNOWN | The exact IBS5YG product/release pin is absent. The candidate pin `1b235315...` belongs to the Sort/CVE-2025-23420 experiment and is excluded as a substitute; neither IBS5YG pair member is its ancestor. |
| Available `args.gn` and target evidence bind IBS5YG | FAIL | The only found args file is `rk3568`/`hihope`; validation target is `ark_js_host_linux_tools_packages` (host tools), for Sort; generation/build failed. |
| Successful IBS5YG build, compile DB, complete include closure and preprocessed TU | UNKNOWN / MISSING | IBS5YG manifest fields are null/empty; preprocessing is NOT_RUN. |
| IBS5YG source maps to shipped device image/binary | UNKNOWN / MISSING | No matching image/binary hash or source-to-binary mapping is present. |
| Local Git object store custody is independently authenticated | UNKNOWN | Its Gitee remote is self-configured; independent acquisition/custody verification is absent. |

D4's final evidence matrix was independently checked by exact SHA-256 `9c418aed98045a0bf9b16170552c2df7cdb11a8261da59700b7093899d669815`; its README SHA-256 is `035ce9d25172f1afe47e35f70e213226d6b0dea56ff263619046c208731b0460`. I recomputed all 14 evidence artifact hashes listed in the matrix: **14 matched, 0 mismatched**. One initial hash typo for `build-fixed-first.log` was returned to D4 and corrected before final review. Exact claim values and Git commands are in [T4_INDEPENDENT_REVIEW.json](T4_INDEPENDENT_REVIEW.json).

The only identified args/log evidence is from another case and must not be reused to fill IBS5YG profile fields. Independent checks of the 5.0.2 output found no `build.ninja`, no `compile_commands.json`, and zero files with the listed object, library, TU, image, or binary extensions under `out/rk3568`.

## Review boundary

The local bare store at `D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git` reports origin `https://gitee.com/openharmony/arkcompiler_ets_runtime.git`. Object-level checks are reproducible against it, but origin configuration alone does not establish custody or authenticity. This review does not establish vulnerability, exploitability, severity, or safety, and does not close PC-1.
