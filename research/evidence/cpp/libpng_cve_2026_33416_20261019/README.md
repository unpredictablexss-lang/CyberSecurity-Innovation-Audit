# libpng CVE-2026-33416 source and backport audit

Verification date: 2026-10-19. The official [libpng advisory](https://github.com/pnggroup/libpng/security/advisories/GHSA-m4pc-p4q3-4c7j) identifies CVE-2026-33416, affects libpng >=1.2.1 through 1.6.55, and lists 1.6.56 / 1.8.0 as patched. It describes two independent cross-struct aliases: `png_set_tRNS` aliases `trans_alpha`, and `png_set_PLTE` aliases `palette`. The advisory gives attacker control of the tRNS chunk and requires an application path that frees/replaces data before continuing decode; product entry/reachability is not established here.

## Root-cause card

1. **Attacker control / conditions.** The PNG can control tRNS chunk values. The vulnerable application must call `png_free_data(...PNG_FREE_TRNS/PLTE...)` or call the setter again after reading info, then continue decoding; actual OpenHarmony caller behavior is unknown.
2. **Object flow.** `png_set_tRNS` assigns `png_ptr->trans_alpha = info_ptr->trans_alpha`; `png_set_PLTE` assigns `info_ptr->palette = png_ptr->palette`. Independent struct lifetimes and independent freeing permit one field to dangle while row transforms still dereference it; some transform paths write.
3. **Missing guarantee.** Each struct needs ownership of independent storage, or a shared lifetime contract; the old setters made aliases between separately managed owners.
4. **Upstream invariant.** Full fixes allocate independent buffers and copy source values. `png_set_quantize` also must copy caller storage before unconditional cleanup, and palette copies require zero fill for NEON access. Official commits: tRNS fix `23019269764e35ed8458e517f1897bd3c54820eb`; palette fix `7ea9eea884a2328cc7fdcb3c0c00246a50d90667`; palette API compatibility follow-up `c1b0318b393c90679e6fa5bc1d329fd5d5012ec1`. [Advisory details and patch references](https://github.com/pnggroup/libpng/security/advisories/GHSA-m4pc-p4q3-4c7j).
5. **Static proof / obligations.** A useful UAF rule must relate two owner fields to aliased allocation provenance, release of one owner, stale alias, subsequent dereference/write, and a feasible path. This round did not implement such a rule. Product caller path, attacker-controlled decode, exact build output, and impact remain unknown.
6. **Safe lookalikes.** Two fields containing equal copied data are safe if allocations are independent. A caller-owned palette requires copying or explicit borrowed lifetime; merely seeing `free` or two pointer fields is insufficient.

## Fixed source identity and local source identity

OpenHarmony component pin: `e57b1079564a02a50321ec528aa6e41884979d32`, tree `02b17492f4490ff2e4d17ba74e2080358a500059`. This pin stores the libpng 1.6.55 archive blob `975cee2aca0eda6bfa3e9b7a1336c956fcf1b094`, SHA-256 `71a2c5b1218f60c4c6d2f1954c7eb20132156cae90bdb90b566c24db002782a6`. The exact local extracted file identities follow. Official fix commits are tRNS `23019269764e35ed8458e517f1897bd3c54820eb`, parent `0c37b8fbffe779314f3c842e16983ceec5930af1`; palette `7ea9eea884a2328cc7fdcb3c0c00246a50d90667`, parent `a3a21443ed12bfa1ef46fa0d4fb2b74a0fa34a25`; palette compatibility follow-up `c1b0318b393c90679e6fa5bc1d329fd5d5012ec1`. The fixes are separate commits because the disclosure combines two related but distinct ownership paths. Extracted source files before patching:

| File | SHA-256 |
|---|---|
| `pngread.c` | `feee8bdd4c553cc4f01bb288a868d4b83e1ce0f75014a96163a49eb32119cba6` |
| `pngrutil.c` | `b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e` |
| `pngset.c` | `9bd59a79669db37b2ecc481439481eb5f49bf77bee0de4b1aba649915609b3d0` |

## Backport replay (no product source modified)

The attached `patch-dry-run.log` is from `patch -p1 --fuzz=0 --dry-run` against the pristine extracted archive. `actual-application-replay.log` records application using the same patch command/options as `install.py` in a second isolated scratch copy. Source hashes show `pngrutil.c` stayed identical, while `pngread.c` and `pngset.c` changed; rejects exist for the failed hunks. The `pngset.c` palette hunk did apply; correction to the earlier note: **the core palette hunk did not fail**. The failed hunks are `pngrutil.c` (removal of a tRNS TODO) and `pngset.c` hunk #2 (`png_set_tRNS` independent `trans_alpha` allocation). The patch ends mid-line.

The full official upstream patch text for both fixes was independently inspected through the commit `.patch` pages: [tRNS patch](https://github.com/pnggroup/libpng/commit/23019269764e35ed8458e517f1897bd3c54820eb.patch) and [palette patch](https://github.com/pnggroup/libpng/commit/7ea9eea884a2328cc7fdcb3c0c00246a50d90667.patch). The tRNS patch changes `pngread.c`, `pngrutil.c`, `pngset.c`, and `pngwrite.c`; the palette patch changes `pngread.c`, `pngrtran.c`, `pngrutil.c`, `pngset.c`, and `pngwrite.c`. This confirms patch-to-root-cause relationships, but web inspection did not produce local Git objects or fixed-source blobs for scanner binding.

This one-patch replay is security-relevant but does not represent the final package output: when run alone against the pristine archive, the tRNS allocation hunk failed while the destructor hunk applied. The later full ordered install replay below produces a different source state because earlier patches change matching context and the subsequent CVE-2026-34757 patch also runs. Do not infer the final generated package state from this standalone replay. Both replay directories are isolated under workspace tmp; the OpenHarmony source checkout was not edited.

The dry-run and application replay above document only applying CVE-2026-33416.patch alone to a pristine source copy. That one-patch replay produced rejects and source hashes recorded in the archived output; it is not the full install.py result. The full ordered install replay, generated-source scan and runtime results are recorded below. Product-binary inspection remains unperformed.

## Production baseline scan

To run the pinned local 1.6.55 source through the existing production M2 entry, the archive was copied into an isolated temporary Git repository. Its synthetic commit is `f3ef808f45af32fabed16e1796ee82598c17e9f7`, tree `47d092e8fc7e5c94a03bea1bd50fcfd10defe23d`; file blobs are the archive source files identified above. This synthetic commit is only a transport wrapper for exact local package bytes, not an upstream commit. The CLI command was:

```powershell
python -m src.cli ohscan-run --repo-dir 'D:\openHarmonyScanner\tmp\libpng-cve-2026-33416-production-baseline-20261019' --repository pnggroup/libpng --commit f3ef808f45af32fabed16e1796ee82598c17e9f7 --include pngset.c --include pngread.c --detector ohscanner.cpp.lifetime --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/libpng_cve_2026_33416_20261019/baseline-local-1.6.55.json --md-out research/evidence/cpp/libpng_cve_2026_33416_20261019/baseline-local-1.6.55.md
```

Result: **0 diagnostics; both C files parser-partial; `ohscanner.cpp.lifetime` is not applicable to C; `ohscanner.cpp.resource_lifetime` is blocked on partial parses; report `completed_with_limitations`.** This is not a miss, not safe, and not unaffected.

The complete source chain was then scanned with a broader fixed scope including both setters, the `png_free_data` implementation, destruction, and row transforms:

```powershell
python -m src.cli ohscan-run --repo-dir 'D:\openHarmonyScanner\tmp\libpng-cve-2026-33416-production-baseline-20261019' --repository pnggroup/libpng --commit f3ef808f45af32fabed16e1796ee82598c17e9f7 --include pngset.c --include png.c --include pngread.c --include pngrtran.c --detector ohscanner.cpp.lifetime --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/libpng_cve_2026_33416_20261019/baseline-alias-chain-local-1.6.55.json --md-out research/evidence/cpp/libpng_cve_2026_33416_20261019/baseline-alias-chain-local-1.6.55.md
```

Result: **0 diagnostics; all 4/4 C files parser-partial; lifetime detector not applicable to C; resource-lifetime detector blocked; `completed_with_limitations`.** `pngset.c` contains both cross-struct assignments; `png.c` implements the release helper; `pngrtran.c` dereferences the alias during transforms. This attributes the baseline gap to language inapplicability and parse blocking before semantic analysis. Once parse is complete, the current resource detector would still need cross-struct alias and helper-mediated, cross-function lifetime reasoning to prove this family.

An explicit fetch of official v1.6.55 and v1.6.56 tags was attempted separately and failed at the network connection; see [UPSTREAM_SOURCE_SYNC.md](UPSTREAM_SOURCE_SYNC.md). The scan did not fetch source.

## Detector implementation and source-bound replay

The baseline miss was followed by a bounded generic lexical rule in `src/ohscanner/detectors/cpp/resource_lifetime_detector.py`, version 0.1.8: `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003`. Without CVE metadata, it looks for a cross-object same-member assignment, a member passed to a deallocator-shaped function ending in `free`, `release`, or `destroy`, and a direct dereference through the opposite member. It has fact/pair budgets. This is deliberately a candidate heuristic: it does not prove same-object identity, actual deallocation, execution order, feasible path, attacker control, or impact. Partial parse units remain marked partial/blocked while retaining findings.

Same explicit source scope and production M2 entry results:

| Source | Commit / tree | Baseline | Rule 0.1.8 | Parsing |
|---|---|---:|---:|---|
| libpng v1.6.55 | `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` / `e01f5780f93eaa6d74cca003bb39b427c8f1e910` | 0 (blocked) | 2 candidates | 4/4 partial; blocked |
| libpng v1.6.56 | `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33` / `a28bb962645843af84063c77f574f6d88da79f76` | not run before implementation | 0 same-rule candidates | 4/4 partial; blocked |

The vulnerable-tag candidates are at `pngrtran.c:1187` (tRNS) and `pngrtran.c:1228` (palette). The fixed-tag scan has no same-rule candidate, but partial parse means this is not a safe verdict. Reports: `final-v1.6.55-rule-0.1.8.{json,md}` and `final-v1.6.56-rule-0.1.8.{json,md}`. Superseded failed/overinclusive tuning reports are preserved.

A post-freeze synthetic mechanism variant with renamed fields and a `destroy`-named release wrapper was scanned through the production CLI, with no advisory/CVE input: one candidate, complete parse. Synthetic commit `95e24c4777c7063cc555cae815424de1c1e14a16`; reports `holdout-variant-production.{json,md}`. This is not an independent real-world labeled sample. Focused detector tests cover positive, fixed-copy, safe, unrelated, renamed dot-member, and incomplete controls; the two new targeted tests pass. The full module still has pre-existing fixture-manifest byte-size mismatches, which were not changed.

The upstream and full OpenHarmony install-generated component sources were subsequently built and exercised under ASan as detailed below. Neither run identifies the actual linked product binary.

## Cross-rule regression after resource-lifetime detector v0.1.9

After adding the curl recursive-cleanup candidate rule to the shared registered resource-lifetime detector, the same four-file libpng source scope was replayed through M2. The vulnerable tag still reports only the two existing cross-member UAF candidates (`pngrtran.c:1187`, `pngrtran.c:1228`); the fixed tag reports zero same-rule candidates. Both remain 4/4 parser-partial and detector blocked. This verifies the recursion rule did not add a libpng finding or suppress the existing pair; it does not upgrade the partial-parse evidence. Reports: `cross-regression-v0.1.9-vulnerable.{json,md}` and `cross-regression-v0.1.9-fixed.{json,md}`.


## Component runtime reproduction (2026-10-19)

The runtime gap is closed for both documented alias paths at the component API level. Official SourceForge release archives were downloaded explicitly and hash-bound: v1.6.55 archive SHA-256 `d925722864837ad5ae2a82070d4b2e0603dc72af44bd457c3962298258b8e82d`; v1.6.56 archive SHA-256 `f7d8bf1601b7804f583a254ab343a6549ca6cf27d255c302c47af2d9d36a6f18`. The 1.6.55 runtime source copy was checked against the official archive for relevant source files; the 1.6.56 extracted source hashes match the fixed source identities recorded above. Both were built in isolated WSL2 directories with GCC 16.2.0, AddressSanitizer, static libpng and system zlib; optional tests/tools/shared library were disabled.

`runtime_trns_uaf.c` reads tiny indexed PNGs from memory, calls `png_read_info`, frees either `PNG_FREE_TRNS` or `PNG_FREE_PLTE`, enables expansion, then continues update/read. The minimized inputs are `trigger_trns.png` and `trigger_palette.png`. Results:

| Path | Vulnerable 1.6.55 | Fixed 1.6.56 | No-free control on 1.6.55 |
|---|---|---|---|
| tRNS alias | ASan heap-use-after-free at `png_init_palette_transformations` (`pngrtran.c:1187`), exit 134 | Decode completes, exit 0 | Decode completes, exit 0 |
| PLTE alias | ASan heap-use-after-free at `png_do_expand_palette` (`pngrtran.c:4482`), exit 134 | Decode completes, exit 0 | Decode completes, exit 0 |

Full identities, artifact hashes, build/runtime commands and limits are in `runtime-reproduction-20261019.json`; raw ASan and build logs are beside it. This verifies component API call patterns, not OpenHarmony product linkage, application reachability, attacker permissions, or product exploitability. Repeated-set and `png_set_quantize` variants were not exercised. Same-scope static results remain two/zero candidates with 4/4 partial parse, so retain partial/blocked rather than a safe verdict.


## Full OpenHarmony install pipeline and generated-source rescan (2026-10-19)

The earlier one-patch test was superseded for package-state analysis by replaying the actual copied third_party/libpng/install.py bundle and full patch order against the pinned 1.6.55 tarball. The script returns 0 while logging one failed comment/TODO hunk; its catch-and-continue behavior is visible in source. The pngset.c setter hunk for independent tRNS storage succeeds in this full order (it failed in the earlier isolated single-patch replay), and subsequent patch files run. Generated-source hashes and synthetic snapshot identities are in openharmony-install-source-snapshot.json.

The four generated C files were built with the same isolated ASan settings. The tRNS and PLTE free/continue sequences both decode successfully against this full install output. A production M2 scan on the exact generated-source snapshot produced zero findings, but all four files remained parser-partial and ohscanner.cpp.resource_lifetime blocked; this scan does not prove a fixed source state. Runtime controls plus the static report are in runtime-reproduction-20261019.json and openharmony-install-source-production-scan.md.

The selected rk3568 final binary and active libpng implementation remain unknown. Product config selects image_framework with image_framework_feature_upgrade_skia = true. The image framework GN defaults to Skia for this feature and excludes legacy PNG codec plugins on non-cross-platform targets. Skia has libpng decode enabled by default, but skia_use_system_libpng depends on is_official_build; the OH Skia config defaults skia_use_system_lib = false, while is_official_build defaults false in GN. No selected product args/global_parts_info/build.ninja or final link manifest is present to confirm overrides. The Skia bundled libpng externals directory exists but is empty in this checkout. Source therefore shows a conditional route into either system OH libpng or bundled Skia libpng, not which one the product links. Also, third_party/libpng/BUILD.gn declares the tarball and older patches as action inputs but omits CVE-2026-33416.patch, CVE-2026-33636.patch, and CVE-2026-34757.patch; the installer does apply all three. This is a build invalidation concern, not evidence that the checked-in patch set was omitted from an already generated build.
## Current-checkout M2 revalidation (2026-10-19)

To avoid treating earlier report identity strings as proof of a current replay, I built a new isolated synthetic Git source snapshot from the already present, hash-bound SourceForge 1.6.55/1.6.56 extracted release trees. The replay scope is exactly `pngset.c`, `png.c`, `pngread.c`, and `pngrtran.c`; the two synthetic commits bind the source bytes only and are not upstream commit IDs. Source hash, Git blob, tree, snapshot hash, detector version and timings are recorded in `current-m2-source-identities.json`.

Current M2 `ohscanner.cpp.resource_lifetime` v0.1.9 results:

| Snapshot | M2 result | Findings | Parse coverage | Time |
|---|---|---:|---|---:|
| Vulnerable libpng 1.6.55 | `blocked` / `completed_with_limitations` | 2 CWE-416 candidates at `pngrtran.c:1187` and `pngrtran.c:1228` | 4/4 partial | 0.325 s |
| Fixed libpng 1.6.56 | `blocked` / `completed_with_limitations` | 0 same-rule candidates | 4/4 partial | 0.332 s |

The vulnerable findings bind to `pngrtran.c` SHA-256 `4df05c2e5db00911817d7f125c862524205895f34a65106e016d351f7e6edb53`; messages show the paired alias in `pngset.c`, release-shaped `png_free` in `png.c`, and later dereference. No CVE metadata is passed to the detector. The fixed zero remains partial/blocked, so it is not a clean safety verdict. Existing component ASan positive/fixed/no-free controls and post-freeze synthetic variant remain separate evidence and are not promoted to product confirmation.

A fresh replay attempt mistakenly passed the upstream commit hash to the synthetic snapshot repository; Git rejected it before scanning. No report was produced from that attempt. The corrected replay above used the synthetic commits and preserved original release source hashes separately.

A-line suite recheck: `python -m unittest discover -s tests/detectors -v` ran 149 tests with 4 failures and 3 errors, all related to hash/size integrity mismatches in dirty existing manifests/fixtures (null, shared_ptr guard-lifetime, resource-lifetime, memory-safety manifest, null-signal and unsafe-call controls). Focused cross-member positive/fixed/renamed/incomplete tests and vector-index focused test passed 3/3; vector bounds class passed 8/8. Existing dirty fixtures were not rewritten.

Exact next operation: advance the existing A-line parser prerequisite request with this fresh hash-bound M2 evidence and request owner review of a complete C parser profile that makes these four unchanged source files complete without path/CVE hardcoding. Completion condition: rerun the same four-file scope with complete parsing, retain vulnerable candidates, fixed zero same-rule, then replay the source-bound ASan matrix; keep product caller/build/reachability unknown until independently established.

### Source-binding cross-check (2026-10-19)

The current M2 snapshot identities were independently checked against the pre-existing extracted release trees after scanning. All 4/4 files per side match recorded byte length, SHA-256 and Git blob OID; each report scope is exactly the same four files. Both vulnerable diagnostics carry `source_binding=bound` and match the exact `pngrtran.c` source SHA-256. Fixed has no diagnostics to bind. This strengthens source identity only; parser coverage remains 4/4 partial/blocked on both sides.


## Independent current-turn production M2 replay (2026-10-19)

Replayed the exact current-checkout CLI command on the existing byte-bound synthetic source snapshots, without CVE metadata, detector `ohscanner.cpp.resource_lifetime` v0.1.9, and identical four-file scope (`pngset.c`, `png.c`, `pngread.c`, `pngrtran.c`):

| Source | Commit wrapper / tree | Result | Parse / detector | Time |
|---|---|---|---|---:|
| Upstream vulnerable 1.6.55 bytes | `afad740f043acd9bee412677d0a5ff1e046aaa24` / `5d18312a3b10c4aa1a488b91ac41d010606640ef` | 2 candidates at `pngrtran.c:1187` and `:1228` | 4/4 partial; blocked | 0.3335 s |
| Upstream fixed 1.6.56 bytes | `dcd78000a2e39558bd0b9340633d7acff796d37b` / `444dba821b3f8b58326ce85d0daf056f64029ec7` | 0 same-rule candidates | 4/4 partial; blocked | 0.3342 s |
| OpenHarmony full ordered install output | `ef42021d7597d3ca008c08567f0d698df39a4fa3` / `65f42cf3e86c5484802093f86e5f2babd623b573` | 0 candidates | 4/4 partial; blocked | 0.3400 s |

The fresh vulnerable/fixed differential retains the prior UAF candidates and the OH generated output remains silent, but all three runs are parser-partial. Therefore the OH zero result cannot be treated as static proof that the installed output is fixed; the separate ASan component reproduction is quiet for the two tested API sequences. Exact M2 JSON/Markdown outputs are `turn-rerun-vulnerable.*`, `turn-rerun-fixed.*`, and `turn-rerun-openharmony-install.*`. Each report binds the synthetic snapshot identity; these wrapper commits are not represented as upstream commits. Product build selection and caller reachability remain unknown.
