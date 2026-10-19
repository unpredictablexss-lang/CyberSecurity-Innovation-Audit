# T4 Review: D2 Supplemental Source Identity Evidence (2026-10-20)

**Reviewed commit:** `0795106aa054b0cda8650d670fae66470ff83a48`
**Review base:** `dc5990f76ad38c12d33d06875753563af3b43c39` (verified clean before review)
**Disposition:** PASS for reproducible local object identity computation, with source-custody and product-profile gates still BLOCKED.

## Scope and commands

Initial T4 worktree: `D:\openHarmonyScanner\worktrees\c-t4-ibs5yg-profile-audit-20261020`. `git rev-parse HEAD` returned the review base above; `git status --short` was empty. Review read D2 content directly from the immutable commit object. The verifier was materialized only in a temporary directory together with the commit JSON and the base manifest; no D2 file or T4 source outside `review/**` was changed.

Recomputed file hashes from the D2 commit blobs (SHA-256 over blob bytes):

| Path | Git blob | Bytes | SHA-256 |
|---|---|---:|---|
| `research/methods/ark_runtime/build_profile_20261019/README.md` | `d7fb71a2124f201b9d4f8a90bb4c413f96c69d75` | 10055 | `bf1b98ed86a3e5c1c273f2369fe283f304abe15f2d80161e26dbb5ea101d41b6` |
| `research/methods/ark_runtime/build_profile_20261019/supplemental_source_identity_evidence.py` | `25d2ed2c7fe803e1cdf5f970f12c43c0b8d80b2b` | 12468 | `c9e235881c45c2f4373815e4ee2e9e8bd52210492a2169cf61c2b2e585ea944c` |
| `research/methods/ark_runtime/build_profile_20261019/supplemental_source_identity_evidence.v1.json` | `e429707c79d9709e043d9a957ff9224147868028` | 22048 | `1a578b992a11fb1f2bbf2725fa0598bcaf9e89c1e6032ffbc5bd9d823a13e34d` |

Exact read-only verifier invocation (temporary materialization; output path points to temp copy):

```powershell
python supplemental_source_identity_evidence.py --git-dir "D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git" --verify-only
```

Result: exit code 0, stdout `verified supplemental source identity evidence`, stderr empty. The script recomputed evidence from local object storage and compared exact serialized JSON. No network fetch or target build/test was run.

## Case-by-case object results

The 7 IDs are the manifest’s 7 `recorded_incomplete` cases with at least one anchored commit. For each, the pinned manifest digest is `a33c893cce5ba4bd2dbc80e7f94b3ce47a5c6c0ed8b62f5157fb7db8aeb7c214`. Table gives historical manifest tree → recomputed local tree and whether an expected tree existed. `NR` means the manifest did not record a comparable value.

| Case | Parent commit / tree | Fixed commit / tree | Tree checks | Parent→fixed ancestry |
|---|---|---|---|---|
| `ARK-RUNTIME-CALLINFO-CONSTRUCTION-PENDING-EXCEPTION-I7K7L6` | `11c5ad59240da5603504821d674c499e3cbff75a` / `2614d90ed3924631ed455a302093a0a5d5a668da` → `2614d90ed3924631ed455a302093a0a5d5a668da` | `f596e410db3ab90a4706a248cf935b135a62490a` / `9bcf5a2aaaa2fcdf35719d4641ed7e3bfde8400c` → `9bcf5a2aaaa2fcdf35719d4641ed7e3bfde8400c` | parent `MATCH`, fixed `MATCH` | `PASS` |
| `ARK-RUNTIME-INSTANCEOF-EXCEPTION-RETURN-VALUE-I7SDBG` | `905f840797ff27839d9d984aee36c0f8a773adb2` / `NR` → `d0c68ae8fc7a5e0cbc9c4c60800d4d550eb35b37` | `c73261dd8452524fa707c0b3c768e899786d22f2` / `NR` → `77e27c24686ff4d8b3bee0913af8a4f29386ddb5` | parent `NOT_RECORDED`, fixed `NOT_RECORDED` | `PASS` |
| `ARK-RUNTIME-NEWCALLINFO-EXCEPTION-GUARD-IB40SU` | `811daec3dc48a2ba4426b9c6eea7bcc1ee7ab315` / `NR` → `b20077ce95fed3c0ecc7ca3e147a17bd7ef9bbc4` | `3bf1a3cee91252507d02ebcd0ef332d61bbad342` / `NR` → `a4d25adf9122ca9857319372bcae84af580d7055` | parent `NOT_RECORDED`, fixed `NOT_RECORDED` | `PASS` |
| `ARK-SHAREDARRAY-FINDINDEX-EXCEPTION-PROPAGATION-PARTIAL-2A9BCFB` | `4972b782328d8d3587dded347b0a7f3158120b1d` / `NR` → `774da68efa3097fb89f6846d53fbd31fa92eeec7` | `2a9bcfb6082a25ebd0b35ab4a31202ce062aae6d` / `NR` → `4edac3274a498fa0b0352960cff2c77cc8000d21` | parent `NOT_RECORDED`, fixed `NOT_RECORDED` | `PASS` |
| `ARK-TYPEDARRAY-FILTER-RECEIVER-TYPE-GUARD-IAO7E8` | `c4c52fb57b6e204128e1520340c8e66c8e708981` / `7e1498c2be74908365e2a984e0c5edd5f639fc2f` → `7e1498c2be74908365e2a984e0c5edd5f639fc2f` | `2a70904be0e21a37a666eb00cab49d02068260ea` / `8e5503ee7eebbb8e72bc6d5ca0cb88d5775301ef` → `8e5503ee7eebbb8e72bc6d5ca0cb88d5775301ef` | parent `MATCH`, fixed `MATCH` | `PASS` |
| `ARK-TYPEDARRAY-MAP-NEWARRAY-PENDING-EXCEPTION-IC7B8Q` | `bcf67a5df41bcf37b94d848812e54884f6bedb95` / `27ec52bd443ccd4e45b472731114e8547df71ea2` → `27ec52bd443ccd4e45b472731114e8547df71ea2` | `b362fab4f80c7466b1a33d882fa65b828d952712` / `identity manifest` → `bad9c4b3b9e868fcf07a36ab864978fd8ad598f2` | parent `MATCH`, fixed `NOT_RECORDED` | `PASS` |
| `ARK-TYPEDARRAY-MAP-STORE-TYPE-ORIGIN-CVE-2025-24304` | `c4623e514d5648aa0f7fe33631c8379b31cba7c4` / `454e898b43b55950b104053cf42d32645474ef8f` → `454e898b43b55950b104053cf42d32645474ef8f` | `6627179cbf6f8d40d1adfcf5c3c686b902f42419` / `fa482a14984ee8cd8f424131cb5179ba7a6a9422` → `fa482a14984ee8cd8f424131cb5179ba7a6a9422` | parent `MATCH`, fixed `MATCH` | `PASS` |

Per-path blob ID, raw SHA-256, byte count and checks against the historical manifest:

### `ARK-RUNTIME-CALLINFO-CONSTRUCTION-PENDING-EXCEPTION-I7K7L6`

| Side | Path | Recomputed blob | Recomputed SHA-256 | Bytes | Historical blob / SHA / bytes checks | Result |
|---|---|---|---|---:|---|---|
| parent | `ecmascript/ecma_macros.h` | `6d4ac758d955085d7192ec11bc26a1529936a44a` | `0c842369e3259807df2148a9138ccdc5d2a6712e1a0af86ca41fe4e77d26f761` | 38236 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| parent | `ecmascript/js_iterator.cpp` | `7ff9cd673b260b41417d749d6066095740f0c3cb` | `4dbd5bc460ed68820bff3e639355a183ea26b7089c0022288a0a796f707859ee` | 14782 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| fixed | `ecmascript/ecma_macros.h` | `6d4ac758d955085d7192ec11bc26a1529936a44a` | `0c842369e3259807df2148a9138ccdc5d2a6712e1a0af86ca41fe4e77d26f761` | 38236 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| fixed | `ecmascript/js_iterator.cpp` | `bbeb6300a42110837af7065accb53f04cc0ddbdb` | `dcd1e8a3593bc07dc83aa8a7c3a989b20e41cf301174c8d300545229429e7144` | 14898 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |

### `ARK-RUNTIME-INSTANCEOF-EXCEPTION-RETURN-VALUE-I7SDBG`

| Side | Path | Recomputed blob | Recomputed SHA-256 | Bytes | Historical blob / SHA / bytes checks | Result |
|---|---|---|---|---:|---|---|
| parent | `ecmascript/ecma_macros.h` | `a44172fb7b886ee788020b4b4a8472def56e3703` | `8ba3030f1a6f92bc176c69a42974e60e83876d49cacc2077e9392a7bec341f0e` | 38511 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| parent | `ecmascript/stubs/runtime_stubs-inl.h` | `91f1c6c2d2c6184554de2c9f7db8144e4a078ee9` | `d37464b716c3bfe4cb4baa3753c7613603fa93308959f9cb71ca9ae4ed81acfe` | 125331 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| fixed | `ecmascript/ecma_macros.h` | `a44172fb7b886ee788020b4b4a8472def56e3703` | `8ba3030f1a6f92bc176c69a42974e60e83876d49cacc2077e9392a7bec341f0e` | 38511 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| fixed | `ecmascript/stubs/runtime_stubs-inl.h` | `2b582ba6e7510a5e5cea56026e8ba9f4f46310b9` | `5eeeb9a98119f9bd0fd9dacae3261b46d1ead36545cf34e3adfce1956f30a439` | 125283 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |

### `ARK-RUNTIME-NEWCALLINFO-EXCEPTION-GUARD-IB40SU`

| Side | Path | Recomputed blob | Recomputed SHA-256 | Bytes | Historical blob / SHA / bytes checks | Result |
|---|---|---|---|---:|---|---|
| parent | `ecmascript/builtins/builtins_async_from_sync_iterator.cpp` | `3fb6a992fdc69690a2604452caeb00c3f5959593` | `5ca4084a53c2b86baeae9e4549838d250637eeb16f2622cc1f04cf46479f609c` | 11186 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| parent | `ecmascript/ecma_macros.h` | `2f93576f54544ee95c5b57ee8d7bb6b0b8a2b3bb` | `9ad43ea1a799f3ef7b7010bf96124fa1063947b199a84bd3804fa45bdf9a3665` | 50070 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| fixed | `ecmascript/builtins/builtins_async_from_sync_iterator.cpp` | `633fba4ae9964a97850b6b4f4ab5bf3646d707ba` | `a82f3665c6a62cd9c42d6e48748ff133fcab5c3e34042be3d8058421d8316986` | 11269 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| fixed | `ecmascript/ecma_macros.h` | `2f93576f54544ee95c5b57ee8d7bb6b0b8a2b3bb` | `9ad43ea1a799f3ef7b7010bf96124fa1063947b199a84bd3804fa45bdf9a3665` | 50070 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |

### `ARK-SHAREDARRAY-FINDINDEX-EXCEPTION-PROPAGATION-PARTIAL-2A9BCFB`

| Side | Path | Recomputed blob | Recomputed SHA-256 | Bytes | Historical blob / SHA / bytes checks | Result |
|---|---|---|---|---:|---|---|
| parent | `ecmascript/builtins/builtins_shared_array.cpp` | `1e841711a8b974802892d7a9968a51393cb8c9d1` | `828c8119ddafdd0794113c5ee6135b5c56e76db24852a05e789e028d0c1616ed` | 114213 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| parent | `ecmascript/ecma_macros.h` | `4c27b6788d5218f9d04e509bd895231d28b7804b` | `e73f8c2fe7baa0e49d78f2a9a07f3d9d951f8453f408ba6aee96ed8ee9616052` | 49940 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| fixed | `ecmascript/builtins/builtins_shared_array.cpp` | `fe50ae41382d496ca2508bfba31a30518403b501` | `ce6c79210f411ca962ce37bd1dec7fc1135100d0f444fc289a773b9cbe1eaf59` | 114238 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| fixed | `ecmascript/ecma_macros.h` | `4c27b6788d5218f9d04e509bd895231d28b7804b` | `e73f8c2fe7baa0e49d78f2a9a07f3d9d951f8453f408ba6aee96ed8ee9616052` | 49940 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |

### `ARK-TYPEDARRAY-FILTER-RECEIVER-TYPE-GUARD-IAO7E8`

| Side | Path | Recomputed blob | Recomputed SHA-256 | Bytes | Historical blob / SHA / bytes checks | Result |
|---|---|---|---|---:|---|---|
| parent | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `e1e4f6411df4733b8f1ba5b679189e29d904a63f` | `f1cdd8d0707cab2ac9bb9e024383151435bfc279c6815c5eceb98925974ff1a4` | 125744 | MATCH/MATCH/MATCH | `OBJECT_BYTES_RECOMPUTED` |
| parent | `test/moduletest/typedarrayfilter/typedarrayfilter.js` | — | — | — | no expected path | `NOT_PRESENT_IN_THIS_SIDE` |
| fixed | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `df765b9c212dc2e55c38dc385f85f183ce6606da` | `b51826a74a89d6ee105c4087b4260363a7abfd632bb2c68d43c0ee9b17c883c5` | 125744 | MATCH/MATCH/MATCH | `OBJECT_BYTES_RECOMPUTED` |
| fixed | `test/moduletest/typedarrayfilter/typedarrayfilter.js` | `c0e05428adb80360d355e17bb87c8db16d46f04b` | `f14585618ac3e97237817a5ed26df8b560dde0aa96a0718250ba533dfaf6ed24` | 839 | MATCH/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |

### `ARK-TYPEDARRAY-MAP-NEWARRAY-PENDING-EXCEPTION-IC7B8Q`

| Side | Path | Recomputed blob | Recomputed SHA-256 | Bytes | Historical blob / SHA / bytes checks | Result |
|---|---|---|---|---:|---|---|
| parent | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `34f6aa2c6ccaad144a2038c8aab208ea290b5a86` | `2c45da670fcb4170176bb9bd93da7d21dbc286925a0ca1126d250318412417ff` | 152029 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| parent | `test/moduletest/typedarraymapoverflow/typedarraymapoverflow.js` | — | — | — | no expected path | `NOT_PRESENT_IN_THIS_SIDE` |
| fixed | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `893a63a79b6ab85a1473a4f3b33315db0f848a37` | `0abdb870aff6560c671895c0e3360bb3e82fb052cb6a7cf28a90a8c6443044a5` | 152737 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| fixed | `test/moduletest/typedarraymapoverflow/typedarraymapoverflow.js` | `9f40e6ce18950c3164b01de9b1e455c9dc4f8eb4` | `f3b377735b1a47e9e3adc2cee69790104655a01ebff6dea37dbab38082972e19` | 1037 | NOT_RECORDED/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |

### `ARK-TYPEDARRAY-MAP-STORE-TYPE-ORIGIN-CVE-2025-24304`

| Side | Path | Recomputed blob | Recomputed SHA-256 | Bytes | Historical blob / SHA / bytes checks | Result |
|---|---|---|---|---:|---|---|
| parent | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `2aae41b75a5ffd1441309439ff3834d959f71b79` | `6133af44de48ec3ff00fdc7b06597fbef1c9a270cc04ba48d09b4475976c2381` | 150108 | MATCH/MATCH/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |
| fixed | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `1818dd72f5ac68aa7f8ee7a38a59b923f4ab5476` | `32e98e94d7dca38607b4a028c567ce2c5d9182742df41acf98cc012dead5b1d1` | 150189 | MATCH/NOT_RECORDED/NOT_RECORDED | `OBJECT_BYTES_RECOMPUTED` |

## Unanchored variants and field-level feedback

The following remain `UNKNOWN`; the manifest supplies no bound parent/fixed pair and path scope. No identity was inferred:

| Case | Missing manifest anchors |
|---|---|
| `ARK-ARRAY-CALLBACK-ABRUPT-COMPLETION-HISTORY-VARIANT` | parent/fixed commit and scope are null; the manifest text mentions two history commits but does not bind either to this pair |
| `ARK-DATAVIEW-INDEX-WIDTH-AND-BOUNDS-IB8BCA` | parent/fixed commit, tree, and file paths are null |
| `ARK-TYPEDARRAY-CONSTRUCTOR-LENGTH-NARROWING-I7W51D` | parent/fixed commit, tree, and file paths are null |

D2 field feedback:

- **IC7B8Q fixed tree:** manifest fixed `tree` is the literal `identity manifest`, not a 40-hex OID. The supplemental record correctly leaves `tree_check=NOT_RECORDED` while computing actual fixed commit tree `bad9c4b3b9e868fcf07a36ab864978fd8ad598f2`. This is supplemental computed identity only; it does not repair or rewrite the historical manifest. Parent tree matches its recorded tree.
- **Unrecorded tree fields:** I7SDBG, IB40SU and 2A9BCFB have no expected trees in the historical manifest; computed commit trees are useful object-store evidence but cannot be called expected-value matches.
- **Unrecorded blob/SHA/length fields:** most source values have no historical expected values. The verifier appropriately marks these `NOT_RECORDED`; recomputation must not be promoted to an independent expected value. IAO7E8’s recorded builder blob/SHA/length and fixed test blob match; the test SHA/length were not recorded. CVE-2025-24304’s recorded parent blob/SHA and fixed blob match; fixed SHA and both lengths were not recorded. No expected-value mismatch was observed.
- **Three unanchored variants:** I7W51D, IB8BCA and CALLBACK remain UNKNOWN. Please preserve null commits/tree/path fields until a source owner supplies bound identities; similar titles or historical commit mentions are insufficient.
- **Verifier reporting hardening (non-blocking):** `--verify-only` proves deterministic equality of the saved record to recomputation, while its success text can be read as an all-claims pass. Consider emitting explicit aggregate counts for `MATCH`, `NOT_RECORDED`, `MISMATCH`, and unanchored cases, and failing or warning on mismatches. The current records contain zero mismatches, so this is a clarity/defense-in-depth suggestion, not a finding against these outputs.

## Decision boundaries

- **Object verification:** PASS for the 7 anchored cases against the configured local bare object store: 14 commit objects resolve to trees; 26 side/path checks include 24 present blobs recomputed with blob OID, SHA-256 and byte length plus 2 absent-on-side paths; all 7 parent commits are ancestors of their fixed commits. Seven recorded trees match; the other seven comparisons are `NOT_RECORDED` (including IC7B8Q fixed malformed tree value).
- **Acquisition custody / authenticity:** UNKNOWN. Bare-store status and configured Gitee origin match the declared URL, but this does not authenticate how the object store was acquired, its custody, or the server response. The script explicitly labels custody `NOT_INDEPENDENTLY_VERIFIED`.
- **Product profile:** still BLOCKED / NOT_ADMITTED, 0/16 complete, PC-1 `IN_PROGRESS_BLOCKED`. Source object identity does not show target product revision, build configuration, compile/include closure, preprocessing, runtime path or shipped-binary association. This supplemental evidence does not complete a case product profile or portfolio.

## Scope integrity

Only this report is within the T4 write allowlist `research/methods/ark_runtime/ibs5yg_profile_gap_20261020/review/**`. No D2 branch/file, historical manifest, evidence JSON, network source, product build, test, or PoC was modified/run.
