# PC-1 case gate vs portfolio gate

Date: 2026-10-20. This is a read-only acceptance note for the D2/T2 profile work. It records current evidence and review criteria; it does not change the profile manifest, assert product applicability, or authorize a build or PoC.

## Acceptance scope

PC-1 has two related but distinct questions:

1. **Portfolio gate (G12-PC-1):** Are all 16 registered Ark parent/fix cases bound to independently auditable source identities and complete product build/preprocess profiles? The portfolio gate closes only when every required case has its own complete evidence. A passing single case cannot be extrapolated to the other 15.
2. **Case gate (IBS5YG):** Does one explicitly identified target product build contain the relevant Ark Runtime revision, and can its exact build/preprocess inputs and shipped artifact be traced? Passing this gate would close only IBS5YG's PC-1 evidence, not the 16-case portfolio gate.

Current manifest metrics record 16 cases, 6 with `recorded_complete` source-identity fields, and 0 with complete product build profiles. All cases currently report `build_profile.status=BLOCKED`; the IBS5YG D4 matrix separately reports `status=BLOCKED`. `recorded_complete` means fields were recorded; it does not itself prove object-store custody, product inclusion, or a product build.

## Current IBS5YG evidence and unknowns

Frozen source pair recorded for IBS5YG:

- Parent commit `2ea501258ab4155826b64f01b499b43d1911e0e2`, tree `579712c1ebbb703d17cea422b1572023bed5d8a4`, source SHA-256 `847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422`.
- Fixed commit `919e4fbb011f610427e788889083fa8e28d2f951`, tree `82af11ced4297818410ccf61906b703d25b69165`, source SHA-256 `8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e`.
- D4 records source pair ancestry and local object checks as passing for source identity only. Historical acquisition/custody of the local object store is `UNKNOWN` / not independently verified.

The D4 evidence matrix records these profile gaps:

| Profile field | Current disposition | Evidence needed to resolve it |
|---|---|---|
| Product release/version, product name, build ID, branch/tag, locked manifest, board/device | `UNKNOWN` | Product/release owner supplies a uniquely identifying target; then bind the locked manifest and revisions. |
| Ark Runtime product component revision and source relationship | `UNKNOWN` | Exact component revision from that locked manifest and evidence relating it to the frozen parent/fix pair. |
| GN target, successful generation/action, exact product args | `FAIL` to close | Successful target/action and arguments for the identified product build. Existing Sort args/build attempt is excluded. |
| Compiler/linker, toolchain, target triple, sysroot | `UNKNOWN` | Tool identities and hashes, target triple, sysroot, all bound to the successful action. |
| Compile database and complete direct/transitive include closure | `UNKNOWN` | Exact compile action plus complete include and generated-input closure. |
| Generated inputs, preprocessed TU, macro log | `UNKNOWN` | Same-build generated inputs, preprocessing command, macro log, TU bytes and hashes. |
| Successful compile/link output and logs | `FAIL` to close | Successful logs/artifacts for the exact target action; failed or unrelated builds do not qualify. |
| Shipped binary/image and source/component association | `UNKNOWN` | Shipped artifact digest plus auditable mapping from the built target/component into it. |
| Object-store acquisition/custody attestation | `UNKNOWN` | Independent custody/acquisition evidence if required by project policy. |

Minimum intake before target-specific D5 collection: OpenHarmony release; product build ID or image version; source branch or release tag; locked manifest URI or commit; product name; board/device target. All six must identify one build without ambiguity. These inputs are currently `UNKNOWN`. Technical build evidence is collected from the owners below; the product owner need not guess or pre-populate build internals.

## Artifact responsibility map

| Owner | Required evidence/artifacts |
|---|---|
| Product/release owner | Exact release/build, product, branch/tag, locked manifest, board/device, and Ark Runtime component revision/source relationship. |
| Build integration owner | Successful GN generation, target/action identity, exact args/build arguments, successful compile/link logs. |
| Toolchain/build infrastructure owner | Compiler/linker/GN/Ninja identity and hashes, target triple, sysroot, complete direct/transitive include and generated-input closure. |
| Preprocess/build evidence owner | Compile database entry, preprocessing command, macro log, and hashed preprocessed TU from the same build. |
| Product release/verification owner | Shipped binary/image hash and auditable mapping to the compiled Ark Runtime target/component revision. |
| Evidence custodian | Independent object-store acquisition/custody attestation, if required. |
| D5 profile owner | Assemble a field-level manifest and artifact ledger; preserve `UNKNOWN`/`BLOCKED` when evidence is absent; revise after T2 findings. |
| T2 independent reviewer | Independently recompute identities/hashes and challenge closure and cross-case/product mismatches; return field-level counterexamples to D5. T2 does not construct D5 evidence or close product applicability. |

## T2 independent challenge cases

T2 should test whether D5's verifier and evidence ledger fail closed on at least these counterexamples. Use synthetic mutations or read-only record review only; do not substitute a wrong artifact into the product profile.

1. **Cross-case contamination:** use another case's valid manifest, args, toolchain or TU while leaving the IBS5YG case ID unchanged. Expected: reject because case/source/build identity does not match.
2. **Parent/fix or component-revision mismatch:** bind the fixed revision where the parent is expected, or cite a product component revision with no verified relationship to either frozen source. Expected: field remains `UNKNOWN`/`FAIL`; no inferred ancestry.
3. **Unrelated product/build:** reuse the Sort CVE-2025-23420 OpenHarmony 5.0.2 host-tools args/logs or the C1 `a65a2853ccae13da167d9aa4720ab8b11ec16656` profile. Expected: reject as unrelated; they do not identify the IBS5YG component/build.
4. **Failed action presented as successful:** provide args.gn without successful GN generation/build, a log that fails before Ark Runtime compilation, or a missing target output. Expected: do not mark target/action or compile/link fields complete.
5. **Partial configuration closure:** omit a transitive include, generated header/input, compile database entry, macro log, or TU; provide a TU from a different action. Expected: profile remains blocked because closure and same-action binding are incomplete.
6. **Host/product tool confusion:** label host compiler/prebuilt tools as the product compiler or omit the target triple/sysroot. Expected: reject the toolchain field as unbound.
7. **Binary/source association gap:** provide a binary hash with no build provenance or product integration mapping, or a source revision with no shipped artifact digest. Expected: no shipped-product association.
8. **Hash/identity drift:** mutate bytes while retaining the recorded SHA/blob/length, or provide a matching hash for the wrong path/revision. Expected: recomputation fails or identity mismatch is reported; never pass on a hash field alone.
9. **Portfolio aggregation error:** close IBS5YG and claim PC-1 portfolio closure while any of the other 15 cases remains incomplete. Expected: case-level pass is preserved, portfolio PC-1 remains open.
10. **Unknown laundering:** replace missing release/build/board/manifest values with a neighboring release guess or infer product inclusion from source ancestry alone. Expected: reject; retain `UNKNOWN`.

For each challenge T2 should report the exact input field/artifact, independently recomputed value, expected rejection/unknown disposition, actual result, and D5 correction needed. After D5 revises the profile, T2 must re-audit the new manifest digest. T2 acceptance of the profile ledger is not a product vulnerability finding and does not close PC-3, PC-4, PC-5, or PC-6.

## Current task-tree disposition

The current G12 tree remains `ACTIVE_NOT_ADMITTED`: PC-1 `IN_PROGRESS_BLOCKED`; PC-2 `PIPELINE_IMPLEMENTED_NOT_EXECUTED`; PC-3 `BLOCKED`; PC-4 and PC-5 `NOT_RUN`; PC-6 `NOT_ADMITTED`. PC-1 portfolio completion requires all 16 profiles. PC-3 additionally requires per-case product entry, privilege boundary, attacker-controlled trigger, reachable sensitive operation, and concrete CIA impact. PC-4 requires the product-build and applicability gates plus explicit authorization; PC-5 requires a valid PC-4 reproduction and a fixed build using the same profile.

## Evidence references

Hashes below identify the local records read for this note; they do not attest product artifacts that are absent.

| Record | Local path | SHA-256 |
|---|---|---|
| 16-case build/profile manifest | `research/methods/ark_runtime/build_profile_20261019/ark_parent_fix_build_profile_manifest.v1.json` in worktree `D:\openHarmonyScanner\worktrees\c-d4-ibs5yg-profile-gap-20261020` | `e45469a0f6abfed30797fb58c2cb5b0154b4125c66f82620b52ae88489a27e42` |
| IBS5YG D4 evidence matrix | `research/methods/ark_runtime/ibs5yg_profile_gap_20261020/evidence_matrix.json` in the same worktree | `9c418aed98045a0bf9b16170552c2df7cdb11a8261da59700b7093899d669815` |
| Profile README | `research/methods/ark_runtime/build_profile_20261019/README.md` in the same worktree | `adeb73ec3444c750df26deb23b3859176b803021c3ce4cbcfa3e47378472ba23` |
| G12 task tree | `research/deliveries/product_closure_20261019/task_tree.json` in the same worktree | `1861a62e864949e506ec935db8ecd1313fecefe4130995bcd72c66d2970fbb84` |
| D5 minimum-input intake | `research/deliveries/product_closure_20261019/D5_PRODUCT_TARGET_INTAKE_20261020.json` in worktree `D:\openHarmonyScanner\worktrees\c-line-task-tree-20261020` | `73a14df2c3176a16254af870d049cb0c67aa2bd6a671ab2ce9d94d487659d30d` |

