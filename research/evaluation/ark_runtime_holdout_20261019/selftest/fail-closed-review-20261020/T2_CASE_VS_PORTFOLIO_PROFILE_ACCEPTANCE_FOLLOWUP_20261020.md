# T2 second-round follow-up: profile acceptance contract

Date: 2026-10-20. Scope: independent read-only comparison of the finalized D2 acceptance note, D5 intake, and `profile-spec.json`. No tests, builds, PoCs, or network access were used.

## Artifact identity

| Artifact | Expected SHA-256 | Recomputed SHA-256 | Result |
|---|---|---|---|
| D2 `CASE_VS_PORTFOLIO_PROFILE_ACCEPTANCE_20261020.md` | `0cb727bf2ac73a711fd78dd75cec6b5d47912a540e6273827476582b59c075d3` | `0cb727bf2ac73a711fd78dd75cec6b5d47912a540e6273827476582b59c075d3` | PASS |
| D5 `D5_PRODUCT_TARGET_INTAKE_20261020.json` | `689b374626deae64765e4ef38f89c115e8ad175c4a6be21e8138818321099c6b` | `689b374626deae64765e4ef38f89c115e8ad175c4a6be21e8138818321099c6b` | PASS |
| `profile-spec.json` | `3e65da9ac5119708d5c081d5550f4d1f3753ea834f54cc163fa7e1c7362ddb03` | same | PASS |
| 16-case profile manifest | `e45469a0f6abfed30797fb58c2cb5b0154b4125c66f82620b52ae88489a27e42` | same | PASS |
| D4 IBS5YG evidence matrix | `9c418aed98045a0bf9b16170552c2df7cdb11a8261da59700b7093899d669815` | same | PASS |
| Current owner task tree | `1861a62e864949e506ec935db8ecd1313fecefe4130995bcd72c66d2970fbb84` | same | PASS |

## Independent set comparison

The `profile-spec.json` source of truth declares these **10 required identity fields**:

`commit`, `tree`, `blob`, `source_sha256`, `detector_rule_version`, `scope`, `profile`, `config_hash`, `parser_identity`, `toolchain_identity`.

D2's finalized per-case contract lists all 10, with case-specific acceptance evidence for each. D5's `case_profile_required_identity_fields` array matches the spec exactly: no missing, extra, or substituted field. **PASS.**

The spec declares these **10 required build inputs**:

`product_manifest`, `exact_args_gn`, `gn_target`, `compile_commands_json`, `actual_include_closure`, `compiler_identity`, `linker_identity`, `sysroot_identity`, `preprocessed_translation_units`, `macro_expansion_log`.

D2 explicitly enumerates all 10 in its acceptance note. D5's finalized `case_profile_required_build_inputs` array matches `profile-spec.json` exactly: no missing, extra, or substituted field. D5's `same_build_evidence_closure` further requires immutable manifest identity/digest; successful GN generation, target/action, exact args and compile/link logs; compiler/linker, target triple, sysroot, compile database, generated inputs and complete direct/transitive include closure; preprocess command, macro log and TU bytes/digest; and shipped binary/image digest plus source-to-product mapping. **PASS.**

## Follow-up checks

| Check | Status | Evidence and disposition |
|---|---|---|
| Previous omission of detector/parser/config identity | PASS — corrected | D2 now enumerates the complete 10-field identity set, and D5 carries the same exact array. It also requires per-case binding and blocks missing/unverified fields. |
| Exact build-input set | PASS — corrected | D5 now exposes `case_profile_required_build_inputs`; independent ordered comparison with the spec gives exact 10/10 equality. Its close-case rule requires every listed input, and the same-build closure supplies corresponding provenance details. |
| Immutable manifest routing | PASS — corrected | D2 and D5 both require an immutable commit or manifest URI plus verified/recomputed content digest. Branch/tag or undigested URI is only a locator. |
| Case versus portfolio gate | PASS | D2 and D5 require all 16 case gates for portfolio PC-1. D5 explicitly limits an IBS5YG pass to that case and says portfolio status stays `IN_PROGRESS_BLOCKED`. The current manifest hash and contents still show 16 cases, 6 `recorded_complete` source-identity entries, 0 complete product profiles; current task tree hash/content still shows PC-1 `IN_PROGRESS_BLOCKED`. |
| Same-build build/preprocess/binary closure | PASS — criteria; actual profile UNKNOWN | The D5 closure covers all required build inputs plus generated inputs, successful actions/logs, preprocessing command/TU/macro data, shipped digest and source-to-product integration. No new product artifact is present in this review; D4 matrix remains `BLOCKED`. |
| Sort/C1 exclusion | PASS — criteria; product relationship UNKNOWN | The finalized D2 document retains the explicit exclusion and the D5 intake continues to cite the D4 matrix and Sort failed-attempt record by digest. The record hashes were independently matched in the prior T2 round; this second round did not rebuild either artifact. |
| Evidence-owner responsibility | PASS with custody limitation | D5 lists product/release, build integration, toolchain, preprocessing, product verification and custodian roles. D2 assigns profile assembly to D5 and independent recomputation to T2. Custody attestation remains conditional on admission policy; whether the policy requires it is still UNKNOWN. |
| Local artifact search scope | PASS — claim narrowed | D5 now limits the negative search claim to the D4 matrix and cited Sort/C1/profile-verification records, and expressly says it is not exhaustive across worktrees. This avoids treating that search as proof of global absence. |
| Target intake readiness | PASS — gate correctly blocks | All six target-routing values remain null and status remains `WAITING_FOR_PRODUCT_OWNER_INPUT`. The locked manifest identity must be immutable. D5 can collect technical internals after target routing; the product owner is not asked to guess build details. |
| Source object custody / authenticity | UNKNOWN | D2 still accurately distinguishes local object checks from independent acquisition/custody verification. The source identity fields and their recorded hashes do not by themselves prove acquisition history or product inclusion. Keep this limitation visible and follow the governing admission policy. |

## T2 disposition

**Acceptance-contract review: PASS. Product case profile: UNKNOWN / BLOCKED. Portfolio PC-1: IN_PROGRESS_BLOCKED.** The previous D5 identity-field omission, missing explicit build-input array, mutable-manifest ambiguity, and unbounded local-search statement have been corrected. Identity and build-input arrays each match `profile-spec.json` exactly (10/10); both case and 16-case portfolio gates are explicit. No target product inputs or same-build product artifacts have arrived, so this review accepts the contract only; it does not accept a completed IBS5YG profile, close PC-1/PC-3, or establish a vulnerability or safety conclusion.
