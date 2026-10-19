# C13-CROSS-FILE-FACTS gap ledger

## Scope

- Worktree: `E:\网安\CyberSecurity-Innovation-Audit-c13-cross-file-20261019`
- Branch: `codex/c13-cross-file-facts-20261019`
- Base HEAD: `842948084660207fd64399cfd598ed93e5593dcc`
- Base tree: `ce857096f56653c1194528aca45507b15379ab5c`
- Remote: `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`
- Slice rule: evidence-only. No algorithm modification, no push, no merge, no Ready marking.
- Status vocabulary: `fact_state=matched` means the requested fact or expected negative fact was deterministically observed by the listed control. `fact_state=unknown` means the fact remains unresolved. No row upgrades a vulnerability to candidate/confirmed/reportable.

## Source-bound identity

Every row references `I*` entries below. Full worktree blob OIDs and SHA-256 values are in `source_identity.txt`; 62 fixture identities are in `fixture_identity.txt` (`manifest_body_file_sha256=6204e587e1df93b75ae269370a7a71d2738d07d431383103324971fe2dbe31a8`).

| Ref | Source identity | Worktree blob | HEAD blob | Worktree SHA-256 |
|---|---|---|---|---|
| I01 | `src/ohscanner/detectors/ark_runtime/analysis.py` | `836a3f2c75e5e4d97bcf82d49aabe9a67f6ede66` | same | `808dbf14832d3747f528d2601d669040faad6d796b4555c978a3ff20994a031f` |
| I02 | `src/ohscanner/detectors/ark_runtime/cross_helper.py` | `ca8a4f1af23053906ad81f179419254db0d405c8` | same | `d99861674d1a9e2d52b6a44a9f2e1d9deffba8fb43ce86980e31b1673f107bd6` |
| I03 | `src/ohscanner/detectors/ark_runtime/cross_file_facts.py` | `f29f2cfdd608b928969c43f1ac5807ae595f714f` | absent | `e3a6b5e7ab00ae8c69290b0d9fc53ef92fa034a512fa4e744a3b326fbe482139` |
| I04 | `src/ohscanner/detectors/ark_runtime/detector.py` | `788666ce30f06adfddc714690f03092e1ef906b4` | `25c699fbf4e600ad939a1f73ad99731270624485` | `3f682baef654aee6e1b8feacbacd026701bc2e9f18c89f8567b2176db9d19a2e` |
| I05 | `src/ohscanner/detectors/ark_runtime/model.py` | `92438eeb4597cf819397a6cd69e030a78e84bc5a` | `ecdd988952182a8f34b89e4828d8f50aa77f0415` | `46ecc77ac875e0d18cfd6ca9f5f20b1ea406d0eed68f5534f197e49bc753a33d` |
| I06 | `src/ohscanner/detectors/ark_runtime/runtime_ir.py` | `4fa98998c17d5bae6361c68740fe0e5b3d636044` | same | `c082c30ba8b3501357d00fc76dc6bb5d113501675689de0a72a0489c26ed41a2` |
| I07 | `src/ohscanner/detectors/ark_runtime/size_overflow.py` | `fa2b19ac241845dfdc922f21005adc3b40e60078` | same | `82dc5aa2decfd71813f2b741f7d3731d03ec6abf69ee92759b96bce43b5daf7d` |
| I08 | `src/ohscanner/detectors/ark_runtime/syntax.py` | `8507a127856d22af01a6eaa64738c8030ed414af` | same | `b1dd8d2e5b9a4e0f30cd39f77e9a86ff5c42345066b21858e19f0b191b78245d` |
| I09 | `tests/detectors/ark_runtime/test_c11_alias_cross_helper.py` | `0cd460fa4a8362428065a316e4c1d53b03145856` | same | `cdc402fc91e42b7b77b2366d92f4f10c1a4b8e24ec6ef5af72507a9dc91bf430` |
| I10 | `tests/detectors/ark_runtime/test_c12_deep_semantics.py` | `650e1304d77114e91457faf6b14bc2a2332e19d8` | same | `09456d3a6d75595108affce5127ba15e357b780f07fad85bbbdb351c862d56b6` |
| I11 | `tests/detectors/ark_runtime/test_c13_cross_file_facts.py` | `d601c8fbf07c156d7d1e36d42387d99da43e0269` | absent | `1e99de1987e8c023df654b3ba5d142de7172c3056173ddb62224b737b67c21ed` |
| I12 | fixture manifest, 62 files | see `fixture_identity.txt` | tracked fixture blobs | manifest body hash above |

Important binding limitation: `cross_file_facts.py` and `test_c13_cross_file_facts.py` are untracked, while `detector.py` and `model.py` are modified in the worktree. Therefore the tests validate the exact worktree hashes above, not a clean commit-only implementation.

## Validation evidence

- Exact test command: `python -m unittest -v tests.detectors.ark_runtime.test_c11_alias_cross_helper tests.detectors.ark_runtime.test_c12_deep_semantics tests.detectors.ark_runtime.test_c13_cross_file_facts`
- Interpreter: `C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`
- Result: 30 tests run, 28 passed, 2 failed, exit 1. Raw output: `unittest_raw.txt`.
- Exact compile command: `python -m compileall -q src tests`
- Result: exit 0. Raw output: `compileall_raw.txt`.
- `pytest` was unavailable in the selected bundled interpreter (`No module named pytest`); `pytest_raw.txt` preserves that environment result. The unittest run above executed the same unittest cases.
- `git diff --check` is recorded after ledger creation in the delivery note and final handoff.

## Positive controls

| ID | Mechanism | fact_state | Observed fact/control | Test evidence | Source refs | Limitation | Next minimal algorithm target |
|---|---|---|---|---|---|---|---|
| P-ALIAS | alias | matched | alias fact bound to source unit and SHA-256 | `CrossFileFactControls.test_positive_alias_cast_helper_summary_loop_and_include_are_bound`; `C11AliasCrossHelperControls.test_alias_cast_helper_and_loop_controls_are_fail_closed` | I01,I03,I09,I11,I12 | local syntax fact only; no ownership, dominance or exploitability proof | T3 |
| P-CAST | cast | matched | cast fact bound to source unit and SHA-256 | `CrossFileFactControls.test_positive_alias_cast_helper_summary_loop_and_include_are_bound`; `NumericCastSignWidthControls.test_positive_signed_narrowing_is_candidate` | I03,I07,I10,I11,I12 | sign/width fact is finite syntax/IR evidence | T4 |
| P-IDENTITY | identity helper | matched | direct helper classified `identity` | `CrossFileFactControls.test_positive_alias_cast_helper_summary_loop_and_include_are_bound`; `CrossFunctionSummaryControls.test_direct_identity_is_still_supported`; `HelperContractControls.test_effectful_helper_has_explicit_contract_and_is_not_identity` | I02,I03,I10,I11,I12 | identity summary is bounded and does not prove product call context | T5 |
| P-LOOP | loop backedge | matched | `LoopBegin/LoopEnd` backedge extracted and source-bound | `CrossFileFactControls.test_positive_alias_cast_helper_summary_loop_and_include_are_bound`; `MinimalLoopBackedgeControls.test_positive_loop_end_backedge_is_audited` | I03,I06,I10,I11,I12 | generated-IR syntax model only | T1 |
| P-SUMMARY | summary | matched | identity summary, resolved include and macro fact bound | `CrossFileFactControls.test_positive_alias_cast_helper_summary_loop_and_include_are_bound`; `CrossFunctionSummaryControls.test_forwarding_chain_is_bounded_identity_summary` | I02,I03,I10,I11,I12 | bounded forwarding chain; include resolution is fixture-local | T2,T5 |

## Fixed controls

| ID | Mechanism | fact_state | Observed fact/control | Test evidence | Source refs | Limitation | Next minimal algorithm target |
|---|---|---|---|---|---|---|---|
| F-ALIAS | alias | matched | fixed alias shape retained as fact without candidate escalation | `C11AliasCrossHelperControls.test_alias_cast_helper_and_loop_controls_are_fail_closed`; `CrossFileFactControls.test_fixed_identity_summary_is_bound_without_effect_contract` | I01,I03,I09,I11,I12 | negative control is fixture-local | T3 |
| F-CAST | cast | matched | unsigned-width fixed control has no candidate | `NumericCastSignWidthControls.test_fixed_unsigned_width_control_has_no_candidate` | I07,I10,I12 | does not prove arbitrary conversion safety | T4 |
| F-IDENTITY | identity helper | matched | fixed helper is effect-free and identity-classified | `HelperContractControls.test_fixed_identity_helper_is_effect_free`; `CrossFileFactControls.test_fixed_identity_summary_is_bound_without_effect_contract` | I02,I03,I10,I11,I12 | bounded helper body only | T5 |
| F-LOOP | loop backedge | matched | fixed exit has no backedge | `MinimalLoopBackedgeControls.test_fixed_exit_has_no_backedge` | I06,I10,I12 | fixed fixture shape only | T1 |
| F-SUMMARY | summary | matched | fixed identity summary bound without an effect contract | `CrossFileFactControls.test_fixed_identity_summary_is_bound_without_effect_contract` | I02,I03,I10,I11,I12 | macro/guard closure is not complete in production regression; see G2 | T2 |

## Safe controls

| ID | Mechanism | fact_state | Observed fact/control | Test evidence | Source refs | Limitation | Next minimal algorithm target |
|---|---|---|---|---|---|---|---|
| S-ALIAS | alias | matched | local alias fact exists but is not a security verdict | `CrossFileFactControls.test_safe_local_shape_is_not_a_security_verdict`; `C11AliasCrossHelperControls.test_alias_cast_helper_and_loop_controls_are_fail_closed` | I01,I03,I09,I11,I12 | `safe` is a control label, not product safety | T3 |
| S-CAST | cast | matched | local zero-product control has no security verdict | `NumericCastSignWidthControls.test_safe_local_zero_product_is_not_security_verdict` | I07,I10,I12 | local zero proof only | T4 |
| S-IDENTITY | identity helper | matched | local identity helper is not a security verdict | `HelperContractControls.test_safe_local_identity_is_not_a_security_verdict` | I02,I10,I12 | no product reachability proof | T5 |
| S-LOOP | loop backedge | matched | zero-iteration shape has no backedge/security verdict | `MinimalLoopBackedgeControls.test_safe_zero_iteration_shape_is_not_a_security_verdict` | I06,I10,I12 | shape-specific only | T1 |
| S-SUMMARY | summary | matched | safe local fact extraction does not imply product safety | `CrossFileFactControls.test_safe_local_shape_is_not_a_security_verdict`; `HelperContractControls.test_safe_local_identity_is_not_a_security_verdict` | I02,I03,I10,I11,I12 | no independent labelled safety data | T2,T5 |

## Unrelated controls

| ID | Mechanism | fact_state | applicability | Test evidence | Source refs | Limitation | Next minimal algorithm target |
|---|---|---|---|---|---|---|---|
| U-ALIAS | alias | matched | not_applicable | `CrossFileFactControls.test_unrelated_source_is_not_promoted_to_a_cross_file_fact`; `C11AliasCrossHelperControls.test_alias_cast_helper_and_loop_controls_are_fail_closed` | I01,I03,I09,I11,I12 | expected absence is fixture-local | T3 |
| U-CAST | cast | matched | not_applicable | `NumericCastSignWidthControls.test_unrelated_conversion_without_allocation_is_not_applicable` | I07,I10,I12 | allocation context is syntactic | T4 |
| U-IDENTITY | identity helper | matched | not_applicable | `HelperContractControls.test_unrelated_helper_has_no_applicable_contract`; `CrossFunctionSummaryControls.test_unrelated_type_helper_is_not_promoted` | I02,I10,I12 | name/type matching is finite | T5 |
| U-LOOP | loop backedge | matched | not_applicable | `MinimalLoopBackedgeControls.test_host_loop_is_unrelated_to_generated_cfg`; `CrossFileFactControls.test_unrelated_source_is_not_promoted_to_a_cross_file_fact` | I03,I06,I10,I11,I12 | host-loop exclusion is supported only for tested shape | T1 |
| U-SUMMARY | summary | matched | not_applicable | `CrossFileFactControls.test_unrelated_source_is_not_promoted_to_a_cross_file_fact`; `CrossFunctionSummaryControls.test_unrelated_type_helper_is_not_promoted` | I02,I03,I10,I11,I12 | no general semantic equivalence claim | T2,T5 |

## Unknown controls

| ID | Mechanism | fact_state | Observed unknown | Test evidence | Source refs | Limitation | Next minimal algorithm target |
|---|---|---|---|---|---|---|---|
| X-ALIAS | alias | unknown | alias propagation through unresolved helper/include remains unknown | `C11AliasCrossHelperControls.test_unknown_wrapper_is_not_promoted_to_safe`; `CrossFileFactControls.test_missing_include_and_unresolved_loop_are_explicit_unknown` | I01,I03,I09,I11,I12 | no whole-program alias graph | T3 |
| X-CAST | cast | unknown | unknown conversion stays partial and is not promoted | `NumericCastSignWidthControls.test_unknown_conversion_is_explicitly_partial` | I07,I10,I12 | no general C++ range/type proof | T4 |
| X-IDENTITY | identity helper | unknown | unresolved/effectful helper is not identity | `HelperContractControls.test_unknown_helper_is_explicitly_effectful`; `CrossFunctionSummaryControls.test_unknown_forwarding_helper_remains_unknown` | I02,I10,I12 | call depth and effect coverage are bounded | T5 |
| X-LOOP | loop backedge | unknown | unresolved loop label/target is fail-closed | `MinimalLoopBackedgeControls.test_unknown_loop_target_is_fail_closed`; `CrossFileFactControls.test_missing_include_and_unresolved_loop_are_explicit_unknown` | I03,I06,I10,I11,I12 | generated labels can cross macros/files | T1 |
| X-SUMMARY | summary | unknown | missing include and unresolved macro/helper closure remain explicit unknown | `CrossFileFactControls.test_missing_include_and_unresolved_loop_are_explicit_unknown`; `CrossFunctionSummaryControls.test_unknown_forwarding_helper_remains_unknown` | I02,I03,I10,I11,I12 | include search is bounded to supplied source units | T2,T5 |

## Observed production gaps

| Gap | Mechanism | fact_state | Exact failing control | Evidence | Limitation | Next minimal algorithm target |
|---|---|---|---|---|---|---|
| G1 | loop backedge / size-product summary | unknown | `ProductionNineShapeRegression.test_nine_known_ark_shapes_have_production_candidate_and_fixed_controls` subtest `ark.runtime.typedarray-buffer-size-multiplication-overflow`, parent `tests/detectors/ark_runtime/fixtures/c13_cross_file_facts/loop_positive.cpp` | production run returned `status=blocked`, `file_outcomes=partial`, `findings=()`, limitation `bounded_size_product_model_no_general_cpp_ranges_or_cfg` | loop fact extraction passes, but production size-overflow closure does not convert the known shape into the expected diagnostic; this ledger does not upgrade it to candidate | T1 |
| G2 | cross-file summary | unknown | same production test subtest `ark.runtime.callback-exception-before-result-conversion`, fixed `tests/detectors/ark_runtime/fixtures/c13_cross_file_facts/runtime_fixed.cpp` | one finding remained at line 7; obligation `cross_file_macro_closure=unknown`; source SHA-256 `06cab796d25f28f1ef86379d0ee1efd058b510dcda510dd9e3aeca2c77be37fe` | fixed macro guard was not summarized as a dominating exception exit, producing a fixed-control failure | T2 |

## Minimal next algorithm targets

| Target | Minimal objective | Required controls | Completion evidence |
|---|---|---|---|
| T1 | Bind generated loop backedges to bounded size-product/range facts across alias/cast summaries | loop positive/fixed/safe/unrelated/unknown plus G1 production subtest | G1 positive emits a source-bound diagnostic and fixed remains clean; unknown remains unknown |
| T2 | Close included macro/guard bodies into source-bound summaries and recognize dominating exception exits | summary positive/fixed/safe/unrelated/unknown plus G2 production subtest | G2 fixed emits no diagnostic; missing include stays unknown |
| T3 | Propagate alias equivalence through exact helper/include identities with fail-closed unresolved edges | alias five-way controls | all alias controls retain expected fact_state and no status promotion |
| T4 | Preserve signedness/width provenance through alias/cast chains and bound unknown conversions | cast five-way controls | fixed/safe/unrelated stay clean; unknown remains partial |
| T5 | Bound identity/effect summaries by exact helper blob and call depth; distinguish constant/effectful/unrelated helpers | identity helper and summary five-way controls | identity/effect controls remain deterministic and unresolved helpers stay unknown |

## Explicit unknowns and non-claims

- Two production regression subtests failed; the slice did not modify algorithms to force them green.
- No candidate, confirmed, reportable, safe, miss, Precision, Recall, FP or FN status is upgraded by this ledger.
- AST/pattern/IR facts do not prove ownership, dominance, concurrency, attacker control or CIA impact.
- No product build, product entry, privilege boundary, runtime PoC, isolated dynamic validation or fixed-product revalidation was performed.
- The dirty worktree contains algorithm work outside this evidence-only slice; it was preserved and not included in this ledger commit.
