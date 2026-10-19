# C4 exact source replay through Runner

Source bytes were obtained for the exact upstream revisions and independently checked against the Git blob OID and SHA-256 recorded below. They were passed through the registered Catalog detector and public `run_all_with_coverage` Runner adapter with the exact repository, commit, target path, Git-object provenance, `light-ast` profile and partial AST facts.

| Revision | Git blob | SHA-256 | Bytes | Runner status | Coverage | Candidate |
|---|---|---|---:|---|---|---:|
| Parent `830e85b40240677039719fcbf14f721ad3b19050` | `054451b1be4f39254d56a1683cc9d1c1b5e55018` | `847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422` | 150433 | blocked | 0 complete, 1 partial | 1 |
| Fix `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `95f54f2875f401afe3167c62f8c1e7799782be8c` | `8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74` | 150509 | blocked | 0 complete, 1 partial | 0 |

The candidate carries `model_applicability`, `runtime_path_feasibility`, `security_impact`, `isolated_validation`, and `parse_completeness_impact` obligations. The fixed revision emits no finding under this rule. This is a source-bound static replay, not a dynamic reproduction and not proof of safety.

The model/detector version is `0.6.1`, digest `3069f778c0869e00b8a8a67429811c62444aa5e5025a3ffe41e792280072147c`. The temporary source files were not added to the repository.

A second, independent rule covers the allocation exception path at another exact upstream parent/fix pair. See C4_EXCEPTION_GUARD.md; it is not included in the type-origin candidate counts above.


## Caller-profile sweep at the exact source bindings

The fixed translation unit was also run with `research_partial=True` after exact commit/path/blob/SHA checks. This is the internal research path used by the registered adapter; it does not change the partial file outcome.

| Commit | Parse / outcome | Local function observations | Remaining limitation |
|---|---|---|---|
| Parent `830e85b40240677039719fcbf14f721ad3b19050` | partial / partial | CopyWithin: matched at 964; Filter: candidate at 1498; Set: matched at 2234; With: matched at 1762 | `experimental_partial_function_scope`, `experimental_partial_scope_routed_through_exact_binding_adapter`, `parse_dependency_contamination_unknown` |
| Fix `a0e30483ab3e4aead67ecfb5c708489915e447f9` | partial / partial | CopyWithin: matched at 964; Filter: matched at 1499; Set: matched at 2235; With: matched at 1763 | Same three limitations |

The registered Runner's evidence contract remains conservative: the parent preserves one Filter candidate and the fixed source preserves none; both are blocked with one partial file. A local `matched` observation means only that this bounded model found the reviewed local type relation on the exact bound input. It is not a whole-file safe verdict.
