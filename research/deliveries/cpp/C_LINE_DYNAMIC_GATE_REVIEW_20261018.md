# C-line dynamic validation gate review — 2026-10-18

## Decision

**No C-line candidate is admitted to product-level dynamic validation or PoC construction in this review.** Keep both items `candidate/unknown`; do not infer a vulnerability or create a synthetic PoC that would only demonstrate a chosen mechanism. The evidence presently establishes bounded static source observations, not the required combination of a realistic product entry, attacker-controlled path, sensitive operation, trigger, and testable CIA impact.

This is a gate decision, not a claim that the code is safe. No online service was contacted, no untrusted build script was run on the host, and no source/build configuration was changed. No vulnerable/fixed binary was produced, so there is no patch revalidation result.

## Reviewed candidates and exact bindings

1. **TypedArray `Filter` type-origin candidate.** The scanner evidence bundle is `CyberSecurity-Innovation-Audit` commit `76f20af9e372189627f5117ed9a30815d1f49747`; the frozen research implementation is commit `4ea5f4020884aed5860a88d50f5a926610e7b98a`; the replay was run from workspace commit `f8e3a0ad7463f216db4be7502bd8a19eec545908`. Detector `ohscanner.ark.runtime.type_safety` 0.2.0, rule `ark.runtime.typedarray-store-type-origin`, model SHA-256 `1421ec97eb81e0f08910a83d7b72cfdd9d5bcd22aa752105739faf36341c72fe`.
   - Parent: `openharmony/arkcompiler_ets_runtime` commit `830e85b40240677039719fcbf14f721ad3b19050`, tree `579712c1ebbb703d17cea422b1572023bed5d8a4`, file `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`, blob `054451b1be4f39254d56a1683cc9d1c1b5e55018`, SHA-256 `847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422`.
   - Fix: `a0e30483ab3e4aead67ecfb5c708489915e447f9`, tree `82af11ced4297818410ccf61906b703d25b69165`, same path, blob `95f54f2875f401afe3167c62f8c1e7799782be8c`, SHA-256 `8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74`.
   - Bounded replay observed `candidate` on parent and `matched` on fix; safe `Set` control matched and unrelated `Map` had no observation. Parent/fix are both `limited` / `partial`, with `parse_dependency_contamination_unknown`, `production_runner_not_admitted`, and `research_only_partial_function_scope`.

2. **Pending-exception propagation research probe.** Parent `2e2cebedf5a96fb798144c82296b8b55e2eb60c6`, tree `b3489e3b4202da7fe180e8d6c292d544f5973874`, `ecmascript/compiler/slowpath_lowering.cpp`, blob `00003d3b0a5b2863d9c9677c423d96a72f4c6ae6`, SHA-256 `472c9b11722ef5df40bcd6a3e743a5a209bce66b6d3e0f41351da97c6de04a0c`; fix `c80d853d1b3be23ca999618a199183bc854eaa6a`, tree `c57ae1249050c8e2b9f0046ca630f45e08645cf9`, blob `5c290f71cae4220b9f1fc93fd18803a8ee995c98`, SHA-256 `cd4614fa6a4920d7e2ab850ce027d555421d49f40d99c509b0cab980abb342dc`. Regression source blob `5908e384c00382cd0ec1f7ed92c52e39b84c2e40`, SHA-256 `de603593f0f5723f5e0f15ff2735619024bf2ae8248a930418c5720c1aa5620b`. A separate narrow research probe observed `candidate` → `matched`; the official C-line detector has no exception rule and returned `not_analyzed`. Full CFG/dominance and runtime exception-state behavior are not established.

## Evidence gate

| Requirement | TypedArray `Filter` | Exception probe |
|---|---|---|
| Realistic entry | A source-level `Filter` caller is identified; no built runtime or deployed product entry is tied to it. | A compiler lowering path is identified; no product-level caller/runtime path is tied to it. |
| Attacker-controlled path | JavaScript receiver/species behavior is plausible from the API shape, but the replay does not prove a feasible adversarial value sequence reaches the flagged store with a type mismatch. | No attacker-controlled source-to-sensitive-operation chain is established. |
| Sensitive operation | A type-origin difference at a modeled store is an analyzer observation; actual incorrect machine/runtime operation is unproven. | Exception-state ordering is a syntax/model observation; an invalid sensitive effect is unproven. |
| Trigger and impact | No executable trigger, crash, state change, or CIA effect observed. | No executable trigger, crash, state change, or CIA effect observed. |
| Same-config vulnerable/fixed build and revalidation | Not run; no build profile, complete preprocessing/dependency closure, binaries, or runtime comparison. | Not run; same missing product build/runtime evidence. |

The C-line contract itself requires complete AST eligibility, resolved dependency/build-profile evidence, independent positive/fix/safe controls, and an independently labeled holdout before reconsidering production admission. It also requires product inclusion, runtime type behavior, reachable entry, attacker control, feasible generation path, and concrete impact before product vulnerability promotion. Current evidence explicitly records an assumed `NDEBUG=1; ENABLE_ASM_ASSERT=0` profile, no preprocessing/macro expansion, and no product build verification. The typed-array fix replay's `newArray` type read before `HasPendingException` remains `unknown`, not a second confirmed issue.

## Reproduction provenance and limitations

The bounded source replay can be repeated from the scanner repo root with:

```powershell
python research\experiments\ark-runtime-exact-source-20261018\replay_exact_sources.py
```

It checks exact Git blob OIDs, source SHA-256, detector/model implementation hashes, then emits the parent/fix and controls. The replay record is `research/experiments/ark-runtime-exact-source-20261018/reproduction-record.json`; its source manifest is `source-git-bindings.txt`; the file manifest is `hash-manifest.json` with detached digest `hash-manifest.sha256` (`acb2726e2612a38fcbfed535f3a7993cdc56c427eec799de15e7fd31a27c288f`). The recorded environment is Windows 11, Python 3.13.9, tree-sitter 0.26.0 / tree-sitter-c 0.24.2 / tree-sitter-cpp 0.23.4. Parser packages match the frozen run, but Python differs from frozen Python 3.12.0. This is a scanner source-analysis replay, not target runtime execution.

The separate `outputs/ark-runtime-isolated-validation-20261018` package concerns historical `JSArray::SortElementsByObject` / CVE-2025-23420, not these C-line TypedArray/exception candidates. Its recorded GN attempts failed; the latest `build-fixed-rk3568-hihope-gn-retry11.log` also ends in GN errors. It has no vulnerable or fixed runtime binary and must not be cited as dynamic C-line evidence.

## Required evidence before reopening dynamic validation

First establish from exact product source/build manifests and a supported, isolated build environment: complete relevant source/dependency/defines profile; successful vulnerable and fixed target builds; real JS/VM product entry and applicable trust boundary; a concrete input that reaches the sensitive operation; and a safe/unrelated control. Only then build a minimal bounded PoC and observe a repeatable crash or state/CIA change, with logs and binary hashes. If those facts cannot be established, retain `candidate/unknown` and record the specific missing proof.
