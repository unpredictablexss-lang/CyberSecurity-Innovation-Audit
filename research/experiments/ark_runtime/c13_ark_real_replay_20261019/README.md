# C13-ARK-REAL-REPLAY minimal slice

Date: 2026-10-19 (Asia/Shanghai)

## Scope

This slice is restricted to `research/experiments/ark_runtime/c13_*` and
`tests/detectors/ark_runtime/test_c13_real_replay.py`. It does not change
shared contracts, Runner, Catalog, or detector source.

## Source identity

The human source-audit input is retained as a pinned OHScanner Git blob:

- commit `4c56210`
- path `research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`
- blob `dbedea677c8dc70c1b0066c7bc52df27bcff06ea`
- bytes `29553`

The first real Ark pair is source-bound in `c13-replay-result.json`:

- repository `openharmony/arkcompiler_ets_runtime`
- parent `2ea501258ab4155826b64f01b499b43d1911e0e2`, tree `579712c1ebbb703d17cea422b1572023bed5d8a4`, target blob `054451b1be4f39254d56a1683cc9d1c1b5e55018`, source SHA-256 `847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422`
- fixed `919e4fbb011f610427e788889083fa8e28d2f951`, tree `82af11ced4297818410ccf61906b703d25b69165`, target blob `95f54f2875f401afe3167c62f8c1e7799782be8c`, source SHA-256 `8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e`

All object checks use `GIT_NO_LAZY_FETCH=1` and fail closed on missing type,
tree, blob, size, or SHA-256 mismatch.

## Result

Five development controls pass: positive `candidate`, fixed/safe `matched`,
unrelated no candidate, and wrong-arity `unknown`. The production `ohscan-run`
reports for the real pair are retained. Both reports are `blocked`/partial
under the current bounded model and contain zero same-root diagnostics. This
is explicitly `blocked_partial_unknown`, not proof that the parent is clean
and not a fixed-side safety claim.

The remaining eight source-audit cases are open obligations in the manifest.
No dynamic build, product binding, attacker entry/permission path, CIA impact,
PoC, fix revalidation, independent truth, or Precision/Recall is claimed.
