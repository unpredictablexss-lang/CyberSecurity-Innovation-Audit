# Latest local/GitHub refresh — 2026-10-21

Base: main `4ce0951f9dc61018328c06b6ff9f0a35bafaf417` (PR #54). Merged remote feature `c5a6431f9b422312e7360cb54c57eacf6cb95cb0`, then imported the current Windows progressive-triage-latest working changes without modifying its index or files.

Active integration: frozen multi-endpoint L0/L1 grouping/ranking and policy consent, explicit candidate L2 source preview and operation, fixed-source/provider binding, shared parent-audit budget, cancellation, idempotency, UI entry and result views. Integration fixes initialize the consent manifest before parent validation and use the same scan endpoint for budget dispatch/reservation; regression covers successful parent dispatch, cancellation and changed-plan refusal.

Original checkouts/services are preserved. Existing detectors, performance tools, current main's automatic Agent behavior and earlier merges remain intact. The previous policy_store/progress-callback experiment is an incompatible alternative and is preserved as a patch rather than replacing current implementation. Fourteen scanner-eval reports are historical evidence, not new runs; that worktree's detector fix and test already equal main. Sparse checkout omissions are not deletions to apply. The disconnected `origin/unrelated` CI fixture history has no new product code.

L2 remains individually authorized; automatic bulk L2/L3 dispatch, shared deep-Agent enforcement, real Provider and browser acceptance are not claimed. USD is advisory; candidates are never automatically promoted. Local regression results and publication commit are recorded separately below. GitHub CI must be checked for the final published head.
