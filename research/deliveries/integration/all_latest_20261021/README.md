# Latest main integration inventory (2026-10-21)

Baseline main: `4f75a65775b202b8220a208ebdb50fdb5c8dbb4d`.

The inventory records local repositories, branch tips and immutable dirty-file snapshots without changing the owners worktrees. Local patches preserve overlapping and superseded variants; they are source history, not an instruction to apply all old patches over current main. Original source, databases, credentials, environments and generated caches are excluded.

Active integrations include advanced PR38/44 workflows, source catalog/import, product-bound case validation, latest C++ bounds/resource controls, Ark Runtime C10-C12 rules, and policy settings/grouping/ranking/ledger/quick-screen primitives. Progressive policy is not scheduled by the Worker and is not a billing hard cap. Candidate and unknown evidence remain separate from confirmed product vulnerabilities.

See local_snapshots.json, branch_inventory.json and evidence_imports.json for per-file provenance.

## Main advanced during integration

PR #51 advanced main to `efa5b162f3e61ccdb982f6a88f9822d3e310b62a`. Its coherent C13 model, bounded Agent budgets, performance tools and evidence were retained. PR #52 adds the reviewed A-line and platform/report/policy deltas. The earlier C12 adapter comparison is preserved as `alternate-c12-adapter-vs-c13.patch`, not installed over the newer C13 model. Shared imported evidence keeps the newer main bytes; evidence_imports.json records any alternate original digest.
