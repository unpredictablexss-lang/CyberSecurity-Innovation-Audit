# D2 baseline — 2026-10-17

Actual working HEAD: f11d5fdf4ab01a345a1ffb702b18edb6b5109a38.
GitHub main and merge-base: e510c99c67f31ec6c73365f9ab749c79ca6ff0a1.
PR #17 OPEN/Draft, ahead1/behind0 at this check; no dirty files initially.
Real-time PR metadata and compare API were queried, not inferred from old notes.
D1 is already pushed. Older validation.json push=false is a pre-publication snapshot.

Read current AGENTS, docs/README, architecture, real contracts/runner plus all D
implementation/test/research inputs. Approved scope: only data detector/models,
D tests/fixtures and research/data_sensitive; no public core/frontend/catalog/UI.
Original main's unrelated Operations.tsx fix remains untouched in its own worktree.

P0 bug: branch block() returns False on return but caller discards it and merges
both environments. Also nested block ignores exit and else_clause is not interpreted.
D2 writes failing tests before changes, then introduces explicit fallthrough/exits,
lexical binding restoration, conservative short-circuit/conditional effects.
Risk: no full CFG/alias/product log proof; unsupported code must remain partial.
D2-2 keeps fixed9files/commit/model, audits every AST error and private probe separately.
D2-3 will record verified history or bounded failed search, not invented fixes.
D2-4 will freeze source hash before independent-label planning; no fabricated holdout.

D1 fixture files and expectations are hash-frozen in D2_BASELINE.json. Do not edit
their expectations to hide regressions. New controls get a separate D2 manifest.
Planned D2 evidence: BASELINE, IMPLEMENTATION, COVERAGE, HISTORICAL,
EVALUATION, POC_PLAN and HANDOFF. Existing Draft PR will be updated, not duplicated.
