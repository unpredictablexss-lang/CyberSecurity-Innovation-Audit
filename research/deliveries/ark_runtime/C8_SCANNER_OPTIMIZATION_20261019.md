# C8 Ark Runtime scanner optimization delivery

Date: 2026-10-19 (Asia/Shanghai).

## Scope and source identity

- Worktree: `E:\网安\CyberSecurity-Innovation-Audit-c-line-opt-20261019`
- Branch: `codex/c-line-scanner-optimization-20261019`
- Base commit: `b011ea0cf732e5c07cb9d9fe0ab9ec451e87c5df`
- Detector/model version: `0.7.0`
- Public contracts, Runner and Catalog were not modified.
- The requested `源码漏洞审查记录_20261018.md` was not present in the checkout, local commit trees, parent directory or locally pinned remote objects. Three explicit fetch attempts failed at GitHub HTTPS/443. The implementation therefore uses the recorded C3 review counterexamples, C4 source facts and C7 fail-closed replay evidence as bounded replacement inputs. This delivery does not claim that the missing file was reviewed.

## Scanner changes

1. Type-origin invalidation now drops stale facts after update expressions, nested/sequence assignments, unmodelled transformations and effects. The six recorded `expected=unknown / actual=matched` counterexamples now remain unknown while explicit safe transfers and fresh reads retain only provable origin.
2. Exception-guard analysis now models allocation/potential-throw obligations, `HasPendingException` branch state, guard-before-effect, guard-after-effect, branches/loops, zero-length returns and unknown effects. Missing guards produce local candidates; fixed ordering produces a local mechanism match; unprovable order remains unknown/partial.
3. Partial parser owner recovery no longer invents namespace/class owners from lexical proximity. Owners are accepted only from complete visible AST/source tokens and are source-bound; partial, macro, conditional, cross-TU and ambiguous contexts remain unknown.

## Controls and evidence boundary

- Positive, fixed, safe, unrelated and unknown controls are retained.
- `safe` is only a control role and is not a vulnerability verdict.
- All findings remain `candidate/unassessed`; `validated_vulnerability=0`.
- Local syntax/graph order is not product entry, permission, attacker control, CIA impact, CVE or exploitability evidence.
- Historical parent/fix replay is still blocked by missing pinned Ark Git objects. Eight tests are skipped and are not counted as passes.

## Verification

- Ark Runtime unittest modules: `116 tests`, `8 skipped`, `0 failed`.
- Runner applicability on Windows: `5 tests`, `0 skipped`, `0 failed`.
- WSL runner/owner integration: `19 tests`, `14 skipped`, `0 failed`; owner integration was skipped because optional web dependencies are unavailable.
- Python compilation for Ark Runtime source/tests: passed.
- `git diff --check`: passed.

## Continuous next slices

1. Supply the missing source-audit Markdown and reconcile its findings against this change set.
2. Supply pinned Ark Git stores for the historical parent/fix/safe/unrelated replay.
3. Freeze the 0.7.0 rule semantics, then generate and independently label a new target-rule-applicable holdout.
4. Keep product entry/permission/CIA/build/version/PoC/fix/CVE closure separate and do not upgrade findings until the evidence gate is met.
