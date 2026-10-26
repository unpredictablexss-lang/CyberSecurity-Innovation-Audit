# D3 libpng CVE-2026-46675 typedef-gap status (2026-10-19)

## Status: blocked; prototype is not PR-ready

The worktree is `codex/a-memory-d2-20261019`, based at `db77164fdc2af0da02e4d3efc056d84694fd68e8`. The pinned vulnerable source and exact fix are recorded in [d3-libpng-46675-gap.md](d3-libpng-46675-gap.md): vulnerable commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`, fixed commit `aa77ef38c17ab2fc1b41bec09fb973c6a386641d`. Their `pngrutil.c` SHA-256 values are respectively `b328fb05352226866b1e44c8cddd3e03df35413f1f38f4d81ba51afe4f2333a5e` and `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e`. The selected header declares `typedef png_struct * PNG_RESTRICT png_structrp;` (the exact fetched header hash is recorded in the prior gap note).

## Change and evidence

Added header-scoped pointer typedef collection and parameter resolution to `shared_state_lifetime_detector.py`, then connected its candidate output to the existing `CppResourceLifetimeDetector` in `resource_lifetime_detector.py`. Added an unrelated typedef fixture and regression test. This is a bounded lexical prototype; it does not implement type checking, CFG, or interprocedural alias proof.

Raw pinned vulnerable and fixed source units were replayed through the candidate detector with the selected `png.h`. The typedef previously yielded no candidates; resolution now produces candidates in the vulnerable unit, including a candidate at `png_handle_iCCP` (reported source line 1491 in that transport snapshot), but also produces 7 candidates in the fixed source. The vulnerable side produced 8. This does not establish a discriminating vulnerable/fixed result and the candidates must not be counted as a confirmed CVE detection.

An exact upstream CLI replay could not be completed: `git clone https://github.com/pnggroup/libpng.git` failed because this environment could not connect to `github.com:443`. No fabricated local commit was substituted for the pinned upstream identities. Existing real-source CLI evidence remains `completed_with_limitations`, with `ohscanner.cpp.resource_lifetime` blocked and the vulnerable source parse status partial, as documented in `d2-libpng-46675-vulnerable-unknown.md`.

## Verification and disposition

- `python -m unittest tests.detectors.test_cpp_shared_state_lifetime_detector -v`: 7 tests passed.
- `git diff --check`: passed.
- `python scripts/check_change_scope.py --base db77164fdc2af0da02e4d3efc056d84694fd68e8 --lane cpp`: no violations.
- No Catalog, Runner, contract, or known-CVE signature changes were made. The changed detector integration is in A-owned detector code, but this prototype should remain out of a competition PR until it has a useful exact-source differential and adequate false-positive controls.

## Next sustained task

Improve C parsing or trusted syntax-region extraction so typedefs and relevant member state survive partial translation-unit parsing. Then model a generic owner release followed by a later consumer resume, with unrelated decompressor positives and fixed-clear-state, safe, unrelated, and partial controls. The acceptance gate is a repeatable exact pinned vulnerable/fixed CLI replay that flags the vulnerable mechanism while suppressing the fixed source; otherwise preserve `unknown/partial` status and do not claim coverage.
