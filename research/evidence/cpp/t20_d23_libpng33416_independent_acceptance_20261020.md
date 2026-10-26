# T20 independent acceptance: D23 / D20 libpng 33416

Date: 2026-10-20 (Asia/Shanghai)  
Independent checkout: `a-t17-d20-d21-20261020`, branch `codex/a-t17-independent-d20-d21-20261020`  
Scope: evidence only; detector, tests, fixtures, and the 345-row queue were not edited.

## Model regression and no-change decision

I independently reran `python research/evidence/cpp/d20_libpng33416_replay_20261020.py` with `ohscanner.cpp.resource_lifetime` 0.4.2. It verified the full-file SHA-256 values before parsing. All four selected functions on each exact source variant matched the D20 records and replayed as `partial` slices, with their parent translation units also `partial`; all eight detector executions were `blocked` and emitted zero findings. Vulnerable commit/tree are `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` / `e01f5780f93eaa6d74cca003bb39b427c8f1e910`; fixed commit/tree are `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33` / `a28bb962645843af84063c77f574f6d88da79f76`.

The parser node inspection on those same hash-matched bytes found:

| Variant | Function | Original file lines | Exact error node(s) |
|---|---|---:|---|
| vulnerable | `png_set_PLTE` | `pngset.c:740-802` | `ERROR` over `PNGAPI` at line 740, columns 6-12; `ERROR` over the literal `#        ifdef PNG_MNG_FEATURES_SUPPORTED` line 770 and `#        endif` line 772 |
| vulnerable | `png_set_tRNS` | `pngset.c:1145-1212` | `ERROR` over `PNGAPI` at line 1145, columns 6-12 |
| vulnerable | `png_free_data` | `png.c:482-683` | `ERROR` over `PNGAPI` at line 482, columns 6-12 |
| vulnerable | `png_do_expand_palette` | `pngrtran.c:4328-4497` | zero-width missing `;` nodes at `PNG_UNUSED(png_ptr)` lines 4447 and 4477 (column 35) |
| fixed | `png_set_PLTE` | `pngset.c:741-813` | `ERROR` over `PNGAPI` at line 741, columns 6-12; `ERROR` over the literal `#        ifdef PNG_MNG_FEATURES_SUPPORTED` line 771 and `#        endif` line 773 |
| fixed | `png_set_tRNS` | `pngset.c:1156-1235` | `ERROR` over `PNGAPI` at line 1156, columns 6-12 |
| fixed | `png_free_data` | `png.c:482-683` | `ERROR` over `PNGAPI` at line 482, columns 6-12 |
| fixed | `png_do_expand_palette` | `pngrtran.c:4352-4521` | zero-width missing `;` nodes at `PNG_UNUSED(png_ptr)` lines 4471 and 4501 (column 35) |

The extraction keeps the original line numbers by leaving newline placeholders outside the function, and retains the original columns on selected lines. It does **not** preserve absolute byte offsets: omitted lines become one newline each, so later byte positions shift. No macro substitution, directive deletion, equal-length rewrite, or declaration stitching was performed in the replay. A hand-assembled/preprocessed input could be useful as a syntax experiment, but it would be synthetic context and cannot upgrade the hash-bound raw-source coverage or establish build semantics.

The `PNG_UNUSED` dependency is concrete: the source snapshot's `pngpriv.h:472-480` defines it as `(void)param;`, including the semicolon, while the two invocation lines omit a semicolon. A parser that sees the unexpanded macro therefore reports missing `;` nodes. `PNGAPI` is configured through `pngconf.h` (fallback at lines 247-248 to `PNGCAPI`; platform/build overrides are conditional), which is why the isolated raw function fragments cannot establish the active calling-convention expansion. `PNG_MNG_FEATURES_SUPPORTED` is enabled in the checked-in generated `pnglibconf.h` for the vulnerable snapshot; its active target build and include/config selection still need confirmation for both pinned trees. The directives inside the conditional expression are legal preprocessor input but are not evaluated by this raw C parse.

The evidence supports **no detector/model change**. The two zero-finding runs are a parser-coverage regression result only; they do not show safe behavior or a fixed pass. The rule still lacks interprocedural typed member alias and release/use ordering.

## CVE case status and minimum unblock package

**CVE-2026-33416 remains PARTIAL/BLOCK.** Source inspection confirms a plausible vulnerable/fixed differential: vulnerable `png_set_PLTE` aliases `info_ptr->palette = png_ptr->palette` (`pngset.c:798`), and vulnerable `png_set_tRNS` aliases `png_ptr->trans_alpha = info_ptr->trans_alpha` (`pngset.c:1178`). `png_free_data` releases and nulls the info-owned palette (`png.c:653-660`) and transparency (`png.c:517-525`) fields. The row transform reads `png_ptr->palette` and `png_ptr->trans_alpha` in `pngrtran.c:4906-4907`, through `png_do_expand_palette`. The fixed `png_set_PLTE` and `png_set_tRNS` versions allocate independent `png_struct` and `png_info` buffers and copy the data. This makes the root-cause candidate source-supported, but D20's four corresponding slices remain parser-partial and the replay cannot demonstrate the candidate or a fixed differential through the detector.

Minimum inputs for a parser-owner-reviewed replay, bound independently for both source trees:

1. The actual compile/preprocess configuration and include order selecting `pngconf.h`, `pngpriv.h`, and generated `pnglibconf.h`; expansions for `PNGAPI`/`PNGCAPI`, `PNG_UNUSED`, and `PNG_MNG_FEATURES_SUPPORTED`; and the feature macros that include the `png_info`/`png_struct` fields and `png_free_data` release branches.
2. Exact declarations with hashes and line spans: `png_info` fields `png_colorp palette` and `png_bytep trans_alpha` in `pnginfo.h:38,141`; `png_struct` fields of the same types in `pngstruct.h:223,306`; relevant `num_palette`, `num_trans`, and ownership/validity fields (`free_me`, `valid`). Include the typedef chain for `png_colorp`, `png_bytep`, `png_structrp`, and `png_inforp` so member identity is typed, not inferred by spelling.
3. Source-bound order/call context from the PLTE and tRNS chunk handling setters into `png_free_data`, then through `png_read_update_info` / transformation setup to row decoding and the `png_do_expand_palette` call at `pngrtran.c:4906-4907`. Record paths where cleanup can occur while the `png_struct` copy remains live, and distinguish the fixed independent-allocation path.
4. A replay contract with exact vulnerable and fixed inputs plus source-bound safe and unrelated ownership controls, preserving a mapping from parser nodes to original file positions. Label syntax coverage separately from whole-TU coverage and product build/reachability evidence.

Current disposition: **root cause plausible from source; detector candidate not demonstrated; fixed differential BLOCK; full case PARTIAL/BLOCK**. No finding count of zero on partial inputs is a safety conclusion. The 345 queue rows and their status pairs remain untouched; queue integrity was checked with the existing verifiers.

## Commands and results

- `python research/evidence/cpp/d20_libpng33416_replay_20261020.py` — completed; all eight expected source hashes matched, 4 vulnerable + 4 fixed slices `partial`, parent TUs `partial`, each run `blocked`, 0 findings. The generated replay JSON was restored to its committed baseline afterward so nondeterministic timing did not alter D20 evidence.
- Inline Python inspection using `parse_source`, `fragment`, and the same C tree-sitter parser — verified each listed error/missing node and exact node text/position on the hash-matched source bytes.
- `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py` — overall OK; 345 unique IDs, original status counts preserved (`not_reproduced=9`, `not_testable=336`), 97 source-hash manifest entries and 4,364,747 bytes verified.
- `python research/evidence/cpp/t13_first_batch/verify_t13_queue.py` — overall OK; all 345 IDs/status pairs and selected source objects reconciled.
- `python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp` — 0 violations.
- `git diff --check` — clean.

Machine-readable case, slice, parser-node, macro, and queue evidence is in [`t20_d23_libpng33416_independent_acceptance_20261020.json`](t20_d23_libpng33416_independent_acceptance_20261020.json).
