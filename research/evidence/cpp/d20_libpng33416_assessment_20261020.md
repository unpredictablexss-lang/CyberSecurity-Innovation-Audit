# D20 libpng CVE-2026-33416 root assessment

Date: 2026-10-20 (Asia/Shanghai)  
Baseline: `b276ca10fcae03e7e9b5ab7e7ceabcd883d42b4e`  
Detector: `ohscanner.cpp.resource_lifetime` `0.4.2`  
Disposition: **no detector change; case remains PARTIAL/BLOCK**.

## Source identity and replay

The D12 hash-bound source identities were reused without modifying their bytes. Vulnerable source is libpng commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`, tree `e01f5780f93eaa6d74cca003bb39b427c8f1e910`; fixed source is commit `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33`, tree `a28bb962645843af84063c77f574f6d88da79f76`. SHA-256 identities, extracted fragment hashes, parser issues, locations, detector result and runtime are in [the JSON replay](d20_libpng33416_replay_20261020.json).

| Variant | Source function | Source SHA-256 | Lines | TU / slice parse | Findings |
|---|---|---|---:|---|---:|
| vulnerable | `png_set_PLTE` (`pngset.c`) | `9bd59a79669db37b2ecc481439481eb5f49bf77bee0de4b1aba649915609b3d0` | 740–802 | partial / partial | 0 |
| vulnerable | `png_set_tRNS` (`pngset.c`) | same file hash | 1145–1212 | partial / partial | 0 |
| vulnerable | `png_free_data` (`png.c`) | `0d8e45e9039cf04088764a09dcda7b24695f199288a44e11dba54ebfaca1c730` | 482–683 | partial / partial | 0 |
| vulnerable | `png_do_expand_palette` (`pngrtran.c`) | `4df05c2e5db00911817d7f125c862524205895f34a65106e016d351f7e6edb53` | 4328–4497 | partial / partial | 0 |
| fixed | `png_set_PLTE` (`pngset.c`) | `d3a203e40b6a6000a7cb78a61e0fd9664b0c39a65d82260efedb0f0184a8bc19` | 741–813 | partial / partial | 0 |
| fixed | `png_set_tRNS` (`pngset.c`) | same file hash | 1156–1235 | partial / partial | 0 |
| fixed | `png_free_data` (`png.c`) | `29a37cedb5be5597aafa3cab62a223c0accbd6016edfff97386471a6e118100c` | 482–683 | partial / partial | 0 |
| fixed | `png_do_expand_palette` (`pngrtran.c`) | `6b724ff0047cced71884176296aac10a6fc1d2592477034bbd622222ded3373f` | 4352–4521 | partial / partial | 0 |

The source-visible relation to investigate is `png_set_PLTE` assigning the same allocation to `png_ptr->palette` and `info_ptr->palette` (vulnerable lines 791–792), `png_free_data` freeing and nulling the info-owned palette (lines 654–658), and `png_do_expand_palette` receiving palette and transparency pointers (function lines 4328 onward; caller at `pngrtran.c:4906`). `png_free_data` also releases `info_ptr->trans_alpha` at lines 519–523. This is a cross-function, cross-file field-alias and lifetime relation, not a local variable alias chain. The source shows a plausible state-flow to model, but the current parser output does not expose a complete typed field/call relation suitable for a reliable rule contract.

## Why no narrow rule is supported

The D12 extraction retained original source positions but all eight target slices and all four parent translation units were partial. For example, the `png_set_PLTE` slice has parse errors at lines 740, 770 and 772; `png_set_tRNS` has a parse error at 1145/1156; `png_free_data` at 482; and `png_do_expand_palette` has missing/error issues around its conditional-compilation ranges. The replay under 0.4.2 reproduces zero findings on both variants, but this is inconclusive.

`resource_lifetime` models allocation/release/use events for local names within a function and lexical flow segments. On partial source it retains only a bounded recursive-compare heuristic; it does not join state across functions or files. Supplying hand-copied declarations or stitching multiple functions into synthetic units would not repair the original parser coverage, and would not prove `png_struct`/`png_info` member identity, conditional build semantics, call order, or runtime reachability. Adding a generic field-name or `png_free_data` heuristic would exceed the evidence and risk reporting unrelated cleanup patterns. Therefore the missing capability is a cross-file typed ownership/call model (and adequate parse context), not a demonstrated narrow rule defect.

No detector, tests, or fixtures were changed. No safe/unrelated fixture was fabricated as though it were a source-bound control. The existing dedicated detector suite remains the relevant rule-control suite; it does not close the libpng case. The fixed source is exact and hash-bound, but its partial coverage cannot support a fixed differential PASS.

## Commands

```powershell
python research/evidence/cpp/d20_libpng33416_replay_20261020.py
python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v
python -m unittest discover -s tests/detectors -p "test_cpp_*.py" -v
python -m scripts.check_change_scope --base b276ca10fcae03e7e9b5ab7e7ceabcd883d42b4e --lane cpp
git diff --check
```

Root cause candidate status is **not established**; source relation assessment is partial; parser coverage is partial; fixed comparison is **BLOCK** for acceptance purposes. The next useful step requires parser-visible declarations/type identity and call-order context or an explicitly reviewed slice contract from the parser owner. Product build and application reachability evidence are also outside this static replay.
