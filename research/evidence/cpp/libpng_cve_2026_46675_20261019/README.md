# libpng CVE-2026-46675 / GHSA-qvg3-h654-xq3j investigation

Verification date: 2026-10-19. This is an A-line source and parser-coverage investigation; there is no detector finding or product verdict.

## Root-cause card

- **Disclosure:** upstream libpng GHSA says versions 1.6.0 through 1.6.58 are affected, fixed in 1.6.59 and 1.8.0. The advisory lists CVE-2026-46675. It requires a crafted PNG plus the sequential API order `png_read_info()` then `png_read_end()` without starting row reads. The stale read occurs before libpng errors on the unconsumed IDAT data. zTXt/iTXt can leave `zstream.next_in` pointing into the chunk buffer; iCCP can leave it pointing into local stack arrays. This is an availability crash in the reported heap case; advisory says the dangling pointer is only read and output is discarded, so it does not claim disclosure or data corruption.
- **Attacker control / unknowns:** a caller may receive an attacker-crafted PNG and execute the unusual `png_read_info` → `png_read_end` sequence. Whether any OpenHarmony app accepts such PNG input and takes that sequence is unknown. Known safer APIs/call sequences include reading rows before `png_read_end`, `png_read_png`, simplified `png_image_*`, and progressive `png_process_data`.
- **Flow:** malformed/incomplete zTXt/iTXt/iCCP decompression can exit a zlib chunk path while `zstream.avail_in` remains nonzero. The chunk release sets `zowner = 0` but leaves `next_in`/`avail_in`. Later `png_read_end` before row reading starts skips the IDAT zstream claim; `png_read_IDAT_data` sees nonzero `avail_in`, skips refilling from IDAT, and resumes inflation through the old pointer. A subsequent tEXt/pCAL buffer growth can have freed the chunk buffer; iCCP uses stack-local arrays.
- **Missing invariant in vulnerable source:** every zlib stream release must detach the input/output buffers and zero the associated available-byte counters. The affected chunk-release exits lack that guarantee.
- **Upstream fix:** commit `aa77ef38c17ab2fc1b41bec09fb973c6a386641d` adds `png_inflate_detach_buffers` and invokes it on stream acquisition and all identified release paths, including compressed text, iCCP and IDAT finish. This establishes `next_in == NULL`, `avail_in == 0`, `next_out == NULL`, `avail_out == 0` at detach. The official diff says it cherry-picks `6c7783b151377f591c83955e23da50991ad1a600` from the libpng 1.8 branch. Parent commit: `4eeb825ab26605ed34cd74495d4cce920939fe9f`.
- **Static proof obligations:** track zstream pointer origin and count, the chunk-decompression release path that clears `zowner` but not buffer state, potential buffer free/reallocation or stack lifetime end, later use in `png_read_IDAT_data`, and the `png_read_end`/no-row-read call sequence. `png_inflate_claim` clearing on next acquisition is insufficient when this trigger never claims the IDAT stream. Cross-function state, zlib behavior and app call sequence are not proven by the current lexical resource-lifetime detector.
- **Safe lookalikes:** a dangling-looking stream field is not by itself a UAF; it must have nonzero input count, remain selected by the path, and be dereferenced after storage lifetime ends. Reading rows before `png_read_end`, simplified/progressive APIs, or detaching buffers before release avoid this specific sequence. Unrelated cleanup/reallocation is not this flaw.

## Bound source identities

- OpenHarmony archive: `third_party/libpng/libpng-1.6.55.tar.gz`, SHA-256 `71a2c5b1218f60c4c6d2f1954c7eb20132156cae90bdb90b566c24db002782a6`; `README.OpenSource` declares 1.6.55. `BUILD.gn` runs `install.py` and lists generated `pngrutil.c`; configured product target remains unverified.
- Vulnerable source: official GitHub tag `v1.6.55`, commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`; `pngrutil.c` blob `a4eda54c8cb3d36cf1651dba159067b65030e3aa`; file SHA-256 `b328fb05352226866b1e44c8cddd3e03df35413f1f38f4d81ba51afe4f2333a5e`. GitHub-returned file bytes match the local extracted archive copy.
- Fix parent: full commit `4eeb825ab26605ed34cd74495d4cce920939fe9f`; `pngrutil.c` blob `5513951681f52da994ba72c96af135bfede5393e`; file SHA-256 `f67dbcc82dce533ec0a768184a142216f6ac3d9e68f2a35d5cd90c4667b24d1c`.
- Fix commit: full commit `aa77ef38c17ab2fc1b41bec09fb973c6a386641d`; `pngrutil.c` blob `482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a`; file SHA-256 `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e`.
- Upstream commit tree IDs were not returned by the connected read API and local GitHub network fetch failed; commit, path, blob and file hashes are pinned. Do not invent tree IDs.
- The OpenHarmony `install.py` output snapshot used by the existing A-line runtime work has `pngrutil.c` SHA-256 `871e76294344c9f9671ca5a2c86d45e3631b6087b805568e8f7a15864b3fec2c`. It contains the affected release exits (`zowner = 0` at lines 812/1507/1534/4361 in that generated snapshot) without `png_inflate_detach_buffers`; this is source-level root-cause evidence. Product target selection and final link remain unknown.

## Production baseline and limits

- Current scanner production M2 CLI, detector `ohscanner.cpp.resource_lifetime` 0.1.9, one-file source scope, no CVE input. The four source variants (upstream 1.6.55, upstream fix parent, upstream fix commit, OpenHarmony-generated 1.6.55) were stored byte-for-byte in an isolated synthetic Git snapshot `e283ed5d3a74c0112f092ddb1003c97e0e9a4717` (tree `c78da20c3ffe37b09653eaa3b49c5213745ac4bd`, snapshot SHA-256 `192e4c1ac567f539395a92a383b0f55e22baa49467de510efda1198962064098`). The original official commit/blob/file identities above are separate; the synthetic commit is not presented as upstream.
- All four runs report 0 diagnostics and `blocked`; each selected one-file parse is partial. Detector time is about 0.085 s. These results are not a valid static miss, fixed result, or safe result. Raw parser output has errors spanning lines 18-4684/4689/4716 in the three respective source copies; the production CLI did not establish complete coverage.
- No component ASan reproduction, fixed-build execution, safe PNG sequence control, or same-mechanism variant was run for this advisory. No detector rule was implemented. Product reachability remains unknown.
- Local Git CLI fetch of official commit objects failed once with connection refusal; exact parent/fix/tag files were obtained by the connected GitHub read API and saved under workspace `tmp/libpng-ghsa-qvg3-source-20261019`. Source sync completed before the production CLI scans.

## Replays

From `CyberSecurity-Innovation-Audit`:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-ghsa-qvg3-scan-20261019 --repository pnggroup/libpng --commit e283ed5d3a74c0112f092ddb1003c97e0e9a4717 --include vulnerable-1.6.55/pngrutil.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/libpng_cve_2026_46675_20261019/baseline-upstream-1.6.55.json --md-out research/evidence/cpp/libpng_cve_2026_46675_20261019/baseline-upstream-1.6.55.md
```

Change `--include` and output basename to `parent-fix/pngrutil.c`, `fixed/pngrutil.c`, or `openharmony-generated/pngrutil.c` to replay the other source variants.

## ASan harness attempt (2026-10-19)

- Built the OpenHarmony `install.py` generated 1.6.55 source in two isolated copies with WSL Kali GCC 16.2.0, static libpng, zlib, `-O1 -fsanitize=address -fno-omit-frame-pointer`; both builds and the C harness link completed. The second source contains the five complete hunks from the saved official commit diff plus a strict single-occurrence replacement of the exact sixth-hunk old text from that same official diff. This is a documented transplant, not an official fixed release build.
- First generated trigger was invalid as an exploit input: `png_read_info` warned `zTXt: too short`, then `png_read_end` rejected IDAT parameters. The read-rows trigger and valid-zlib control also completed without ASan reports, but because the malformed trigger never entered the intended decompression state they do not satisfy root-cause validation or count as safe controls. Fixed-transplant runtime cases were not run.
- Preserved initial logs: `asan-vulnerable-trigger-no-rows.log`, `asan-vulnerable-trigger-read-rows.log`, `asan-vulnerable-valid-no-rows.log`; harness and input generator are adjacent. No detector change.
- Next exact operation: correct the zTXt fixture so it passes chunk parsing and zlib rejects only after leaving nonzero `avail_in`; rerun the same six source/sequence cases and inspect ASan's allocation/free/use stack. Completion requires UAF only for vulnerable `png_read_info` → `png_read_end` without row reads, with no-row valid stream and read-rows malformed stream controls clean, and fixed transplant free of the same report. If parser blocks input again, retain that failure and use a verified advisory regression fixture/source.

## Corrected ASan matrix (2026-10-19)

The first fixture attempt above remains preserved as an invalid-input failure. The corrected fixture keeps the invalid zlib window header `F8 00` and adds trailing bytes so the zTXt chunk passes libpng's minimum input check while zlib rejects the window and retains unconsumed input. Current trigger SHA-256 is `a10810e046794cb276b9a9537b75beb8e2be6b6eb5b3f95d2f972e686b16c16a`; valid-zTXt control SHA-256 remains `79ddafc75a9d94f34bdd6b0fdc4981bc1aca8e1a01675383e2e33adb8687d12d`.

| Source build | Input / API order | Result |
|---|---|---|
| OH generated vulnerable 1.6.55 | invalid-window zTXt + long tEXt; `png_read_info` → `png_read_end`, no rows | ASan heap-use-after-free in `png_zlib_inflate` (`pngrutil.c:529`), reached through `png_read_IDAT_data` → `png_read_finish_IDAT` → `png_read_end`. ASan allocation/free trace binds the buffer to `png_handle_zTXt` / `png_read_buffer` and subsequent buffer reallocation. |
| OH generated vulnerable 1.6.55 | same trigger, one row read before end | `png_read_end` completed; no ASan report. |
| official-fix transplant | same trigger, no row read | no ASan report; libpng later rejects remaining IDAT data. |
| official-fix transplant | same trigger, one row read | `png_read_end` completed; no ASan report. |
| vulnerable and transplant | valid compressed zTXt control, no row read | no ASan report; both later reject the deliberately minimal image's IDAT sequencing. This is a memory-safety control, not a valid-image success test. |

Builds use the same isolated WSL Kali GCC 16.2.0 static ASan profile. Vulnerable `pngrutil.c` remains hash `871e76294344c9f9671ca5a2c86d45e3631b6087b805568e8f7a15864b3fec2c`; transplant `pngrutil.c` hash `afa5dc2d53578862022142678cff69d7f893153ba26379ca51351d72ad96fc7c`. The transplant applies the five complete hunks from the saved official commit diff and the sixth official replacement after a strict unique-preimage check; the connector diff was truncated at the final hunk, so the transplant is not asserted to be byte-identical to upstream fixed source. Raw retry logs preserve all six matrix results.

This establishes the component heap-UAF mechanism on the OH install-generated 1.6.55 source and confirms that this repair invariant suppresses it in the transplant. It does not establish a product caller, attack reachability, or product vulnerability. The production static detector remains blocked because this real source parses partially; no detection rule has been implemented. Exact next action: inspect the A-line detector's existing interprocedural/state model and parser-boundary request, then produce a minimal parser-complete reproducer scope for the zstream ownership path; if production coverage cannot be made complete without a shared parser change, file/advance that explicit integration request and evaluate the next candidate family with complete production parse.
