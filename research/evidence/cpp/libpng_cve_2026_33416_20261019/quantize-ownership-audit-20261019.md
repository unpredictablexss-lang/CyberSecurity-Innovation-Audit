# CVE-2026-33416 quantize ownership audit (2026-10-19)

## Root-cause card addendum

- The disclosed vulnerable flows are `png_set_tRNS` / `png_set_PLTE` storing one allocation in both `png_struct` and `png_info`, followed by one owner releasing it and the other later reading it. The attacker-controlled condition is an image/configuration sequence that activates these setters and a post-release transform; product entry and trigger sequence remain unknown.
- `png_set_quantize` is a distinct alias: vulnerable 1.6.55 assigns the caller-provided `palette` directly to `png_ptr->palette` when that field is null. In the same vulnerable source, `png_read_destroy` frees this pointer only when `free_me & PNG_FREE_PLTE` is set. The 1.6.56 fix copies the palette into a new allocation, because the fixed destructor frees `png_ptr->palette` unconditionally.
- Therefore the quantize alias is a patch safety obligation for the destructor invariant, not evidence that 1.6.55 has the disclosed UAF. Do not promote this path to a positive CVE finding without separately proving a vulnerable release/use path.
- The rule must distinguish duplicated ownership between independently destructible state from a borrowed caller pointer, and must preserve unknown when ownership flags/path relationships are not modeled.

## Source observations

Vulnerable 1.6.55 `pngrtran.c` around `png_set_quantize`: `png_ptr->palette = palette`; `pngread.c` `png_read_destroy`: conditional free guarded by `PNG_FREE_PLTE`.
Fixed 1.6.56: quantize allocates/copies the palette; `png_read_destroy` unconditionally frees it with a source comment stating independent ownership.

## Verification status

No quantize runtime harness or production scan was run in this audit. Existing targeted lifetime tests passed 2/2; existing pinned tRNS/PLTE ASan and production CLI evidence remains as recorded in `README.md` and the coverage ledger. This addendum is source inspection only and does not change detector code or integration status.
