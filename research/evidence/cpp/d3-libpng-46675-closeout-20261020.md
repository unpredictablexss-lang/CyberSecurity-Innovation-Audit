# A-D3 libpng CVE-2026-46675 closeout

Date: 2026-10-20 (Asia/Shanghai)

## Baseline and scope

- Worktree branch: `codex/a-line-final-closeout-20261020`.
- Local `origin/main`: `4b0e16576a45a111b4fad7e8f82819a47ed472f5`.
- Scope is limited to the existing D3 typedef/header-aware parsing gap. No Catalog,
  Runner, contract, or detector implementation change was made in this slice.
- The older A-line task tree records the exact-source candidate observation as
  vulnerable/fixed `8/7`. That observation is retained as historical evidence; it is
  not treated as a complete semantic result.

## Fixed source identity

The reproducible local source copies are under
`D:/openHarmonyScanner/tmp/d38-libpng-preprocess-20261020/`:

| side | file | bytes | SHA-256 |
|---|---|---:|---|
| vulnerable | `46675-vuln/pngrutil.c` | 153112 | `b328fb05352226866b1e44c8cddd3e03df35413f1f38f4d81ba51afe4f2333a5e` |
| fixed | `46675-fixed/pngrutil.c` | 152477 | `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e` |

The corresponding upstream identities already recorded in the D3 evidence are
vulnerable commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` and fix commit
`aa77ef38c17ab2fc1b41bec09fb973c6a386641d` (parent
`4eeb825ab26605ed34cd74495d4cce920939fe9f`). The local copies are source-file
artifacts, not a claim that a complete product build was reproduced.

## Reproduction and parser observation

Commands run:

```powershell
Get-FileHash D:\openHarmonyScanner\tmp\d38-libpng-preprocess-20261020\46675-vuln\pngrutil.c -Algorithm SHA256
Get-FileHash D:\openHarmonyScanner\tmp\d38-libpng-preprocess-20261020\46675-fixed\pngrutil.c -Algorithm SHA256
```

The current tree-sitter C parser was also invoked directly against both files using
the repository Python environment. Both roots report `has_error=True` (four top-level
children); adding the adjacent header files does not turn this into a complete
translation-unit parse in the production light-AST profile. The source visibly uses
`png_structrp` in the affected functions and carries state through
`zstream.next_in`, `zstream.avail_in`, `png_inflate_claim`, and the read/decompress
helpers. The fixed side additionally detaches/reset buffers before the next owner.

This is not a safe/fixed inference: the parser status blocks semantic analysis, and
the existing `resource_lifetime` detector only models bounded local allocation,
release, alias, and callback relations. It does not model the required interprocedural
field-state protocol or resolve the typedef-backed pointer facts across the header.

## Disposition

**Blocked / unknown; no production code change.** The historical 8/7 candidate
difference remains useful as a reproduction lead, but it is not an exact vulnerable/fix
semantic differential. A zero result on either partial side must not be called safe.
No synthetic decompression fixture is counted as real CVE coverage.

Minimum unblock condition:

1. A parser/profile that produces complete or explicitly bounded trusted syntax facts
   for `pngrutil.c` plus the defining headers (`png.h`, `pngpriv.h`, zlib declarations),
   including `png_structrp` and nested `zstream` member types; and
2. a general interprocedural state model for owner claim/release, stale input pointer
   and byte-count propagation, followed by vulnerable/fixed/safe/unrelated/partial
   controls on the exact source identities above.

Product-level impact remains not run: no target product build, call-chain proof, attacker
input path, or runtime validation is bound to these component files.

