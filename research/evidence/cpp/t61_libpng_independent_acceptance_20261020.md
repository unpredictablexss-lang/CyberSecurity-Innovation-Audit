# T61 independent acceptance: libpng CVE-2026-33416 and CVE-2026-46675

Date: 2026-10-20
Baseline: `dac497e85b55baf9279368469047fc142b325ea6`
Detector: `ohscanner.cpp.resource_lifetime` `0.4.2`
Disposition: **both cases remain PARTIAL/BLOCK**.

## Source identities and controls

T61 independently checked the Git commit headers, commit trees, file tree entries, source hashes, and lengths for both vulnerable and fixed sources. Full per-file identities and CLI artifact digests are in [machine audit](t61_libpng_independent_acceptance_20261020.json); rerun checks are in [verifier](verify_t61_libpng_acceptance_20261020.py).

| Case | Vulnerable | Fixed | Fixed parent |
| --- | --- | --- | --- |
| CVE-2026-33416 | Upstream libpng `c3e3049`, tree `e01f578`; four exact source blobs | Upstream 1.6.56 release `d5515b5`, tree `a28bb96`; four exact source blobs | Commit header names `5f9a0b1`, but its Git object is absent from the local shallow mirror. Parent ancestry metadata only; not a separately replayed control. |
| CVE-2026-46675 | Upstream `c3e3049`, tree `e01f578`; `pngrutil.c` blob `a4eda54` | Upstream fix `aa77ef3`, tree `4c64b5f`; `pngrutil.c` blob `482f0ae` | `4eeb825`, tree `8c79809`; parent object and its `pngrutil.c` blob/hash are present and verified. This is pre-fix ancestry, not a safe control. |

The four-file OH/M2 runs for 33416 are extracted replay scopes over exact source files. They are not separate upstream trees or synthetic vulnerable/fixed controls. Existing generic detector fixtures are not source-bound safe/unrelated controls for either CVE. No such controls were found in the reviewed evidence.

## Current scanner outcomes

The production `light-ast` CLI JSONs were independently read and hash-checked. Current detector version is `0.4.2`.

| Case/variant | Scope | Parse | Detector | Findings |
| --- | --- | --- | --- | ---: |
| 33416 vulnerable | 4 files / 507,943 bytes | 4 partial | blocked | 0 |
| 33416 fixed | 4 files / 510,143 bytes | 4 partial | blocked | 0 |
| 46675 vulnerable | `pngrutil.c` / 153,112 bytes | 1 partial, 72 issues | blocked | 0 |
| 46675 fixed | `pngrutil.c` / 152,477 bytes | 1 partial, 72 issues | blocked | 0 |

The independent direct replay on the same exact bytes reproduced the 46675 full-file partial/zero result. For 33416, all four target translation units and all four extracted function fragments on each side remain partial and yield zero findings. Fragment selection does not turn partial translation units into complete source coverage.

## Acceptance decision

- **CVE-2026-33416 — PARTIAL/BLOCK.** The vulnerable and exact 1.6.56 release source objects are hash-bound. The scanner has no root candidate on the vulnerable side, and all four files are partial on both sides. The zero/zero replay is not a demonstrated positive/fixed differential. The fixed commit parent object is missing from the available shallow mirror; do not treat it as an additional control.
- **CVE-2026-46675 — PARTIAL/BLOCK.** Vulnerable and exact upstream fix objects are bound; the fix parent is also bound as an object. Both full-file runs are blocked by 72 parse issues, so zero/zero does not establish a fixed differential. Cross-function stale `zstream` state remains outside the validated candidate evidence.
- **Safe/unrelated controls — BLOCK.** There is no case-specific source-bound control pair in this evidence set. A fixed source with incomplete analysis and generic unit fixtures do not satisfy that gate.
- **A0 queue.** T61 did not edit A0 IDs or statuses. The committed T23 queue verification record still reports 345 unique IDs and original/queue status counts; T61 relies on that recorded baseline rather than claiming to have rerun the original external queue verifier.

Reproduce the evidence checks with:

```powershell
python research/evidence/cpp/verify_t61_libpng_acceptance_20261020.py
```
