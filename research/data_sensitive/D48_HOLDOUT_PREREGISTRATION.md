# D48 blind source review preregistration

Date: 2026-10-19 (Asia/Shanghai). Status before scan: frozen, not yet run.

## Selection and scope

Select the first C++ component in the G-drive campaign-100 selection order that is not named by the existing D research records and has a local Git object snapshot: OpenHarmony distributed_screen. The campaign README identifies the corpus as an A/B scanner campaign; its C/D execution gate was blocked, so this source has no recorded D scan or D tuning. A text search across research/data_sensitive before the run found no distributed_screen profile or replay. This is a convenience sample from a stratified campaign, not a random sample of the OpenHarmony population and not by itself a formal accuracy holdout.

- Source: /mnt/g/OpenHarmony-GitCode-Mirror/campaign-100-20261017/repos/distributed_screen, read-only mirror.
- Exact commit: 373e2b5241c0e5dcb923642059ae83e4e9a1a64e.
- Exact tree: 431a2a0be0c140846b6ff1cefb0e7adfa19d2088.
- Eligible C/C++ scope: all tracked .c/.cc/.cpp/.h/.hpp paths under that tree, excluding test/tests/unittest/mock/mocks/fuzztest path segments; 97 files. The scanner script computes and records the complete scope-path hash.
- No G-drive checkout, index, refs, or files are modified. Replay reads only the pinned Git objects through a temporary shared-object clone under /tmp.

## Frozen detector and protocol

Freeze repository code at D branch base 5346c40a9487193ecc3d0b84a3f168aa42049e6c before scanning. Detector ohscanner.data.sensitive_exposure is 0.21.0 (SHA-256 62fcbca2b58e2d527e78c9d6827aa114b83bf1c818dfe9993e1c050a9dcb8f46); source model 0.4.0 (SHA-256 174432ffb40a9bbb0aaee65f5a8161da7227dc5a88060a71965261d7f8ae10c2); sink model 0.8.0. Replay driver d19_unreviewed_replay.py SHA-256 is 2667970000267421c9b5751759cfc131ee0d509cdfb826ca62cb016fe60a2e16.

Run the exact pinned scope twice without code/model edits; compare source identity, candidate signature and coverage. Record wall time and peak RSS. Do not tune from this run. Any later detector/model change voids D48 as an accuracy holdout and requires a new frozen source set. The two runs measure stability only.

## Labeling and claim boundary

No labels are available at preregistration. An independent reviewer who did not develop or tune D must assess source excerpts without seeing the detector prediction first and assign supported_risk, protected_safe, unrelated, or unknown with line-bound supporting and contradicting evidence. Until that blind review is complete, report candidate counts only; do not calculate TP/FP/FN/precision/recall. Any zero-candidate scan remains blocked/partial and is not a clean bill of health. D48 cannot establish product inclusion, runtime log configuration, reader authorization, attacker reachability, CIA impact, affected versions, a product PoC, or a fixed-product retest; product vulnerability status remains unchanged.