# Independent holdout freeze assessment, 2026-10-17

## Conclusion

The current local historical corpus cannot provide a clean independent holdout after this development pass.

- CVE-2025-23420 was used to add and tune `ohscanner.cpp.bounds` direct element-access coverage.
- CVE-2025-0587 was used to add and tune `ohscanner.cpp.integer_bounds` narrowing-index coverage.
- c_utils shared_ptr and dsoftbus null samples were already used to exercise existing A detectors.
- The kernel race and user/kernel boundary cases are not applicable to the current lexical A rules.

Therefore none of these samples can honestly be relabelled as untouched independent evaluation data. Computing Precision/Recall on them now would leak development/tuning information and violate the taskbook holdout rule.

## Required next corpus

A future independent holdout must be frozen before detector tuning and contain root-cause-separated pairs:

- official/public fix or advisory reference;
- vulnerable and fixed repository/commit/tree/blob/source hashes;
- actual entry, attacker control and trigger;
- CWE and any CVE assignment;
- vulnerable/fixed/safe/unrelated controls;
- product build/runtime permission limitations;
- license/provenance.

At least several independent root causes per supported family are needed before root-cause TP/FP/FN, Precision, Recall, F1 and unable-to-analyze counts are auditable.

## Current permitted reporting

- Historical capability replay: allowed.
- Root-cause hit/miss/unknown/not-applicable: allowed.
- Product/global Precision/Recall/F1: not eligible.
- Zero FP/FN claims: prohibited.

This file freezes the methodological decision so later metrics cannot silently reuse tuning samples.
