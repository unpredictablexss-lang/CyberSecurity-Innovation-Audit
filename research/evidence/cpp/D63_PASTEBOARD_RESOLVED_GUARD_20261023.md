# D63: Pasteboard guard source-resolution refinement

## Scope and lineage

D63 is a follow-up to frozen D61 commit `b0ce27a3e3b08f085e46a22468e890ac8808d1c1`; that commit and the D59 frozen commits were not modified. D62 supplied two counterexamples: a same-named `CheckPastePermission` helper that always returns true, and a helper that delegates to `CheckBluetoothPermission(PERMISSION_READ_PASTEBOARD)`. Both could suppress candidate `CVE-2025-27247` even though neither established a Pasteboard read denial. D60/T59 had separately shown that unrelated Bluetooth/network permission names could suppress the candidate.

The detector version is now `0.19.7`. The change is limited to source-local guard resolution for `ohscanner.known_disclosed_cves`, its focused controls, the corresponding fixture bytes/hashes, and this report. The detected CVE identity and sibling CVE identities are unchanged.

## Matcher behavior

A helper call can suppress the Pasteboard candidate only when all of these syntax checks pass:

1. The caller has a complete denial condition and immediate `return` or `throw` exit before the relevant route/read.
2. The caller check is a call to `CheckPastePermission` or `HasPastePermission`.
3. A `bool` definition for that exact helper is present in the same source unit.
4. The helper starts with a top-level direct permission-state comparison indexed by `PERMISSION_READ_PASTEBOARD` or `SECURE_PASTE_PERMISSION` (or the corresponding recognized token spelling), returns `false`/`0` on the denial branch, and then has only `return true;` as its success tail.
5. Existing ordering, top-level, false-branch, dead-wrapper, and post-read controls still apply.

The helper body is checked directly. A token passed to a generic or unrelated function does not qualify. Thus an unconditional-true helper and a helper delegating to `CheckBluetoothPermission(PERMISSION_READ_PASTEBOARD)` retain the candidate. A direct source-shaped helper is included as a narrow positive syntax control.

## Evidence and limits

The focused regression suite passed: `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` (32 tests). The matrix includes both D62 false-suppression shapes, unrelated Bluetooth/network permission checks, source-shaped positive controls for both accepted helper names, and the existing D59/D61 ordering, nested/dead, mixed-condition, post-read, post-serialization, and sibling-CVE controls. The corpus fixture hashes were updated for the two corresponding source changes. `git diff --check` passed.

This remains a source-only candidate detector. Its accepted direct map comparison is a syntax pattern, not a source-backed platform API contract or proof of permission semantics. Same-unit matching does not resolve aliases, map provenance, macros, overload behavior, cross-file contracts, or indirect calls. The matcher is not a complete CFG/dominance analysis; loops, `goto`, exception/catch behavior, and other control-flow constructs can alter reachability. CVE causality, product identity, product inclusion, runtime reachability, and vulnerability status remain unknown. Ambiguous or unresolved guard shapes conservatively retain the candidate.

T63 independent review is pending; this report does not claim acceptance.
