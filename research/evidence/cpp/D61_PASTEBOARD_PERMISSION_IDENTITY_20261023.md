# D61 — Bind Pasteboard suppression to read-permission identity

Date: 2026-10-23 (Asia/Shanghai)

## Scope and triggering evidence

D61 is a follow-up to immutable D59 final code commit `da0195610f2203ce97af1f43385f0091f040504e` (0.19.5); no D59 commit was amended. D60 second-layer review `a9105a4f65cddb0b856242dbdbcb4f76a3741ccf` and T59 independent mismatch report `d17f582b0317bddf0c353f77969eaff6c4e80429` both demonstrated that a top-level early denial for Bluetooth/network permission incorrectly suppressed an unconditional Pasteboard read. The prior matcher recognized permission-shaped syntax but did not bind its permission identity to the protected data.

## Change

Detector version 0.19.6 only treats a denial guard as a Pasteboard-read guard when its complete condition includes one of:

- `READ_PASTEBOARD`, `PERMISSION_READ_PASTEBOARD`, or `READ_PASTEBOARD_PERMISSION`;
- `SECURE_PASTE` or `SECURE_PASTE_PERMISSION`;
- the exact source-backed helper names `CheckPastePermission(...)` or `HasPastePermission(...)`.

This identity check is in addition to D59's constraints: a complete recognized denial condition, immediate `return` or `throw`, top-level placement in the checked method, and an entire guard statement before the read or IPC route. A bare `CheckPermission()` and unrelated network/Bluetooth permission checks retain the Pasteboard candidate. The historical corpus's direct fixture uses `CheckPastePermission()` as its source-backed control.

The exact helper identifiers are supported by the D56/T56 lineage packet: `CheckPastePermission` appears in the 2022-08-15 descendant getter gate (`e13a4ad3b72be7650ccb75de560790c04fa84795`), and `HasPastePermission` is a later helper spelling (`cedbaeb9f55f524fb93c9d76ec06a4dc7b213ba7`). Current READ/SECURE names are source-backed in `VerifyPermission` (`721fecac75d9c51b0b145469abc6c9c78c17753e`). This supports recognizing names only; it does not establish helper semantics for any arbitrary source or device build.

## Control matrix

| Source shape before unconditional `GetPasteData` | D61 result |
|---|---|
| `if (!CheckBluetoothPermission(PERMISSION_NETWORK)) return ...;` | candidate retained |
| `if (!VerifyCallingPermission(PERMISSION_NETWORK)) return ...;` | candidate retained |
| `if (!CheckPermission()) return ...;` | candidate retained |
| `if (!VerifyPermission(PERMISSION_READ_PASTEBOARD)) return ...;` | suppressed syntactically |
| `if (VerifyPermission(SECURE_PASTE_PERMISSION) != PERMISSION_GRANTED) return ...;` | suppressed syntactically |
| `if (!CheckPastePermission()) return ...;` | suppressed syntactically |
| `if (!HasPastePermission()) return ...;` | suppressed syntactically |
| D59 ignored-result, mixed-condition, nested/bypassed, dead, post-read and post-serialization controls | candidate retained |

The positive and negative cases are focused synthetic tests. The pinned D52 source still yields its original rule ID, symbol, line-41 `OnRemoteRequest` method-entry anchor, and source hash. Its full component replay remains blocked/partial (D50 records 57 complete and 10 partial parser states). D61 does not alter findings for sibling CVEs by design; the focused known-CVE corpus suite is rerun below.

## Verification

- `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` — PASS, 32 tests.
- Strict duplicate-key JSON parsing — PASS.
- `git diff --check` — PASS.
- T61 independent acceptance is requested against the frozen D61 code commit; no T61 result is claimed in this report until that review completes.

## Limits

This remains a source-local lexical/syntax filter, not a CFG, dominance, caller, macro-expansion, API-contract, or framework authorization proof. Permission identifier matches do not validate token identity or actual grant behavior. Exact `CheckPastePermission` and `HasPastePermission` names are source-backed helper names, but their semantics vary by historical revision and they may encode focus/default-IME or share-option rules rather than the later READ/SECURE grant. The detector does not trace into core getter helpers or prove that the checked function is the one executed. D52 remains a source-only candidate; CVE causality, product applicability, product vulnerability, exploitability, runtime authorization, and device fixed status remain UNKNOWN.
