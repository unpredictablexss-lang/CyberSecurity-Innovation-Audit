# T61 — Independent D61 permission-identity acceptance

Date: 2026-10-23 (Asia/Shanghai)

## Frozen target and source identities

T61 reviewed D61 commit `b0ce27a3e3b08f085e46a22468e890ac8808d1c1`, detector version 0.19.6, in a detached independent worktree. The D52 stub was read as raw Git object bytes from `openharmony/miscservices_pasteboard` commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`: blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, 6,288 bytes, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`. Its parse status is partial.

## Independent permission-identity and ordering matrix

Every case was evaluated in memory using the existing mapped/routed Pasteboard signature. These results are local syntax behavior only.

| Guard before/around read | D61 result | Interpretation |
|---|---|---|
| `VerifyPermission(PERMISSION_READ_PASTEBOARD)` with denial return before read | D52 suppressed | Recognized read-permission token, syntactic suppression only |
| `VerifyPermission(SECURE_PASTE_PERMISSION) != PERMISSION_GRANTED` with return before read | D52 suppressed | Recognized secure-paste token, syntactic suppression only |
| Generic `CheckPermission(READ_PASTEBOARD_PERMISSION)` with return before read | D52 suppressed | Permission identity token appears in condition |
| `CheckBluetoothPermission(PERMISSION_NETWORK)` with return before read | D52 candidate retained | Unrelated permission does not suppress |
| Bare `CheckPermission()` with return before read | D52 candidate retained | Generic helper name alone does not suppress |
| `CheckPermission(PERMISSION_NETWORK)` with return before read | D52 candidate retained | Unrelated permission token does not suppress |
| `VerifyCallingPermission(PERMISSION_NETWORK)` with return before read | D52 candidate retained | Unrelated permission token does not suppress |
| Bare `VerifyPermission(PERMISSION_READ_PASTEBOARD);` before read, result ignored | D52 candidate retained | Token alone is insufficient |
| Read-permission denial after `GetPasteData` | D52 candidate retained | Ordering control |
| Read-permission denial after `WriteParcelable` | D52 candidate retained | Post-disclosure control |
| Read-permission denial under literal `if (false)` | D52 candidate retained | Dead-branch control |
| Read-permission denial nested under `if (is_privileged)` | D52 candidate retained | Conditional outer path can bypass check |
| Mixed denial condition with `&& caller_is_special` | D52 candidate retained | Ambiguous condition does not suppress |

The separate D51 observer candidate `CVE-2025-25212` remained in the synthetic outputs. The exact input strings and output symbols are in the companion JSON.

## Source-backed helper controls

T61 fetched the helper source directly from the official source mirror and used each actual helper body in an in-memory syntax control:

- `CheckPastePermission` at source commit `e13a4ad3b72be7650ccb75de560790c04fa84795`, file SHA-256 `84d41db5fcb90b7766e011c6bfe5c8f932e3404a7994ea61116e28186ec9b96f`, helper-body SHA-256 `675ceb0432b9a8c7fa9b38a539572c1d3652545c74ab31d5cfb2c0036a4a3307`.
- `HasPastePermission` at source commit `cedbaeb9f55f524fb93c9d76ec06a4dc7b213ba7`, file SHA-256 `9c46a4c6eeb3752a38660d84b3bbf87bb535b19f2d462dca8d24e745e1024d6a`, helper-body SHA-256 `0b6797098121f1e62f30865432233b602de1b9659d157ee9154e637abd9b400d`.

Both exact names suppress the synthetic D52 candidate. The inspected old helper bodies implement focus/default-IME and `ShareOption`/app identity checks. That source-backed naming does not prove a generic `READ_PASTEBOARD` grant or establish that the stub invokes these helpers across the real core/stub boundary. The controls combine the helper implementation and stub call in one in-memory unit; they are not an integrated build replay.

## Independent regression and scope checks

- `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` — **PASS, 32/32**.
- Replayed the exact 67 C/C++ units and saved D50 parser states against c8 0.19.3 and D61 0.19.6 using raw source Git blobs. Both scans are `blocked`, with identical D51 and D52 findings, anchors, and source hashes. Parser states remain 57 complete / 10 partial.
- `git diff --check c8..D61` — **PASS**. The diff is limited to the known-CVE detector, focused tests/corpus controls, the corresponding two fixture bindings, and D59/D61 evidence packets. No unrelated detector implementation changed.
- Strict duplicate-key JSON parsing of the D61 packet — **PASS**.

## Four acceptance dimensions

- **fix-correctness:** **PASS** for the tested source-local identity/order matrix. This is a syntax filter, not proof of permission identity or function semantics.
- **candidate-retention:** **PASS**. The exact pinned D52 candidate and D51 sibling candidate are retained; unrelated permission checks also retain D52.
- **coverage:** **PARTIAL**. The exact 67-unit replay remains blocked, with 10 partial parser states. Product/framework coverage is not established.
- **scope:** **PASS** for frozen D61. No unrelated detector implementation changed.

D52 remains a pinned-source candidate. CVE causality, product applicability, product vulnerability, runtime authorization, and device fixed status remain unknown.
