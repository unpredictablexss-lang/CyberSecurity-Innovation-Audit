# T55 independent delta acceptance: Batch B advisory revision

- Review date: 2026-10-21 (Asia/Shanghai)
- Independent review checkout: `D:/openHarmonyScanner/worktrees/t51-pasteboard-independent-20261020`
- Reviewed Batch B commit: `58343c4e6cc59aac0e2e5d61400cff23319756b1`
- Previous Batch B commit: `55ba5fc0220d9f72443010fd0ad38270d2f22539`
- Scope: read-only byte/hash, headers, JSON schema/state, CVE identity, and evidence-boundary review. No developer files changed.

## Decision

**Batch B integrity: PASS for the captured artifacts and status separation. Batch B advisory evidence: PARTIAL. D55 known-CVE package remains NOT READY; M2 remains NOT MET.**

The prior blocked response-header path fields now resolve to tracked basenames. CVE-2026-33636 has an independently captured 3,207-byte MITRE CVE Services CNA record with matching body/header hashes and HTTP 200. Its separate GitHub GHSA page still has no raw response body and remains blocked. CVE-2026-46675's MITRE lookup is a captured HTTP 404 `CVE_RECORD_DNE` error response; it is explicitly separate from the blocked GHSA-page capture and is not represented as an advisory.

## Checks

- Batch JSON passed strict `object_pairs_hook` duplicate-key rejection; it contains exactly 8 distinct CVE IDs.
- Recomputed raw Git blob SHA-256 and byte length for all six ordinary captured advisory bodies and headers: **6/6 match**.
- Recomputed both blocked GitHub header files: actual tracked names are `CVE-2026-33636.headers` and `CVE-2026-46675.headers`; each is zero bytes with the expected empty-byte SHA-256. Both GHSA body path/hash fields remain null and capture status is blocked.
- Recomputed the supplemental CVE-2026-33636 CNA body: 3,207 bytes, SHA-256 `6d68fea804893b01cf88c685d260962fe592e78425007565afd47809ae457f4e`; header file: 1,015 bytes, SHA-256 `a02c3fe623263540c198c579749677b5058962c689e1c55d3a4936d39a0a645b`. Header status/content type are 200 and `application/json; charset=utf-8`. Parsed body identifies `CVE-2026-33636`, assigner `GitHub_M`.
- Recomputed the supplemental CVE-2026-46675 MITRE lookup error body: 84 bytes, SHA-256 `ff0793bc04d228fac6b8634ea8a29ce08d68067d615654d72b11955d01433b66`; header file: 1,019 bytes, SHA-256 `bf25c73df5a41722ee30442a532990acada84f82e86446777343d2cd9ebd2a48`. Header status/content type are 404 and `application/json; charset=utf-8`; body says `CVE_RECORD_DNE`.
- For all six ordinary captured entries, parsed response headers agree with manifest HTTP status and content type. Each supplemental response's header status agrees with its manifest entry.
- `*.body -text -diff` and `*.headers -text -diff` are present in `.gitattributes` to preserve raw bytes.
- `git diff --check 55ba5fc0220d9f72443010fd0ad38270d2f22539 58343c4e6cc59aac0e2e5d61400cff23319756b1` returned exit 0.

## Per-CVE boundary

| CVE | Batch B evidence state | Independent result |
|---|---|---|
| CVE-2026-33636 | GHSA page **blocked**; MITRE CNA record **captured** | CNA raw JSON is a separate primary CVE record and its hash/headers verify. It does not replace the unavailable GHSA page snapshot. The CNA body identifies vendor `pnggroup`, product `libpng`, affected range `>=1.6.36` and `<1.6.56`, and the ARM/AArch64 Neon condition. |
| CVE-2026-46675 | GHSA page **blocked**; MITRE lookup **404 error** | The 84-byte `CVE_RECORD_DNE` response is preserved as a lookup result only. It does not establish that no GHSA advisory exists, and is not advisory content. |
| CVE-2026-67215 | captured, unreviewed GHSA | The official GHSA response bytes are intact; original CNA/vendor and fixed version remain unknown, with no structured affected/fixed range. |
| CVE-2026-67216 | captured, unreviewed GHSA | Same boundary as CVE-2026-67215; do not infer vendor-confirmed scope or a fix. |
| CVE-2026-92391 | captured curl project advisory | Body/header identities and response status/content type match. |
| CVE-2026-9079 | captured curl project advisory | Identity matches; preserve the unusual introduced/fixed 8.21.0 event without interpretation. |
| CVE-2026-92392 | captured curl project advisory | Body/header identities and response status/content type match. |
| CVE-2026-58313 | captured OpenHarmony bulletin | Body/header identities match; bulletin's exact fixed revision/version remains unknown. |

The new CVE-2026-33636 scope is drawn from its captured CNA JSON. The blocked GHSA page status remains unchanged. The MITRE 404 for CVE-2026-46675 is limited to that CVE Services lookup and is not expanded into a claim about GHSA existence or applicability.

## Validation limits and final state

The captured source bytes and saved headers were verified at the frozen Git commit. Batch B does not store a separate final `url_effective` output for successful requests, so headers establish response status/type and per-CVE file mappings while endpoint association comes from each manifest's recorded source URL and capture documentation.

The revision fixes the earlier path-field issue and adds usable CNA/error lookup evidence without conflating either response with the GHSA webpage. Two GHSA pages remain blocked. Other entries retain explicitly unknown publisher/fixed-version or unusual-scope conditions. **Batch B stays PARTIAL; the overall 17-CVE advisory package is not ready for D55 execution, and M2 remains NOT MET.**
