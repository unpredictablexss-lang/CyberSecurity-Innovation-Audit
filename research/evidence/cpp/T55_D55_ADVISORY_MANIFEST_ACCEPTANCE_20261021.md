# T55 independent review: D55 advisory evidence manifests

- Review date: 2026-10-21 (Asia/Shanghai)
- Independent review checkout: `D:/openHarmonyScanner/worktrees/t51-pasteboard-independent-20261020`
- Batch A frozen commit: `e829231d3f9f06dfda4ca542af23aeaf00e3c22e`
- Batch B frozen commit: `55ba5fc0220d9f72443010fd0ad38270d2f22539`
- Catalog identity: `D_KNOWN_CVE_SCAN_20261019.md`, blob `5e71601423a3247b45fb4ce9adf28323b471dcb5`, SHA-256 `577731fe7f2b252e895c4e1ec93e6ee494db7d3583fc848bb9173ba47eb660e0`
- Scope: read-only verification of catalog membership, committed source object bytes, per-entry digest/length, transport metadata/header association, evidence states, and version-scope boundaries. No source findings or scanner results were reviewed.

## Decision

**Advisory package: PARTIAL / NOT READY for D55 known-CVE execution. M2 remains NOT MET.** The two manifests cover all 17 catalog IDs exactly once. All 15 entries marked captured have a committed body whose raw bytes match the manifest SHA-256 and byte count. Batch A transport metadata matches the requested CVE Services URL and HTTP response metadata for all nine entries. Batch B's six captured entries have response-header bytes matching their SHA-256, status 200 and content type, with per-CVE body/header filename mapping consistent. Two GitHub advisories are correctly blocked: no body, HTTP status `null`/curl `000`, zero response bytes and empty headers. They are not represented as captured evidence.

The package remains incomplete because those two primary captures are absent and multiple entries explicitly lack authoritative vendor scope or a fixed-version mapping. Scope conflicts and unknowns are preserved without broadening affected ranges or claiming OpenHarmony product applicability. Batch B also has a minor manifest path issue for the two blocked header files: `response_headers_file` includes explanatory text after the filename, so the JSON value is not directly resolvable as a Git path. The actual zero-byte files and their empty-byte SHA are present and verified.

## Catalog and body verification

The pinned catalog contains 17 unique IDs. Batch A contributes 9 unique IDs; batch B contributes 8 unique IDs. Their union equals the catalog, with no missing, extra, or duplicate identifier.

For each captured entry, I independently read the Git blob at the named frozen commit and computed SHA-256 over the raw blob bytes. The `body_bytes` and SHA values in both manifests matched all **15/15** captured bodies:

| CVE | State | Raw body bytes | SHA-256 | Result |
|---|---|---:|---|---|
| CVE-2022-45877 | A captured, scope inconsistent | 3,334 | `8cc6368e16aaa77e566a22cfc11b217b06b6123b4456ce6499c5d65a170fc7d0` | PASS |
| CVE-2025-9900 | A captured, publisher scope recorded | 25,639 | `625a41fc0b0bcb6f23eea01e0273e6e85ad43cb4b60babff6b7396a6947d306f` | PASS |
| CVE-2025-25212 | A captured, scope inconsistency | 2,187 | `f969f3768cea8c7304043ac26b6418f2389b005383f9a541e89bf283cd0fb93a` | PASS |
| CVE-2025-27247 | A captured, scope inconsistency | 2,250 | `3f5177eae797c28a9c746d5e7823a8eda828d690ba713876addacbb2de540bb4` | PASS |
| CVE-2025-57052 | A record captured, vendor scope unknown | 2,315 | `3795f9d5d0f050da69450c939f2a3e80d227eae213b8f96253a2957acf394ee9` | PASS |
| CVE-2026-25850 | A captured, publisher scope recorded | 2,218 | `17c834ae4584dc74c6aa9757f0a99d17c8a092af56a7a5b5e338682f48f8065a` | PASS |
| CVE-2026-28733 | A captured, publisher scope recorded | 2,178 | `319d7fb3d963f004c037cab6a4c7e34e0c6324abf5a3ecf31de8ef9e525dc7de` | PASS |
| CVE-2026-28751 | A captured, publisher scope recorded | 2,166 | `5e2f99eccb8618f641370027275ee883fe826a668ca12d0602360d84fcfb276b` | PASS |
| CVE-2026-27648 | A captured, publisher scope recorded | 2,215 | `3e34f6359d50f4b378aaa83af92376e7a5bd355e11c54a4cea6e8ebefa37c74e` | PASS |
| CVE-2026-67215 | B captured, unreviewed GHSA | 2,319 | `aa785168dec0e37803f92ddf084e777a29c2e60d97a0f56e139524ce8e89cda2` | PASS |
| CVE-2026-67216 | B captured, unreviewed GHSA | 2,220 | `9ef9cb1d01583e01fdd3bb250ec8a46c9ea83aec7084d6075a849a223ea75ce7` | PASS |
| CVE-2026-92391 | B captured, curl advisory | 2,739 | `ce88cdf4cce411a2d77df8eaa9f2957e028b4b2aa6b4b263b889a5c068ab30dc` | PASS |
| CVE-2026-9079 | B captured, curl advisory | 2,158 | `ebe4fde1e2bf5fd39c2fff79c5530fe400b3d8c6535893966b503f95bd887424` | PASS |
| CVE-2026-92392 | B captured, curl advisory | 1,933 | `c5fdab909e95d7e2b5608a67ccd1a06035d4018b0391c773efc217d7bcd8f6e3` | PASS |
| CVE-2026-58313 | B captured, OpenHarmony bulletin | 22,309 | `782d7b605509ccae7034e008241d855a8ef246861835b3453d393a65b9d376e3` | PASS |
| CVE-2026-33636 | B blocked | no body | no body hash | Correctly not captured |
| CVE-2026-46675 | B blocked | no body | no body hash | Correctly not captured |

## Transport and status review

- **Batch A (9/9):** each saved `.transport.json` identifies the corresponding `https://cveawg.mitre.org/api/cve/<ID>` request, request headers, UTC retrieval time, HTTP 200, response headers and content length. Response URL equals the manifest `snapshot_source_url`; response content length equals the saved body length. The recorded request uses `Accept: application/json` and the stated archive user agent.
- **Batch B captured entries (6/6):** each committed `.headers` raw blob matches its manifest `response_headers_sha256`; parsed response status is 200 and `Content-Type` matches the manifest. Each body hash/length also matches. The JSON and file naming associate each header/body pair with its CVE. The captured manifest does not preserve curl's final `url_effective` output as a separate field, so the headers independently confirm response metadata while endpoint association relies on the per-entry retrieval/canonical URL and file mapping.
- **Batch B blocked entries (2/2):** `CVE-2026-33636` and `CVE-2026-46675` have null body hash, null body path and null HTTP status. Their zero-byte header blobs hash to the SHA-256 of the empty byte sequence (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`). The manifests report curl exit 28, status `000`, zero bytes and a specific missing-evidence requirement. These are failed capture attempts, not captures.
- **Path annotation:** for the two blocked entries, JSON `response_headers_file` values are `CVE-....headers (zero bytes; no HTTP headers received)`, while the actual tracked filename is `CVE-....headers`. The suffix is descriptive text, not part of the path; consumers that use the field literally will fail to open it. Correct the path field or split path and note into separate fields in a future manifest revision.
- **Raw-file handling:** batch B `.gitattributes` applies `-text -diff` to `.body` and `.headers`, consistent with preserving raw bytes. Both manifest JSON files parse with a duplicate-key-rejecting `object_pairs_hook`.

## Scope and unknown boundaries

- `CVE-2022-45877`: structured affected version says OpenHarmony 3.1.0; description says v3.1.4 and prior. Both are preserved; no range reconciliation was asserted.
- `CVE-2025-25212`: the structured affected range is bounded to v5.0.3/v5.0.3.x, while prose says v5.0.3 and prior. The discrepancy is labeled; the prose is not used to expand the range.
- `CVE-2025-27247`: structured range starts at v5.0.1 through v5.0.3, while prose says v5.0.3 and prior. The record retains both; no broader range is inferred.
- `CVE-2025-57052`: the MITRE-assigned record describes cJSON 1.5.0–1.7.18, but structured affected product/version is n/a and its reference is a researcher blog. Vendor/CNA version scope remains unknown; the description is not promoted to verified product scope.
- `CVE-2025-9900`: Red Hat's CNA record has upstream libtiff and Red Hat package-specific version data. It does not establish OpenHarmony applicability; package-specific EVR bounds are not transferred.
- `CVE-2026-33636`, `CVE-2026-46675`: source/version descriptions were transcribed from browser-readable GHSA text, but raw captures are blocked. No immutable advisory bytes/hash exist; treat source as blocked, not captured.
- `CVE-2026-67215`, `CVE-2026-67216`: official GitHub advisory payloads are captured, but both are unreviewed, lack structured affected/fixed ranges, and do not identify the original CNA/vendor. Their text does not establish a vendor-verified fixed version.
- `CVE-2026-9079`: the curl source includes an unusual introduced/fixed 8.21.0 event pair; the manifest preserves it and does not infer a corrected interval.
- `CVE-2026-58313`: the OpenHarmony bulletin supports the stated release line/component scope but does not give an exact fixed component version/revision. Fixed status remains unknown.

These constraints are correctly reflected in the manifests and Markdown; the evidence does not establish source snapshot or built-product applicability for any CVE.

## Validation performed

- Strictly parsed both batch JSON files with duplicate keys rejected: A 9 entries, B 8 entries; both passed.
- Extracted the 17 unique catalog IDs and asserted exact equality with the 17 unique manifest IDs.
- Read every body/header from its frozen Git commit with `git show`; recomputed raw-byte SHA-256 and length.
- Checked A request URL, HTTP status, response headers/content length against each CVE's manifest entry.
- Checked B response-header SHA, parsed HTTP status/content type against all six captured entries; checked both blocked entries have empty headers and null body/status/hash.
- Confirmed B `.gitattributes` disables text conversion for body/header files.
- `git diff --check` for each advisory commit against its parent returned exit 0.
- No scanner tests, labels, accuracy metrics, or product applicability judgments were produced.

## Final status

The catalog coverage and raw artifact integrity checks **PASS** for all submitted evidence objects; the advisory evidence package as a whole remains **PARTIAL / NOT READY**. The two blocked libpng advisories have no raw body snapshots, several entries explicitly have unresolved authority or version scope, and the two blocked header path fields need normalization for machine consumers. Preserve these statuses as blockers/unknowns. **D55 known-CVE track is not ready for execution; M2 remains NOT MET.**
