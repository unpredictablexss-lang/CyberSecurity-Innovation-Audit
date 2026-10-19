# D55 Primary Advisory Manifest A (CVE 1–9)

Captured at per-response UTC timestamps on 2026-10-19. This batch covers exactly 9 identifiers from the D55 frozen 17-item catalog.

## Collection method

- Primary records: official CVE Services API (`https://cveawg.mitre.org/api/cve/{CVE-ID}`), which returns the CVE JSON record published by the record assigner/CNA. Canonical human-readable record URL is `https://www.cve.org/CVERecord?id={CVE-ID}`. Publisher/assigner is taken from the record `cveMetadata.assignerShortName`; it is not inferred from a secondary search result.
- Each GET used `Accept: application/json` and `User-Agent: OHScanner-D55-Advisory-Archive/1.0`. Python `urllib.request` read response entity bytes directly; the body was saved as `.response.bin` before parsing. SHA-256 and byte count are over that exact saved body.
- Adjacent `.transport.json` records retrieval timestamp (UTC), request URL/headers, HTTP status, and response headers. HTTP transfer framing and TLS packets are not included; no JSON reserialization, newline conversion, or body text decoding occurred. These saved bytes are the immutable capture.
- JSON contains only the nine in-scope IDs. Its SHA fields and byte counts were verified against the committed raw body files, and JSON was loaded with a duplicate-key-rejecting parser.

## Results

| CVE | Publisher / record | Source/version scope from record | Evidence state | Raw bytes SHA-256 |
|---|---|---|---|---|
| CVE-2022-45877 | CVE CNA record; assignerShortName=OpenHarmony ([canonical record](https://www.cve.org/CVERecord?id=CVE-2022-45877)) | CVE CNA structured affected entry says OpenHarmony 3.1.0; CNA description says OpenHarmony v3.1.4 and prior. These conflict; preserve both and require source-level/version adjudication. | captured_primary_cna_record / captured_scope_inconsistency | `8cc6368e16aaa77e566a22cfc11b217b06b6123b4456ce6499c5d65a170fc7d0` |
| CVE-2025-9900 | CVE CNA record; assignerShortName=redhat ([canonical record](https://www.cve.org/CVERecord?id=CVE-2025-9900)) | Red Hat CNA record includes upstream libtiff semver versions below 4.7.1 and separate Red Hat product/package entries with package-specific unaffected EVR thresholds; exact full matrix is in the immutable source bytes. This does not establish OpenHarmony applicability. | captured_primary_cna_record / publisher_scope_recorded | `625a41fc0b0bcb6f23eea01e0273e6e85ad43cb4b60babff6b7396a6947d306f` |
| CVE-2025-25212 | CVE CNA record; assignerShortName=OpenHarmony ([canonical record](https://www.cve.org/CVERecord?id=CVE-2025-25212)) | OpenHarmony CNA structured affected range: product OpenHarmony, version v5.0.3 through v5.0.3.x (inclusive per lessThanOrEqual); defaultStatus unaffected. Description says OpenHarmony v5.0.3 and prior. | captured_primary_cna_record / captured_scope_inconsistency | `f969f3768cea8c7304043ac26b6418f2389b005383f9a541e89bf283cd0fb93a` |
| CVE-2025-27247 | CVE CNA record; assignerShortName=OpenHarmony ([canonical record](https://www.cve.org/CVERecord?id=CVE-2025-27247)) | OpenHarmony CNA structured affected range: product OpenHarmony, starting v5.0.1 through v5.0.3 (inclusive per lessThanOrEqual); defaultStatus unaffected. Description says OpenHarmony v5.0.3 and prior. | captured_primary_cna_record / captured_scope_inconsistency | `3f5177eae797c28a9c746d5e7823a8eda828d690ba713876addacbb2de540bb4` |
| CVE-2025-57052 | CVE CNA record; assignerShortName=mitre ([canonical record](https://www.cve.org/CVERecord?id=CVE-2025-57052)) | MITRE-assigned CVE record describes cJSON 1.5.0 through 1.7.18, but its structured affected entry is vendor/product/version n/a and its only reference is a researcher blog. No vendor/CNA advisory establishing this version range was present in the captured record; do not treat the description as verified vendor scope. | official_cve_record_captured_vendor_advisory_unknown / unknown_no_vendor_scope | `3795f9d5d0f050da69450c939f2a3e80d227eae213b8f96253a2957acf394ee9` |
| CVE-2026-25850 | CVE CNA record; assignerShortName=OpenHarmony ([canonical record](https://www.cve.org/CVERecord?id=CVE-2026-25850)) | OpenHarmony / OpenHarmony; structured affected range starts v5.0.3 and is inclusive through v6.0 (as stated by lessThanOrEqual), defaultStatus=unaffected. Description: in OpenHarmony v6.0 and prior versions allow a local attacker cause information leak | captured_primary_cna_record / publisher_scope_recorded | `17c834ae4584dc74c6aa9757f0a99d17c8a092af56a7a5b5e338682f48f8065a` |
| CVE-2026-28733 | CVE CNA record; assignerShortName=OpenHarmony ([canonical record](https://www.cve.org/CVERecord?id=CVE-2026-28733)) | OpenHarmony / OpenHarmony; structured affected range starts v5.0.3 and is inclusive through v6.0 (as stated by lessThanOrEqual), defaultStatus=unaffected. Description: in OpenHarmony v6.0 and prior versions allow a local attacker arbitrary code execution. | captured_primary_cna_record / publisher_scope_recorded | `319d7fb3d963f004c037cab6a4c7e34e0c6324abf5a3ecf31de8ef9e525dc7de` |
| CVE-2026-28751 | CVE CNA record; assignerShortName=OpenHarmony ([canonical record](https://www.cve.org/CVERecord?id=CVE-2026-28751)) | OpenHarmony / OpenHarmony; structured affected range starts v5.0.3 and is inclusive through v6.0 (as stated by lessThanOrEqual), defaultStatus=unaffected. Description: in OpenHarmony v6.0 and prior versions allow a local attacker cause DOS. | captured_primary_cna_record / publisher_scope_recorded | `5e2f99eccb8618f641370027275ee883fe826a668ca12d0602360d84fcfb276b` |
| CVE-2026-27648 | CVE CNA record; assignerShortName=OpenHarmony ([canonical record](https://www.cve.org/CVERecord?id=CVE-2026-27648)) | OpenHarmony / OpenHarmony; structured affected range starts v5.0.3 and is inclusive through v6.0 (as stated by lessThanOrEqual), defaultStatus=unaffected. Description: in OpenHarmony v6.0 and prior versions allow a remote attacker arbitrary code execution in pre-installed apps. | captured_primary_cna_record / publisher_scope_recorded | `3e34f6359d50f4b378aaa83af92376e7a5bd355e11c54a4cea6e8ebefa37c74e` |

## Per-record source pointers and limits

### CVE-2022-45877

- Canonical record: [https://www.cve.org/CVERecord?id=CVE-2022-45877](https://www.cve.org/CVERecord?id=CVE-2022-45877)
- Immutable capture endpoint: [https://cveawg.mitre.org/api/cve/CVE-2022-45877](https://cveawg.mitre.org/api/cve/CVE-2022-45877)
- Publisher: `CVE CNA record; assignerShortName=OpenHarmony`
- Retrieved: `2026-10-19T18:01:22Z`
- Snapshot: `snapshots/cve-2022-45877.response.bin` (3334 bytes), SHA-256 `8cc6368e16aaa77e566a22cfc11b217b06b6123b4456ce6499c5d65a170fc7d0`; transport metadata `snapshots/cve-2022-45877.transport.json`.
- Scope: CVE CNA structured affected entry says OpenHarmony 3.1.0; CNA description says OpenHarmony v3.1.4 and prior. These conflict; preserve both and require source-level/version adjudication.
- CNA-record reference(s): [https://gitee.com/openharmony/security/blob/master/en/security-disclosure/2022/2022-12.md](https://gitee.com/openharmony/security/blob/master/en/security-disclosure/2022/2022-12.md)
- Limitation: CNA description and structured affected version do not agree; no range inference made.

### CVE-2025-9900

- Canonical record: [https://www.cve.org/CVERecord?id=CVE-2025-9900](https://www.cve.org/CVERecord?id=CVE-2025-9900)
- Immutable capture endpoint: [https://cveawg.mitre.org/api/cve/CVE-2025-9900](https://cveawg.mitre.org/api/cve/CVE-2025-9900)
- Publisher: `CVE CNA record; assignerShortName=redhat`
- Retrieved: `2026-10-19T18:01:23Z`
- Snapshot: `snapshots/cve-2025-9900.response.bin` (25639 bytes), SHA-256 `625a41fc0b0bcb6f23eea01e0273e6e85ad43cb4b60babff6b7396a6947d306f`; transport metadata `snapshots/cve-2025-9900.transport.json`.
- Scope: Red Hat CNA record includes upstream libtiff semver versions below 4.7.1 and separate Red Hat product/package entries with package-specific unaffected EVR thresholds; exact full matrix is in the immutable source bytes. This does not establish OpenHarmony applicability.
- CNA-record reference(s): [https://access.redhat.com/errata/RHSA-2025:17651](https://access.redhat.com/errata/RHSA-2025:17651), [https://access.redhat.com/errata/RHSA-2025:17675](https://access.redhat.com/errata/RHSA-2025:17675), [https://access.redhat.com/errata/RHSA-2025:17710](https://access.redhat.com/errata/RHSA-2025:17710), [https://access.redhat.com/errata/RHSA-2025:17738](https://access.redhat.com/errata/RHSA-2025:17738), [https://access.redhat.com/errata/RHSA-2025:17739](https://access.redhat.com/errata/RHSA-2025:17739), [https://access.redhat.com/errata/RHSA-2025:17740](https://access.redhat.com/errata/RHSA-2025:17740), [https://access.redhat.com/errata/RHSA-2025:19113](https://access.redhat.com/errata/RHSA-2025:19113), [https://access.redhat.com/errata/RHSA-2025:19156](https://access.redhat.com/errata/RHSA-2025:19156), [https://access.redhat.com/errata/RHSA-2025:19276](https://access.redhat.com/errata/RHSA-2025:19276), [https://access.redhat.com/errata/RHSA-2025:19906](https://access.redhat.com/errata/RHSA-2025:19906), [https://access.redhat.com/errata/RHSA-2025:19947](https://access.redhat.com/errata/RHSA-2025:19947), [https://access.redhat.com/errata/RHSA-2025:20956](https://access.redhat.com/errata/RHSA-2025:20956), [https://access.redhat.com/errata/RHSA-2025:20998](https://access.redhat.com/errata/RHSA-2025:20998), [https://access.redhat.com/errata/RHSA-2025:21060](https://access.redhat.com/errata/RHSA-2025:21060), [https://access.redhat.com/errata/RHSA-2025:21061](https://access.redhat.com/errata/RHSA-2025:21061), [https://access.redhat.com/errata/RHSA-2025:21062](https://access.redhat.com/errata/RHSA-2025:21062), [https://access.redhat.com/errata/RHSA-2025:21407](https://access.redhat.com/errata/RHSA-2025:21407), [https://access.redhat.com/errata/RHSA-2025:21506](https://access.redhat.com/errata/RHSA-2025:21506), [https://access.redhat.com/errata/RHSA-2025:21507](https://access.redhat.com/errata/RHSA-2025:21507), [https://access.redhat.com/errata/RHSA-2025:21508](https://access.redhat.com/errata/RHSA-2025:21508), [https://access.redhat.com/errata/RHSA-2025:21994](https://access.redhat.com/errata/RHSA-2025:21994), [https://access.redhat.com/errata/RHSA-2025:23078](https://access.redhat.com/errata/RHSA-2025:23078), [https://access.redhat.com/errata/RHSA-2025:23079](https://access.redhat.com/errata/RHSA-2025:23079), [https://access.redhat.com/errata/RHSA-2025:23080](https://access.redhat.com/errata/RHSA-2025:23080), [https://access.redhat.com/errata/RHSA-2026:0001](https://access.redhat.com/errata/RHSA-2026:0001), [https://access.redhat.com/errata/RHSA-2026:0076](https://access.redhat.com/errata/RHSA-2026:0076), [https://access.redhat.com/errata/RHSA-2026:0077](https://access.redhat.com/errata/RHSA-2026:0077), [https://access.redhat.com/errata/RHSA-2026:0078](https://access.redhat.com/errata/RHSA-2026:0078), [https://access.redhat.com/errata/RHSA-2026:3461](https://access.redhat.com/errata/RHSA-2026:3461), [https://access.redhat.com/errata/RHSA-2026:3462](https://access.redhat.com/errata/RHSA-2026:3462), [https://access.redhat.com/errata/RHSA-2026:7504](https://access.redhat.com/errata/RHSA-2026:7504), [https://access.redhat.com/security/cve/CVE-2025-9900](https://access.redhat.com/security/cve/CVE-2025-9900), [https://bugzilla.redhat.com/show_bug.cgi?id=2392784](https://bugzilla.redhat.com/show_bug.cgi?id=2392784), [https://github.com/SexyShoelessGodofWar/LibTiff-4.7.0-Write-What-Where?tab=readme-ov-file](https://github.com/SexyShoelessGodofWar/LibTiff-4.7.0-Write-What-Where?tab=readme-ov-file), [https://gitlab.com/libtiff/libtiff/-/issues/704](https://gitlab.com/libtiff/libtiff/-/issues/704), [https://gitlab.com/libtiff/libtiff/-/merge_requests/732](https://gitlab.com/libtiff/libtiff/-/merge_requests/732), [https://libtiff.gitlab.io/libtiff/releases/v4.7.1.html](https://libtiff.gitlab.io/libtiff/releases/v4.7.1.html)

### CVE-2025-25212

- Canonical record: [https://www.cve.org/CVERecord?id=CVE-2025-25212](https://www.cve.org/CVERecord?id=CVE-2025-25212)
- Immutable capture endpoint: [https://cveawg.mitre.org/api/cve/CVE-2025-25212](https://cveawg.mitre.org/api/cve/CVE-2025-25212)
- Publisher: `CVE CNA record; assignerShortName=OpenHarmony`
- Retrieved: `2026-10-19T18:01:25Z`
- Snapshot: `snapshots/cve-2025-25212.response.bin` (2187 bytes), SHA-256 `f969f3768cea8c7304043ac26b6418f2389b005383f9a541e89bf283cd0fb93a`; transport metadata `snapshots/cve-2025-25212.transport.json`.
- Scope: OpenHarmony CNA structured affected range: product OpenHarmony, version v5.0.3 through v5.0.3.x (inclusive per lessThanOrEqual); defaultStatus unaffected. Description says OpenHarmony v5.0.3 and prior.
- CNA-record reference(s): [https://gitee.com/openharmony/security/blob/master/zh/security-disclosure/2025/2025-07.md](https://gitee.com/openharmony/security/blob/master/zh/security-disclosure/2025/2025-07.md)

### CVE-2025-27247

- Canonical record: [https://www.cve.org/CVERecord?id=CVE-2025-27247](https://www.cve.org/CVERecord?id=CVE-2025-27247)
- Immutable capture endpoint: [https://cveawg.mitre.org/api/cve/CVE-2025-27247](https://cveawg.mitre.org/api/cve/CVE-2025-27247)
- Publisher: `CVE CNA record; assignerShortName=OpenHarmony`
- Retrieved: `2026-10-19T18:01:27Z`
- Snapshot: `snapshots/cve-2025-27247.response.bin` (2250 bytes), SHA-256 `3f5177eae797c28a9c746d5e7823a8eda828d690ba713876addacbb2de540bb4`; transport metadata `snapshots/cve-2025-27247.transport.json`.
- Scope: OpenHarmony CNA structured affected range: product OpenHarmony, starting v5.0.1 through v5.0.3 (inclusive per lessThanOrEqual); defaultStatus unaffected. Description says OpenHarmony v5.0.3 and prior.
- CNA-record reference(s): [https://gitee.com/openharmony/security/blob/master/zh/security-disclosure/2025/2025-06.md](https://gitee.com/openharmony/security/blob/master/zh/security-disclosure/2025/2025-06.md)

### CVE-2025-57052

- Canonical record: [https://www.cve.org/CVERecord?id=CVE-2025-57052](https://www.cve.org/CVERecord?id=CVE-2025-57052)
- Immutable capture endpoint: [https://cveawg.mitre.org/api/cve/CVE-2025-57052](https://cveawg.mitre.org/api/cve/CVE-2025-57052)
- Publisher: `CVE CNA record; assignerShortName=mitre`
- Retrieved: `2026-10-19T18:01:28Z`
- Snapshot: `snapshots/cve-2025-57052.response.bin` (2315 bytes), SHA-256 `3795f9d5d0f050da69450c939f2a3e80d227eae213b8f96253a2957acf394ee9`; transport metadata `snapshots/cve-2025-57052.transport.json`.
- Scope: MITRE-assigned CVE record describes cJSON 1.5.0 through 1.7.18, but its structured affected entry is vendor/product/version n/a and its only reference is a researcher blog. No vendor/CNA advisory establishing this version range was present in the captured record; do not treat the description as verified vendor scope.
- CNA-record reference(s): [https://x-0r.com/posts/cJSON-Array-Index-Parsing-Vulnerability](https://x-0r.com/posts/cJSON-Array-Index-Parsing-Vulnerability)
- Limitation: No vendor/CNA advisory or authoritative product version scope established by this capture; source/version scope remains unknown.

### CVE-2026-25850

- Canonical record: [https://www.cve.org/CVERecord?id=CVE-2026-25850](https://www.cve.org/CVERecord?id=CVE-2026-25850)
- Immutable capture endpoint: [https://cveawg.mitre.org/api/cve/CVE-2026-25850](https://cveawg.mitre.org/api/cve/CVE-2026-25850)
- Publisher: `CVE CNA record; assignerShortName=OpenHarmony`
- Retrieved: `2026-10-19T18:01:30Z`
- Snapshot: `snapshots/cve-2026-25850.response.bin` (2218 bytes), SHA-256 `17c834ae4584dc74c6aa9757f0a99d17c8a092af56a7a5b5e338682f48f8065a`; transport metadata `snapshots/cve-2026-25850.transport.json`.
- Scope: OpenHarmony / OpenHarmony; structured affected range starts v5.0.3 and is inclusive through v6.0 (as stated by lessThanOrEqual), defaultStatus=unaffected. Description: in OpenHarmony v6.0 and prior versions allow a local attacker cause information leak
- CNA-record reference(s): [https://gitcode.com/openharmony/security/tree/master/zh/security-disclosure/2026/2026-05.md](https://gitcode.com/openharmony/security/tree/master/zh/security-disclosure/2026/2026-05.md)

### CVE-2026-28733

- Canonical record: [https://www.cve.org/CVERecord?id=CVE-2026-28733](https://www.cve.org/CVERecord?id=CVE-2026-28733)
- Immutable capture endpoint: [https://cveawg.mitre.org/api/cve/CVE-2026-28733](https://cveawg.mitre.org/api/cve/CVE-2026-28733)
- Publisher: `CVE CNA record; assignerShortName=OpenHarmony`
- Retrieved: `2026-10-19T18:01:32Z`
- Snapshot: `snapshots/cve-2026-28733.response.bin` (2178 bytes), SHA-256 `319d7fb3d963f004c037cab6a4c7e34e0c6324abf5a3ecf31de8ef9e525dc7de`; transport metadata `snapshots/cve-2026-28733.transport.json`.
- Scope: OpenHarmony / OpenHarmony; structured affected range starts v5.0.3 and is inclusive through v6.0 (as stated by lessThanOrEqual), defaultStatus=unaffected. Description: in OpenHarmony v6.0 and prior versions allow a local attacker arbitrary code execution.
- CNA-record reference(s): [https://gitcode.com/openharmony/security/tree/master/zh/security-disclosure/2026/2026-05.md](https://gitcode.com/openharmony/security/tree/master/zh/security-disclosure/2026/2026-05.md)

### CVE-2026-28751

- Canonical record: [https://www.cve.org/CVERecord?id=CVE-2026-28751](https://www.cve.org/CVERecord?id=CVE-2026-28751)
- Immutable capture endpoint: [https://cveawg.mitre.org/api/cve/CVE-2026-28751](https://cveawg.mitre.org/api/cve/CVE-2026-28751)
- Publisher: `CVE CNA record; assignerShortName=OpenHarmony`
- Retrieved: `2026-10-19T18:01:33Z`
- Snapshot: `snapshots/cve-2026-28751.response.bin` (2166 bytes), SHA-256 `5e2f99eccb8618f641370027275ee883fe826a668ca12d0602360d84fcfb276b`; transport metadata `snapshots/cve-2026-28751.transport.json`.
- Scope: OpenHarmony / OpenHarmony; structured affected range starts v5.0.3 and is inclusive through v6.0 (as stated by lessThanOrEqual), defaultStatus=unaffected. Description: in OpenHarmony v6.0 and prior versions allow a local attacker cause DOS.
- CNA-record reference(s): [https://gitcode.com/openharmony/security/tree/master/zh/security-disclosure/2026/2026-04.md](https://gitcode.com/openharmony/security/tree/master/zh/security-disclosure/2026/2026-04.md)

### CVE-2026-27648

- Canonical record: [https://www.cve.org/CVERecord?id=CVE-2026-27648](https://www.cve.org/CVERecord?id=CVE-2026-27648)
- Immutable capture endpoint: [https://cveawg.mitre.org/api/cve/CVE-2026-27648](https://cveawg.mitre.org/api/cve/CVE-2026-27648)
- Publisher: `CVE CNA record; assignerShortName=OpenHarmony`
- Retrieved: `2026-10-19T18:01:35Z`
- Snapshot: `snapshots/cve-2026-27648.response.bin` (2215 bytes), SHA-256 `3e34f6359d50f4b378aaa83af92376e7a5bd355e11c54a4cea6e8ebefa37c74e`; transport metadata `snapshots/cve-2026-27648.transport.json`.
- Scope: OpenHarmony / OpenHarmony; structured affected range starts v5.0.3 and is inclusive through v6.0 (as stated by lessThanOrEqual), defaultStatus=unaffected. Description: in OpenHarmony v6.0 and prior versions allow a remote attacker arbitrary code execution in pre-installed apps.
- CNA-record reference(s): [https://gitcode.com/openharmony/security/tree/master/zh/security-disclosure/2026/2026-04.md](https://gitcode.com/openharmony/security/tree/master/zh/security-disclosure/2026/2026-04.md)

## Blocking and non-inference notes

- CVE-2025-57052 has an official MITRE-assigned CVE record snapshot, but that record’s structured affected entry is `n/a`; the description states cJSON 1.5.0–1.7.18 and its sole reference is a researcher blog. This batch does not treat that as vendor/CNA-confirmed version scope. Minimum missing evidence: cJSON vendor/CNA advisory or other primary publisher record establishing affected/fixed versions.
- CVE-2022-45877’s OpenHarmony CNA description says v3.1.4 and prior while its structured `affected` array says version 3.1.0. Both are preserved verbatim by the raw snapshot; no reconciled range is asserted.
- The records describe publisher scopes only. They do not establish that any local OpenHarmony source snapshot, product build, or deployment is affected. Red Hat package ranges are not transferable to OpenHarmony.

## Source files

- Manifest JSON: `D55_CVE_ADVISORIES_A_20261019.json`
- Raw HTTP response entity bodies and headers: `snapshots/`
- Catalog pointer (frozen D55 source): `research/data_sensitive/D_KNOWN_CVE_SCAN_20261019.md`, Git blob `5e71601423a3247b45fb4ce9adf28323b471dcb5`, SHA-256 `577731fe7f2b252e895c4e1ec93e6ee494db7d3583fc848bb9173ba47eb660e0`
