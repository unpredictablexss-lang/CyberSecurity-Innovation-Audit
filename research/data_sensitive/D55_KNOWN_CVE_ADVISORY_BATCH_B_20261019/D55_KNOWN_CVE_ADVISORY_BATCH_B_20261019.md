# D55 Known-CVE Advisory Manifest — Batch B

**Baseline:** D55 protocol commit `c86e0b0321eb38b0ff403e98b8597622c7cd556c`  
**Batch scope:** exactly 8 IDs assigned to batch B. This is a supplement; it does not modify the frozen 17-ID catalog, scanner, D55 protocol, or another batch.  
**Retrieval date:** 2026-10-19 UTC. The captured run began at `2026-10-19T18:06:22Z`.

## Status

| CVE | Primary publisher and canonical advisory | Source/version scope captured | Raw response body SHA-256 | State |
|---|---|---|---|---|
| CVE-2026-33636 | pnggroup/libpng maintainer GHSA [GHSA-wjr5-c57x-95m2](https://github.com/pnggroup/libpng/security/advisories/GHSA-wjr5-c57x-95m2) | libpng 1.6.36–1.6.55 with ARM Neon hardware optimizations enabled; patched 1.6.56 and 1.8.0 trunk | Unknown | **BLOCKED:** GitHub page timed out on the raw capture path (curl exit 28, 0 body bytes); GitHub API route returned 404. Browser text is recorded as a source pointer only, not a snapshot. |
| CVE-2026-46675 | pnggroup/libpng maintainer GHSA [GHSA-qvg3-h654-xq3j](https://github.com/pnggroup/libpng/security/advisories/GHSA-qvg3-h654-xq3j) | libpng 1.6.0–1.6.58 and unreleased 1.8.0 dev; patched 1.6.59 / 1.8.0 trunk; vulnerable application call sequence is also specified | Unknown | **BLOCKED:** GitHub page timed out on raw capture (curl exit 28, 0 body bytes); GitHub API route returned 404. Browser text is recorded as a source pointer only, not a snapshot. |
| CVE-2026-67215 | GitHub Advisory Database unreviewed GHSA [GHSA-5q3m-r3x7-8phg](https://github.com/advisories/GHSA-5q3m-r3x7-8phg) | Description says cJSON through 1.7.19; no structured affected/fixed range; fixed version unknown | `aa785168dec0e37803f92ddf084e777a29c2e60d97a0f56e139524ce8e89cda2` | **Captured.** GHSA is unreviewed; original CNA/vendor publisher and fixed version are not identified. |
| CVE-2026-67216 | GitHub Advisory Database unreviewed GHSA [GHSA-ff2v-f99f-wm3f](https://github.com/advisories/GHSA-ff2v-f99f-wm3f) | Description says cJSON through 1.7.19; no structured affected/fixed range; fixed version unknown | `9ef9cb1d01583e01fdd3bb250ec8a46c9ea83aec7084d6075a849a223ea75ce7` | **Captured.** GHSA is unreviewed; original CNA/vendor publisher and fixed version are not identified. |
| CVE-2026-92391 | curl project [CVE-2026-92391](https://curl.se/docs/CVE-2026-92391.html) | libcurl MIME cleanup recursion; official JSON records the exact semver introduced/fixed events and `last_affected=8.22.0` | `ce88cdf4cce411a2d77df8eaa9f2957e028b4b2aa6b4b263b889a5c068ab30dc` | **Captured.** |
| CVE-2026-9079 | curl project [CVE-2026-9079](https://curl.se/docs/CVE-2026-9079.html) | libcurl stale proxy password; official JSON says `last_affected=8.20.0` and enumerates through 8.20.0; semver events preserved verbatim | `ebe4fde1e2bf5fd39c2fff79c5530fe400b3d8c6535893966b503f95bd887424` | **Captured.** Its source event list has an unusual `introduced=8.21.0`, `fixed=8.21.0` pair. No interpretation was added. |
| CVE-2026-92392 | curl project [CVE-2026-92392](https://curl.se/docs/CVE-2026-92392.html) | curl and libcurl HTTP/2 upload UAF; official JSON records exact semver introduced/fixed events and `last_affected=8.22.0` | `c5fdab909e95d7e2b5608a67ccd1a06035d4018b0391c773efc217d7bcd8f6e3` | **Captured.** |
| CVE-2026-58313 | OpenHarmony Security Bulletin [August 2026 archived message](https://lists.openatom.io/hyperkitty/list/security%40openharmony.io/thread/IJ5WNUSUCN7CDCFQLO4FWYGJONVN2WYL/) | `bundlemanager_app_domain_verify`, OpenHarmony-v6.1-Release / 6.1.x; bulletin does not give an exact fixed component revision | `782d7b605509ccae7034e008241d855a8ef246861835b3453d393a65b9d376e3` | **Captured.** Exact fixed version remains unknown. |

The complete machine-readable manifest stores, for each entry, publisher, canonical URL, retrieval URL when it differs, UTC retrieval date, scope, snapshot state, response body bytes/hash, saved response header path/hash, HTTP status/content type, and precise missing evidence. `null` body hashes mean no response body was obtained; they do not mean a zero-byte advisory snapshot exists.

## Capture method and reproducibility

For each attempted source, curl followed redirects and wrote the body directly to the corresponding `.body` file while `-D` wrote response headers to `.headers`. The saved body was hashed as-is with SHA-256; it was not parsed, normalized, or reserialized. The response headers are separately hashed. Captured body bytes and header bytes are in this directory. Recompute hashes from the files with:

```powershell
Get-FileHash -Algorithm SHA256 .\CVE-2026-92391.body
Get-FileHash -Algorithm SHA256 .\CVE-2026-92391.headers
```

Equivalent capture template:

```powershell
curl.exe -L --http1.1 --max-time 12 -sS `
  -D CVE-<ID>.headers -o CVE-<ID>.body `
  -w '%{http_code}|%{url_effective}|%{content_type}|%{size_download}' `
  -A 'D55-advisory-evidence/1.0' --url '<retrieval URL>'
```

The three curl snapshots are the project-published OSV-format JSON endpoints. The cJSON snapshots are GitHub's official advisory API records; both records explicitly report `type=unreviewed`, `github_reviewed_at=null`, and no structured `vulnerabilities` range. The OpenHarmony snapshot is the original archived security-list HTML message. For the two libpng advisories, web reader access exposed the vendor-authored GHSA text and version fields, but the network path used by curl could not retrieve GitHub bytes. The two attempts returned exit code 28, status `000`, zero bytes, and empty header files; the GitHub API advisory endpoints separately returned HTTP 404. Browser-rendered text was not hashed or represented as an immutable snapshot.

`CVE-2026-9079`'s source JSON includes an unusual 8.21.0 introduced/fixed event pair. The manifest preserves that source data and reports the JSON's `last_affected` and enumerated versions without inferring a corrected interval. The OpenHarmony bulletin provides a release line, component and 6.1.x scope but no exact fix revision/version. The cJSON GHSA descriptions state “through 1.7.19” but neither records a fixed version.

## Files

- `D55_KNOWN_CVE_ADVISORY_BATCH_B_20261019.json` — strict JSON manifest for exactly this batch.
- `CVE-<ID>.body` — response bytes for the six successfully captured advisories.
- `CVE-<ID>.headers` — curl response headers for captured advisories; empty files document the two failed GitHub attempts.

This batch alone does not make D55's 17-ID advisory gate complete. Merge or freeze it together with the other batch manifests after independent hash/identity review; the two libpng snapshots and outstanding scope/fix questions remain explicit blockers.
