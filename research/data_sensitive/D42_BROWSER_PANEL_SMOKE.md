# D42 browser acceptance: disclosed-CVE static scan

Date: 2026-10-19. App source: D worktree `feat/d-commercial-readiness-20261019`; built frontend and API/scan/operation/validation Workers ran on loopback port 18765 with a fresh `/tmp` data directory.

## Browser flow

1. The repository scan page showed both D research options: sensitive-data exposure and disclosed-CVE component signatures. Both were unchecked by default.
2. A temporary local Git repository was registered under the isolated test target root. It contained one source file copied from the existing D39 vulnerable LRU fixture; no OpenHarmony product source checkout was modified.
3. Selecting `ohscanner.known_disclosed_cves` produced a visible plan with 8 attempted rules, one not admitted, and zero parser-incomplete files. The scan froze commit `998b622d3edb84236f511dc3789feda9ffac5c9f` and tree `a864090289ed`.
4. The browser task completed and displayed one `ohknowncve-appdomainverify-cve-2026-58313` CWE-416 candidate at `frameworks/common/include/utils/lru_cache_util.h:56`. The evidence view bound the file to SHA-256 `77cf22fe5fc52a1f365f556344360ba4912341c1b6875f8778e40ca80c576ad4` and showed the four product evidence obligations as missing.
5. The task report tab exposed `manifest.json`, `report.json`, `report.md`, `review.json`, and `review.md`. The original report SHA-256 was `297a1e67e214c1cf697bb03b496be1ff77ad45e6d9f697dc257a745bbc7b52c6`; the source snapshot SHA-256 was `c22da4f4f945fdfd9f84517d7cbb827a936b467578cb5febb2c547e7a4a6a1ae`.

## Result boundary

This is browser-level UI → API → Worker → persisted report/evidence acceptance for a synthetic local scan repo containing an exact historical component header. It verifies that the static detector can be explicitly selected and its candidate/report are visible in the page. It does not prove an OpenHarmony product vulnerability, complete repository coverage, or dynamic exploitability. The displayed confirmed-vulnerability count was 0; the finding remained `candidate` with missing product-build, attacker-path, and impact evidence.

The service had no listener on the previously used 8765 port during this acceptance. The test used port 18765 and a fresh data directory; no owner/shared service state was changed.