# D26: G-drive cJSON fixed-source replay

Date: 2026-10-19
Detector: ohscanner.known_disclosed_cves 0.6.0
Classification: repeated real-source replay; not an independent holdout

## Pinned source and method

The read-only scan used the G-drive mirror at commit 0c2c9dff82cc85539c8362132d7a5f6bf7d1e748 (tree 0d8e50cc18f9ae178e9969eed40f8a0c94fb3856). The Runner read local Git objects, not the possibly line-ending-normalized checkout files. The full snapshot digest is 648f483aac768e54d504a3b38aea53bfe3c653521580a0cdb51c763182417731.

At that commit, cJSON_Utils.c has Git blob 8fa24f8e9bf452cf1ba49d1325c85423ce742c74 and source SHA-256 bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9. Both exactly match the fixed cJSON_Utils.c object from the upstream CVE-2025-57052 repair reviewed in D25. The loop checks pointer[position] <= '9'; the vulnerable pointer[0] condition is absent. The source blob and SHA match are stronger evidence than a working-tree hash affected by CRLF checkout normalization.

The reproduction command is:

    .venv-web/bin/python research/data_sensitive/d26_g_cjson_scan.py \
      --repo /mnt/g/OpenHarmony-GitCode-Mirror/repos/third_party_cJSON \
      --output-dir research/data_sensitive/D26_G_CJSON

The script does not fetch, checkout, or modify the source mirror. It verifies the fixed commit, tree, cJSON_Utils blob, SHA-256, and expression, then runs the first-party fixed-commit scan twice. Full reports and the compact comparison are in D26_G_CJSON/.

## Results

Both runs selected 99 C/C++ files (724,785 bytes), with 61 complete parses and 38 partial parses. Both reports were completed_with_limitations; the detector itself was blocked and its coverage sidecar marked all 99 files partial. The runs each retained two stable candidates:

- CVE-2026-67215 at cJSON_Utils.c:808, source SHA-256 bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9.
- CVE-2026-67216 at cJSON.c:3067, source SHA-256 427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb.

CVE-2025-57052 did not produce a candidate because the pinned G source is byte-for-byte the fixed upstream Git object. Candidate identity, source hashes, and coverage were identical on both runs. Measured wall times were 1.435 s and 1.372 s on this host; per-run peak RSS was not captured.

## Interpretation and limits

This demonstrates that the D scanner distinguishes the known fixed cJSON shape in this real G snapshot while preserving two other component-source candidates through the Runner. It does not establish that the component is built into a particular OpenHarmony product, that attacker-controlled input reaches these APIs, or that either remaining candidate has product impact. All evidence obligations remain unresolved and validated_vulnerability is 0.

The CVE-2025-57052 fixed source was already used in rule development, so this replay is not a blind or independent holdout and cannot support a Recall claim. The blocked/partial coverage also means the no-match result does not mean the rest of the repository is safe. See D26_G_CJSON_REPLAY.json and the two raw reports for complete source bindings.
