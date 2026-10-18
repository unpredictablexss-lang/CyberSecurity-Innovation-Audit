# D35: filemanagement external-volume permissions (CVE-2026-25850)

Date: 2026-10-19
Detector: `ohscanner.known_disclosed_cves` 0.11.0
Conclusion: **the fixed upstream source pair confirms a component-level permission-widening root cause; affected OpenHarmony product inclusion and impact remain unknown.** The scanner emits `candidate`, not a confirmed product finding.

## Evidence and root cause

OpenHarmony's May 2026 security bulletin lists CVE-2026-25850 for `filemanagement_storage_service`, describes local-actor sensitive-information disclosure, and names the 5.1.0 and 6.0 release lines. The source pair independently shows the vulnerable operation and its removal in the corresponding 5.1 and 6.0 merge-request histories.

In `ExternalVolumeInfo::DoMount4Ext` and `DoMount4Hmfs`, the before sources set `mode_t mode = 0777` and call `TravelChmod(mountPath_, mode)` after a successful mount. The same pinned `file_utils.cpp` implements `TravelChmod` by chmod'ing the mount root and each child, recursively descending into directories. The fix removes the 0777 assignment and recursive call from both mount methods. The replay binds every source to its commit, tree, Git blob, and SHA-256:

| Line | Vulnerable source | Fixed source | Detector |
|---|---|---|---:|
| 5.1 | `bf13f7daa06915e02788086f8450527eeb90f250` | `ef5145b591456f467531b5f6d38c124392b02e80` | 2 candidates → 0 |
| 6.0 | `3f0a6a2b0dc3f81fe4562ace4681be50243aaf8f` | `7f9e44c24eb27bf2e458f9b7a03c6311983ec912` | 2 candidates → 0 |

The D rule requires the reviewed source path, either named mount method, mode `0777`, and the matching `TravelChmod(mountPath_, mode)` call in that same function. It assigns CWE-732 and confidentiality as the candidate impact. It does not infer a product build, caller identity, mounted filesystem, or readable sensitive content.

## Reproduce the source PoC

This is a **static source replay**, not a runtime exploit or permission-read PoC. It runs the first-party detector over exact upstream Git objects and verifies old/fixed results without changing the source repository. The script never fetches:

```bash
git init /tmp/ohscanner-storage-d35
git -C /tmp/ohscanner-storage-d35 remote add origin https://gitcode.com/openharmony/filemanagement_storage_service.git
git -C /tmp/ohscanner-storage-d35 fetch --filter=blob:none --depth=100 origin \
  +refs/merge-requests/2666/head:refs/remotes/origin/mr-2666 \
  +refs/merge-requests/2674/head:refs/remotes/origin/mr-2674
.venv-web/bin/python research/data_sensitive/d35_filemanagement_cve_2026_25850_replay.py \
  --repo /tmp/ohscanner-storage-d35
```

The expected machine result is 2 candidates / 0 fixed-shape findings for each release line. The direct scan sets parsing to `not_run`; both runs therefore remain blocked, while the source-bound candidates are preserved. The full observations and hash bindings are in [D35 replay JSON](D35_FILEMANAGEMENT_CVE_2026_25850_REPLAY.json).

## Remediation and claim boundary

The reviewed upstream fix removes recursive `0777` assignment on external-volume mounts. Apply the matching supported release fix or an equivalent least-privilege policy; validate access by owner/group and security labels for each supported filesystem, then rerun mount, unmount, read-only, and normal file-access regression tests. Do not treat merely removing this call as a product fix until the exact product branch/build is rebuilt and checked.

The static replay demonstrates that the detector distinguishes these two fixed component-source pairs. It does not test unauthorized access, actual sensitive data, or an OpenHarmony product image. The bulletin's affected release list is public disclosure evidence; this repository has no product build manifest tying either vulnerable revision to a target product. Therefore the product status remains `unknown`, findings remain `candidate`, and `validated_vulnerability=0`. The D35 replay is not a product PoC.

References: [OpenHarmony May 2026 security bulletin](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2026/2026-05.md), [filemanagement_storage_service 6.0 fix MR !2666](https://gitcode.com/openharmony/filemanagement_storage_service/merge_requests/2666), [5.1 fix MR !2674](https://gitcode.com/openharmony/filemanagement_storage_service/merge_requests/2674).
