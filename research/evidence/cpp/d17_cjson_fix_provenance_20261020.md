# D17 — cJSON CVE-2026-67215/67216 upstream remediation provenance

Date: 2026-10-20 (Asia/Shanghai)
Integration baseline: `8e79a238c3689ec6ffc2d98559a801e1620042ed`
Investigation worktree: `codex/a-d17-cjson-provenance-20261020`

## Disposition

| CVE | Official upstream state checked | Fixed-source disposition |
|---|---|---|
| CVE-2026-67215 — JSON Patch add/copy tree amplification followed by recursive deletion | GHSA patched version is unknown; issue #1073 remains open with no linked branch/PR; current `master` and `develop` still use unbounded recursive `cJSON_Delete()` and JSON Patch duplicate/graft paths. PR #1064 is open but addresses MergePatch recursion, a different operation/root. | **No trusted fixed source found.** Preserve fixed comparison as BLOCK. |
| CVE-2026-67216 — exponential recursive object comparison | GHSA patched version is unknown; issue #1073 remains open with no linked branch/PR; current `master` retains the symmetric second object traversal. PR #1078 is open and limits recursion depth for stack exhaustion; that is not a demonstrated fix for the symmetric exponential-work root. | **No merged/released fixed source found.** An official `develop` ancestry candidate (`bd307ec…`) removes the duplicate recursive pass; record it as an unmerged source candidate only, not as a trusted fixed baseline for this A-line pair. |

The latest official release inspected is v1.7.19 (`c859b25…`). GitHub Advisory Database entries GHSA-5q3m-r3x7-8phg and GHSA-ff2v-f99f-wm3f both show `Patched versions: Unknown` and `No known source code`. This is consistent with the `master` history and release page checked on this date; it does not prove no future fix will be published.

## Exact vulnerable/source references

The A-line replay already binds the OpenHarmony source to commit `105eaddbf0d0110b07d16bdefc81ffc796e1444a`, tree `3c07134d5a05aa546b15739e32503a2ca192d258`. Its recorded files are `third_party/cjson/cJSON.c` (blob `152b2caa479c9f448001652913c980a6dafb82e0`, 80,399 bytes, SHA-256 `427c72055ae68467b451599d36da074351a5ca53f6e103cd30064e32cf0fffbb`) and `third_party/cjson/cJSON_Utils.c` (blob `8fa24f8e9bf452cf1ba49d1325c85423ce742c74`, 40,736 bytes, SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`). These are the existing T3/D10 vulnerable inputs, not a proposed fix.

Official v1.7.19 release commit: `c859b25da02955fef659d658b8f324b5cde87be3`; parent `74e1ff4994aa4139126967f6d289b675b4b36fef`; tree `9c7b88a72ea9f3658c7f08c26b5cb09470f51761`. Its `cJSON.c` blob `6e4fb0dd369cd905923da515be87ab06db6c1ee0` is 80,399 bytes, SHA-256 `298581a04a36c0165da4b0aade235c23088cb2faa58651d720ea2f3706ed0b0d`; its `cJSON_Utils.c` blob is the same `8fa24f8e…` as the A-line pinned source, 40,736 bytes, SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`.

## Current official refs and source identities

Refs were read with `git ls-remote` and fetched directly from `https://github.com/DaveGamble/cJSON.git`. Full commit IDs and trees are from fetched Git objects; file SHA-256 values were recomputed from `git cat-file blob` bytes.

| Ref | Commit / parent / tree | Source objects relevant to this review |
|---|---|---|
| `master` | `6d9f2443ab071f86e5d9b43025a40929ec41c46c` / `fb16e5cf358798aabb049655975cde8427101056` / `43196d72eeaf223f8494df8315f3d0dfba07dd6d` | `cJSON.c`: blob `88c2d95b313132abde96d0f6e200789c771fc1e1`, 80,692 bytes, SHA-256 `607e756460fa0de37d20a7a9181f2de29c97bfb7ce5a0e6c2f548243836cd852`. `cJSON_Utils.c`: blob `4f3a9ed8d26a82befd63e97d0fbb7a3b52b3b730`, 40,997 bytes, SHA-256 `4dc793272a1f2c8d2e3965bc5662568b16aa86037e030a3c345f2d5b5e88f73f`. |
| `develop` | `1ac905d3b2359f48a0463afe8e16a080f0e1e03c` / `5437b7908651c6b0828a82b21b4baf98846c0d01` / `459c57c001732c00c65f326a7fe2c6e036161ba0` | `cJSON.c`: blob `727e1827cbee21ace2a2662e25bf1573f30c4414`, 74,746 bytes, SHA-256 `39deb987af54a1ac8b43c330c935889ba7d7e805c691d0083791f50e676850eb`. `cJSON_Utils.c`: blob `0d199f88303f7fe547a497c2a6530c468dd5007f`, 40,019 bytes, SHA-256 `603d76260417aadef920e964d8ac4e3d36493ffcf493ad41eb938b9ee82e0bef`. |

### CVE-2026-67216 unmerged develop candidate

Commit `bd307ec3b5f1c0555976c4b0118621e485367aa2` (`cJSON_Compare: Performance improvement for objects`) is an ancestor of official `develop` and not an ancestor of current official `master`. Parent `4e9154458dce824216820fd49bfe8bd97bc1e287`; tree `fa51cefb4d6f1f097d5cbfa842702a3c4e09bf3f`. At that commit, `cJSON.c` is blob `d8ea4d33a1546a3da052c3387319632b56818341`, 73,339 bytes, SHA-256 `2d13226af13a4f065862caf6f0c34f3ef7b43f83798ce37d28747d05612f097a`.

Its patch checks object child counts and removes the reverse second `cJSON_Compare()` traversal. That directly removes the disclosed duplicate-recursion mechanism at source level. However, it is a historical commit on the divergent `develop` line, not merged into `master`, not represented by a release, and not linked as the remediation for CVE-2026-67216. Therefore this record treats it as a **root-matched upstream candidate**, not a fixed variant that can close the A-line comparison gate. PR #1078 is currently open and its stated changes add depth limits to compare/merge-patch recursion; depth limiting does not establish a fix for the exponential cost at the advisory's reported nesting depth (~40).

### CVE-2026-67215 adjacent work is not a fix

Current `master` and `develop` source still has `cJSON_Delete()` recursively call itself on `item->child` without a depth bound. The JSON Patch `apply_patch()` COPY/ADD paths still duplicate a selected subtree and graft it into the document; the 10,000-level duplicate circularity limit remains distinct from a delete recursion limit. PR #1064 is open and explicitly targets `cJSONUtils_MergePatch` / `cJSONUtils_GenerateMergePatch` recursion related to issue #995. It does not supply a fixed source for RFC 6902 JSON Patch add/copy amplification followed by `cJSON_Delete()`. Do not use it as a fixed control.

## Issue / PR / release state checked

- [Issue #1073](https://github.com/DaveGamble/cJSON/issues/1073): Open as checked 2026-10-20; combines both CVEs; says no confirmed upstream fixed version; GitHub issue metadata shows no branches or pull requests.
- [GHSA-5q3m-r3x7-8phg](https://github.com/advisories/GHSA-5q3m-r3x7-8phg) / [CVE-2026-67215](https://nvd.nist.gov/vuln/detail/CVE-2026-67215): patched versions unknown, source code unknown.
- [GHSA-ff2v-f99f-wm3f](https://github.com/advisories/GHSA-ff2v-f99f-wm3f) / [CVE-2026-67216](https://nvd.nist.gov/vuln/detail/CVE-2026-67216): patched versions unknown, source code unknown.
- [PR #1064](https://github.com/DaveGamble/cJSON/pull/1064): Open; MergePatch/GenerateMergePatch recursion stack guard; unrelated root to CVE-2026-67215.
- [PR #1078](https://github.com/DaveGamble/cJSON/pull/1078): Open; depth-bounds recursive compare and merge-patch paths; not an evidenced fix for exponential object comparison cost in CVE-2026-67216.
- [Latest release](https://github.com/DaveGamble/cJSON/releases/latest): redirects to v1.7.19, commit `c859b25…`, with no later release shown.

## Reproduction

From this repository checkout, the upstream object acquisition and identity checks were:

```powershell
git ls-remote https://github.com/DaveGamble/cJSON.git HEAD refs/heads/master refs/heads/develop refs/tags/v1.7.19
git fetch --no-tags https://github.com/DaveGamble/cJSON.git refs/heads/master:refs/remotes/d17/master refs/heads/develop:refs/remotes/d17/develop
git show -s --format="commit=%H%nparent=%P%ntree=%T%nsubject=%s" refs/remotes/d17/master
git show -s --format="commit=%H%nparent=%P%ntree=%T%nsubject=%s" refs/remotes/d17/develop
git ls-tree refs/remotes/d17/master cJSON.c cJSON_Utils.c
git ls-tree refs/remotes/d17/develop cJSON.c cJSON_Utils.c
git show -s --format="commit=%H%nparent=%P%ntree=%T%nsubject=%s" bd307ec3b5f1c0555976c4b0118621e485367aa2
git ls-tree bd307ec3b5f1c0555976c4b0118621e485367aa2 cJSON.c
git merge-base --is-ancestor bd307ec3b5f1c0555976c4b0118621e485367aa2 refs/remotes/d17/develop
git merge-base --is-ancestor bd307ec3b5f1c0555976c4b0118621e485367aa2 refs/remotes/d17/master
```

The first ancestry command returned 0; the second returned 1. SHA-256 was computed over raw `git cat-file blob <oid>` bytes (not checkout-transformed text). The API endpoint attempt was rate-limited (HTTP 403), and a later PR-ref `git ls-remote` attempt timed out; the official GitHub HTML issue/advisory/PR/release pages were checked as cross-verification. These transient failures do not change the fetched branch object evidence.

## Result / next evidence

No released or merged fixed source is available for either CVE from the official upstream refs examined. Keep both A-line cases PARTIAL/BLOCK pending complete detector analysis, and keep the fixed-source comparison blocked. For CVE-2026-67216, D16/T3 may use `bd307ec…` only as a clearly marked root-matched candidate/control after independently verifying behavior on the exact A-line source context; it must not be called a vendor fixed version. For CVE-2026-67215, the smallest missing input is an upstream merged patch/release or another explicitly trusted fixed source that addresses JSON Patch add/copy depth amplification and recursive deletion.
