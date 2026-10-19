# T56 Independent Review: Pasteboard Source Lineage and Permission Gate

- Date: 2026-10-21 (Asia/Shanghai)
- Test checkout: `D:/openHarmonyScanner/worktrees/t56-independent-lineage-20261021`
- Branch: `codex/t56-independent-lineage-20261021`
- Scope: independently resolve the frozen D52 source's relationship to the current Pasteboard source and inspect the first source-level caller permission gate and official release refs.
- Changes: this report and its JSON companion only; no scanner, D56, source mirror, test, fixture, or expected output was edited.

## Decision

| Question | T56 result | What the evidence proves |
|---|---|---|
| D52 snapshot identity | **PASS** | Official GitCode old repository `master` is `dd22c7c...`; its tree and the two D52 source blobs match the frozen D52 record. |
| D52 to current repository ancestry | **PASS** | The official `distributeddatamgr_pasteboard` object store contains that exact D52 commit and tree, and `dd22c7c...` is an ancestor of current `e73747b...`. The new repository's `master` and `weekly_20261019` both point at `e73747b...`. |
| Repository rename/copy event | **NOT ESTABLISHED / NOT REQUIRED FOR COMMIT ANCESTRY** | Git object ancestry proves exact source history continuity. It does not prove an administrative repository rename or identify a separate copy/import event. No such event is needed to establish the source ancestry result. |
| Permission gate in frozen D52 source | **ABSENT IN REVIEWED GET PATH** | D52's stub dispatches to `GetPasteData`; its 2022 service implementation reads the caller's user-scoped clip without a visible permission decision. The D52 candidate anchor itself is only the `OnRemoteRequest` opening brace. |
| Earliest later getter gate found | **LOCATED** | Commit `e13a4ad3...` (2022-08-15) adds `CheckPastePermission` before the `GetPasteData` data read. It follows D52 and is an ancestor of current `e73747b...`. |
| Later gate evolution | **LOCATED** | `cedbaeb9...` (2022-08-30, !113) adds `HasPastePermission`; `721fecac...` (2024-03-23, !586) later adds explicit READ/SECURE `VerifyPermission(tokenId)` before `GetData`. These are distinct checks and should not be collapsed into a single “first gate.” |
| Official release presence | **PASS FOR V5+ TAGS CHECKED** | The gate is absent from `OpenHarmony-v4.1-Release` and present in `OpenHarmony-v5.0.0`, `v5.0.1`, `v5.0.2`, `v5.0.3`, `v5.1.0`, `v6.0`, and `v6.1-LTS` source tags checked. PR !586 is in the ancestry of the V5+ tags checked. |
| CVE-2025-27247 source-fix attribution | **PATCH IDENTIFIED; D52 ROOT-CAUSE MATCH UNKNOWN** | Official security bulletin `2025-06.md` identifies CVE-2025-27247, affected v5.0.3, and links PR !1106. Upstream fix `f27fb584...` removes the default-IME bundle allowlist / privilege bypass; merge `79e87227...` is in current ancestry. Backport `7ea52073...` is an ancestor of the official v5.0.3 source tag. This does not prove that D52’s generic method-entry candidate is this CVE’s root cause. |
| Specific product applicability | **UNKNOWN** | Official source refs/tags do not identify the product build, component revision, image, or installed device relevant to the D52 finding. |

**Disposition:** preserve D52 as an unassessed historical component candidate. Record the exact later source-path change and ancestry; do not label the candidate CVE-fixed, product-fixed, or product-vulnerable from these facts alone.

## Frozen objects and official history

The source-history review used full bare clones of the two official GitCode remotes, separate from the one-commit local source mirrors:

| Repository | Official remote | Local full-history review clone | Observed official refs |
|---|---|---|---|
| Old D52 repository | `https://gitcode.com/openharmony/miscservices_pasteboard.git` | `D:/OpenHarmony807/t56-miscservices-official.git` | `master` = `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` |
| Current repository | `https://gitcode.com/openharmony/distributeddatamgr_pasteboard.git` | `D:/OpenHarmony807/t56-distributeddatamgr-official.git` | `master`, `weekly_20261005`, `weekly_20261012`, `weekly_20261019` = `e73747b227104e6743e957ce31040edf58507221` |

| Frozen/current object | Commit | Tree | Relevant source objects |
|---|---|---|---|
| D52 snapshot in old repository | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` | `e374a0d61c9ec664ddd29fc17002797828c480ee` | core `pasteboard_service.cpp` blob `c380ac266a85edd818caa811f11b99722d351788`; stub `pasteboard_service_stub.cpp` blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b` |
| Same D52 snapshot in new repository | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` | `e374a0d61c9ec664ddd29fc17002797828c480ee` | Exact same commit/tree and source blob IDs |
| 2024 READ/SECURE permission-gate change | `721fecac75d9c51b0b145469abc6c9c78c17753e` | `947cb76b49ff4575f0fe3b8a5400558894bc5f47` | core blob `0a47eec7bf847aaafe6c97da08ba008cd8be37ca`; stub blob `75094b67321ff3d38e3db4377a2aab429e67c4c7` |
| Current source snapshot | `e73747b227104e6743e957ce31040edf58507221` | `4128cdf9ad11d393c30f2839f43419e97a5a466d` | core blob `fa6a08cdbaa18f34dcb6632babc70f22a700c860`; old service-stub path no longer exists in this tree |

Checks performed against the official GitCode objects:

1. `git cat-file -e dd22c7c...^{commit}` succeeds in the full current-repository history.
2. `git merge-base --is-ancestor dd22c7c... e73747b...` exits `0`.
3. `git rev-parse dd22c7c...^{tree}` in both repositories returns `e374a0d...`.
4. GitCode `ls-remote` shows the old remote's `master` still at D52's pinned commit and the new remote's current weekly refs at `e73747b...`.

This is direct commit-graph evidence of source ancestry despite the repository-name change. It is stronger than a filename/content similarity claim. It does not assert the repositories were administratively renamed.

The old `services/zidl/src/pasteboard_service_stub.cpp` path is removed by commit `44143ebd05d946229649865d675831126799c4fb` on 2025-03-28 (`pasteboard idl`). That change introduces `services/IPasteboardService.idl` and removes the handwritten service proxy/stub sources. Current Binder glue is generated; therefore absence of the old stub path at `e73747b...` is not evidence that the IPC route disappeared. The present service source still has `GetPasteData` / `GetPasteDataInner`; D53 separately binds the current IDL method code.

## D52 route and source change

At the exact D52 source snapshot:

1. `services/zidl/src/pasteboard_service_stub.cpp` maps `GET_PASTE_DATA` to `OnGetPasteData`.
2. `OnRemoteRequest` checks the interface descriptor and dispatches the handler. Its D52 candidate location, line 41, is the method's opening brace; the detector location does not itself identify an authorization expression.
3. `OnGetPasteData` calls the service's `GetPasteData` and serializes the returned parcelable.
4. D52's `services/core/src/pasteboard_service.cpp::GetPasteData` reads `clips_[userId]` into the output. The inspected function has no visible `VerifyPermission`/`CheckPermission` authorization decision. Its user mapping is identity scoping, not an allow/deny permission decision.

The earliest getter guard located after D52 is `e13a4ad3...` (2022-08-15, “剪贴板数据范围限制在应用内”). Its diff adds `CheckPastePermission` in `GetPasteData` after finding the clip and before copying it into the output, and applies the check to `HasPasteData` too. This is a focus/default-IME and share-option/app-identity check, not the later platform permission model. The check is source-verified as a D52 descendant and current-source ancestor.

On 2022-08-30, `cedbaeb9...` (!113, “inApp 默认输入法校验”) adds `HasPastePermission` in the getter path. This change is later than `e13a`; searching only `-S'HasPastePermission'` missed the earlier differently named `CheckPastePermission`.

The later explicit READ/SECURE caller permission gate is `721fecac...` (2024-03-23, merge PR !586). Its diff adds `VerifyPermission(tokenId)` before `GetData`:

- Date/message: `2024-03-23`, `!586 新增权限校验`.
- The new `VerifyPermission(tokenId)` checks caller `READ_PASTEBOARD` and `SECURE_PASTE`, recognizes the default IME as a privileged app, rejects invalid SDK-version lookup, and rejects a caller without an allowed grant at or above the configured SDK threshold. In particular, **when the SDK version is below that threshold and no grant is present, this conditional does not deny the request**; the helper can continue to `return true` (subject to its remaining logic). Ctrl+V and default-IME/permission paths are additional exceptions. Thus “guard exists” does not mean “all callers are denied without a grant.”
- `GetPasteData` calls the helper before `GetData`; a rejected caller returns `PasteboardError::E_NO_PERMISSION`.
- The helper also handles Ctrl+V/toast behavior. This is a source-level caller check on the traced data-return path, with explicit compatibility/privilege conditions; it is not a universal deny for every caller.

The checked `OpenHarmony-v4.1-Release` tag (`ae119620...`, tree `c89ca043...`) contains the older `CheckPastePermission`/`HasPastePermission` lineage and `IsDefaultIME`; it predates the explicit READ/SECURE `VerifyPermission` helper. `e13a` and `cedba` are ancestors of this tag; `721fec` is not. `OpenHarmony-v5.0.0-Release` (`8972d1c6...`, tree `f6550fb0...`) and v5.0.1 through v6.1-LTS checked tags contain the newer permission gate. Exact tag objects, peeled commits, and trees are in the JSON companion. These source refs establish content/ancestry only, not inclusion in a product image.

For CVE-2025-27247, the official Gitee OpenHarmony security bulletin at commit `3ab66b79...` names the vulnerability, affected repository/component and v5.0.3 scope, and links `distributeddatamgr_pasteboard` PR !1106. The source patch `f27fb584...` (2024-12-28) removes the default-IME bundle allowlist and the `isPrivilegeApp` contribution to the grant decision; merge `79e87227...` is in current ancestry. The 5.0.3 backport `7ea52073...` is an ancestor of peeled tag commit `d91a9b38...`; the v5.0.3 tag source no longer contains `IsDefaultIME`. Thus the official CVE patch lineage is identified. The advisory does not map the D52 detector’s generic `OnRemoteRequest` opening-brace anchor to the CVE root cause, and no target product build/image was supplied, so D52-candidate-to-CVE mapping and product fixed status remain UNKNOWN.

The current `e73747b...` `GetPasteDataInner` obtains `IPCSkeleton::GetCallingTokenID()`, calls `VerifyPermission(tokenId)`, and returns a permission-verification error before the subsequent `GetData` call if denied. It also has a developer-mode test-server exception. This current-source inspection is consistent with the historical gate's evolution, but does not replace the commit/release checks above.

The official advisory links PR !1106 and the source patch lineage is verified above. The advisory and patch still do not identify the D52 detector’s generic method-entry anchor as the CVE root cause; that candidate-to-CVE mapping remains unknown.

## Checklist for independent review of D56

Before accepting any D56 disposition or evidence delta, T56 should:

1. **Freeze the exact source objects.** Record D56's repository declaration, exact commit, tree, target file path, tree entry/blob OID, raw blob byte count and SHA-256. Recompute them with the official repository object store; do not pair a worktree-converted file hash with a raw Git blob OID.
2. **Prove lineage rather than infer from names.** Check whether D52 `dd22c7c...` is an ancestor of the exact D56 source commit. Record merge-base/ancestry output, remotes, branch/tag refs, and each relevant rename or deletion commit. If ancestry fails, report no-match/unknown and identify the missing source-history connection.
3. **Rebuild the exact request route at each endpoint.** At D52, bind transaction selector → `OnRemoteRequest` dispatch → `OnGetPasteData` → `GetPasteData` → parcel write. At post-IDL revisions, bind IDL method/code → generated or checked-in dispatch → current service method → data read → response serialization. Do not treat a method-opening-brace location as a root-cause statement.
4. **Compare every actual gate, not one symbol name.** Search all relevant historical spellings, then inspect diffs and predecessors (including `CheckPastePermission`, `HasPastePermission`, and `VerifyPermission`). Confirm each guard dominates the data read/return; inspect token identity, permissions, SDK compatibility, Ctrl+V and test/developer bypasses, and sibling paths. A pickaxe search for only the later helper name can miss earlier gates.
5. **Separate patch attribution from candidate mapping.** Follow the advisory’s exact PR link and verify upstream fix, merge/backport and tag ancestry. Then independently match the advisory root cause to the scanner candidate and product build. A proven official patch lineage does not establish that a broad D52 method-entry candidate is the CVE root cause or that a product image includes the patch.
6. **Bind claims to release source refs.** For every relevant official tag/branch, record the ref's exact commit/tree and either prove the fixing commit is an ancestor or inspect the exact source content when release history was cherry-picked/split. A source tag still does not establish inclusion in the target device image.
7. **Keep product scope independent.** Require a concrete product build fingerprint/output manifest, component source revision, installed-device provenance, and authorized impact/fix retest before changing product applicability from UNKNOWN.
8. **Use positive and negative source controls.** Keep the D52 no-gate source as a historical positive, a later guarded equivalent source as a source-path negative only after exact route equivalence is established, and unrelated/metadata IPC handlers as negative controls. Synthetic controls cannot stand in for the exact source commit pair.
9. **Preserve uncertainty on gaps.** If generated IPC source, authorization inherited from a framework layer, caller path, advisory matching, release ancestry, or product evidence is missing, report the precise missing object and retain UNKNOWN; do not infer safe/miss from partial parsing or absent code in a different repository snapshot.
10. **Check scope before merge.** Limit T56 changes to its assigned report/checklist and machine-readable companion. Review `git diff --check` and the exact changed-path list; do not alter D56 implementation files or shared scanner policy.

## Reproduction commands

```powershell
git --git-dir=D:/OpenHarmony807/t56-miscservices-official.git cat-file -e 'dd22c7cb5e5f207a6c38c50f45b7369ee8575840^{tree}'
git --git-dir=D:/OpenHarmony807/t56-distributeddatamgr-official.git cat-file -e 'dd22c7cb5e5f207a6c38c50f45b7369ee8575840^{tree}'
git --git-dir=D:/OpenHarmony807/t56-distributeddatamgr-official.git merge-base --is-ancestor dd22c7cb5e5f207a6c38c50f45b7369ee8575840 e73747b227104e6743e957ce31040edf58507221
git --git-dir=D:/OpenHarmony807/t56-distributeddatamgr-official.git show --format=fuller e13a4ad3b72be7650ccb75de560790c04fa84795 -- services/core/src/pasteboard_service.cpp
git --git-dir=D:/OpenHarmony807/t56-distributeddatamgr-official.git show --format=fuller cedbaeb9f55f524fb93c9d76ec06a4dc7b213ba7 -- services/core/src/pasteboard_service.cpp
git --git-dir=D:/OpenHarmony807/t56-distributeddatamgr-official.git show --format=fuller 721fecac75d9c51b0b145469abc6c9c78c17753e -- services/core/src/pasteboard_service.cpp
git --git-dir=D:/OpenHarmony807/t56-distributeddatamgr-official.git grep -n -E 'VerifyPermission\(tokenId\)|isReadGrant' OpenHarmony-v5.0.0-Release -- services/core/src/pasteboard_service.cpp
git --git-dir=D:/OpenHarmony807/t56-distributeddatamgr-official.git grep -n -E 'VerifyPermission\(tokenId\)|isReadGrant' OpenHarmony-v5.0.3-Release -- services/core/src/pasteboard_service.cpp
git ls-remote --heads --tags https://gitcode.com/openharmony/miscservices_pasteboard.git
git ls-remote --heads --tags https://gitcode.com/openharmony/distributeddatamgr_pasteboard.git
```

Machine-readable evidence: [T56_PASTEBOARD_LINEAGE_REVIEW_20261021.json](T56_PASTEBOARD_LINEAGE_REVIEW_20261021.json).
