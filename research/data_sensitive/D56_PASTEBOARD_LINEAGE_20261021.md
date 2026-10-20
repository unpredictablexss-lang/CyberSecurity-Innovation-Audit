# D56 Pasteboard lineage and version boundary

Date: 2026-10-21 (Asia/Shanghai)

## Result

The historical D52 snapshot is formally in the Git object ancestry of the current `distributeddatamgr_pasteboard` source. Its commit object and tree are identical across the old and current repository mirrors: `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` / `e374a0d61c9ec664ddd29fc17002797828c480ee`. The current reference `e73747b227104e6743e957ce31040edf58507221` descends from it. This proves source history continuity; it does not, by itself, prove which binaries or device images contain a later change.

D52's historical candidate points at `services/zidl/src/pasteboard_service_stub.cpp` line 41, the opening brace of `PasteboardServiceStub::OnRemoteRequest`. In that snapshot the `GET_PASTE_DATA` transaction dispatches to `OnGetPasteData`, then calls the core `GetPasteData(PasteData&)`. That getter obtains the current user's clip and copies it to the output without a permission check. The D52 location is therefore a coarse method-level candidate; the missing guard is in the core getter, not established by the brace at line 41.

In the checked complete GitCode mirror refs, the earliest verified source-side read gate is the 2022 change titled `剪贴板数据范围限制在应用内`: commit `e13a4ad3b72be7650ccb75de560790c04fa84795` (author date 2022-08-15; commit date 2022-08-27). Its parent is `9fd07a8a7c5b9ef2087a551e90efadf838078b04`, and it adds `CheckPastePermission` before the getter copies the clip into its result. The same tree and patch also appear under commit `ae45d0c8e1a489defb8135041436c3e428436e05` on a parallel parent; both are reachable in the checked release refs. This gate checks focus/default-IME eligibility and the app's `ShareOption`, including an app-id match for `InApp`. Commit `cedbaeb9f55f524fb93c9d76ec06a4dc7b213ba7` (2022-08-30) later changes the helper to `HasPastePermission` and adjusts the logic. The v4.1 and later checked release tags contain the gated source. Commit `721fecac75d9c51b0b145469abc6c9c78c17753e` (2024-03-23, !586) later introduces the `VerifyPermission` form and its default-IME exception; it is a later permission implementation change. This is the earliest gate found by the specified `--all --reverse -S'CheckPastePermission'` history query on the fetched mirror refs, not a claim that no earlier gate could exist outside those refs.

The official June 2025 security bulletin maps CVE-2025-27247 to “剪切板模块权限绕过漏洞”, names `OpenHarmony-v5.0.3-Release` as affected, and links the fix to PR !1106 / the `5.0.3.x` patch line. The PR's source change removes the `IsDefaultIME` privilege allowance from `VerifyPermission`; the 5.0.3 release branch backport is `7ea520735f926b1f4720390e3d56f353642dbfa7`. The corresponding upstream change is `f27fb584ee3dd14ec38b66d64e50cd7e70325bca`. The upstream fix is an ancestor of current `e737`.

The checked v5.0.0, v5.0.1 and v5.0.2 tag snapshots still contain `VerifyPermission` and `IsDefaultIME`; v4.1 contains `HasPastePermission` and `IsDefaultIME`. The checked v5.0.3 tag snapshot has the removal, consistent with the backport commit. However, the bulletin still classifies the v5.0.3 release family as affected and points to `5.0.3.x`. This evidence supports a source-level correction in the tagged branch and an affected release family, but does not identify the exact patch level or source fingerprint of any product image. Product fixed/unfixed status is therefore **unknown without the device build fingerprint and security patch level**. The advisory does not map CVE-2025-27247 to the D52 line-41 detector location or its exact old blob.

The handwritten stub is removed in the IDL migration merge `a8427a6b548db7a0f64f5d3f297f755ec4db804c` (!1333, 2025-03-29), with first parent `333c73f50ba74cd612a2f15aa679ec963e8ba411`; that parent contains the stub and the merge deletes it while adding `services/IPasteboardService.idl`. The current service has a core `GetPasteDataInner` path that checks `VerifyPermission(tokenId)` and returns a permission error on failure, with an explicit developer-mode test-server exception. The current helper also permits native/shell token classes and Ctrl+V flow; conclusions about authorization semantics must account for those rules.

A separate `67ebf975e802cd1f7c25c9d225537fc10dabb987` change adds a local-caller restriction to `OnRemoteRequest`. It is on the 5.1.0 release branch and is not an ancestor of `e737`; it is not the CVE permission fix and should not be used as evidence that the D52 candidate was fixed in current master.

## Pinned evidence

| Claim | Commit / tree / blob | Evidence |
|---|---|---|
| D52 source snapshot | commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`; tree `e374a0d61c9ec664ddd29fc17002797828c480ee`; stub blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`; core getter blob `c380ac266a85edd818caa811f11b99722d351788` | Commit object and tree verified in both official mirrors; old source calls core getter without a gate |
| Current official master snapshot | commit `e73747b227104e6743e957ce31040edf58507221`; tree `4128cdf9ad11d393c30f2839f43419e97a5a466d`; core blob `fa6a08cdbaa18f34dcb6632babc70f22a700c860` | `dd22` and `f27` are ancestors; current core path checks `VerifyPermission` |
| Earliest verified gate in fetched refs | `e13a4ad3b72be7650ccb75de560790c04fa84795`; same tree `a4969d1d7e4186603696c1de7cba2b9f686f7b3d`; parent `9fd07a8a7c5b9ef2087a551e90efadf838078b04`; parallel same-tree commit `ae45d0c8e1a489defb8135041436c3e428436e05` | Adds `CheckPastePermission` in core getter before result copy; v4.1 and subsequent checked release tags contain it |
| Helper evolution | `cedbaeb9f55f524fb93c9d76ec06a4dc7b213ba7` | Later changes the getter helper to `HasPastePermission`; not the first source-side read gate |
| Later verifier change | `721fecac75d9c51b0b145469abc6c9c78c17753e` | !586; later `VerifyPermission` implementation, including default-IME exception |
| CVE upstream source fix | `f27fb584ee3dd14ec38b66d64e50cd7e70325bca`; tree `1fc6df6efc5a5f9c9b072a570c6486f62c0478cd` | Removes default-IME privilege allowance; ancestor of current master |
| 5.0.3 backport | `7ea520735f926b1f4720390e3d56f353642dbfa7`; tree `69a592799ce6ed3877fe5a571aebcda90d355864` | Contained by official `OpenHarmony-v5.0.3-Release` tag |
| Stub-to-IDL migration | merge `a8427a6b548db7a0f64f5d3f297f755ec4db804c`; first parent `333c73f50ba74cd612a2f15aa679ec963e8ba411` | First-parent diff deletes handwritten stub and adds IDL service definition |
| Official advisory source | security repo master `3ab66b799f5fe23b58ad7e1793f576727710bc87`; tree `180a31aa568571587a704f6ccf6ada86b3f3ae8a`; advisory blob `3d29b0704275db717d19a0f63bf2ca896801834b`; SHA-256 `618bd902a93f12702e3b0c92599a17e914352a13c781b2e1caa914050fedb45e` | `zh/security-disclosure/2025/2025-06.md`, CVE row identifies affected release family and PR !1106 |
| Separate local-caller change | `67ebf975e802cd1f7c25c9d225537fc10dabb987` | 5.1.0 branch only; not ancestor of current master and not the CVE fix |

The old D52 stub has 6,288 bytes and SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`. The old getter has 17,335 bytes and SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`. The current core file has 245,309 bytes and SHA-256 `2f18a183e6eaa75f996d221fac735703a534d00cf294d122cbc6637bb28fa78a`.

## Tag comparison

| Tag | Peeled commit | Getter semantics observed |
|---|---|---|
| v4.1 | `ae11962072207bd4b444631ac1ce818560e68327` | `HasPastePermission`; default-IME path present |
| v5.0.0 | `8972d1c68ed74839e26999abdac74a64584d0b92` | `VerifyPermission`; `IsDefaultIME` present |
| v5.0.1 | `6102fdd1b2e5f954bad1718d9f96a11efb215886` | `VerifyPermission`; `IsDefaultIME` present |
| v5.0.2 | `fbed84bb3608e7b41c41309a59420d162ae086c9` | `VerifyPermission`; `IsDefaultIME` present |
| v5.0.3 | `d91a9b38fc801a269dc684c0c9735dc68ddbb0b8` | `VerifyPermission`; `IsDefaultIME` removed in the checked tagged source |

These are repository tag contents, not a claim about every vendor image carrying those marketing version labels.

## Reproduction

All repositories below were fetched independently as full mirrors; neither the shallow OpenHarmony807 checkout nor scanner source files were changed. To scope “earliest gate” to the refs actually inspected, the source search used `git log --all --reverse -S'CheckPastePermission' -- services/core/src/pasteboard_service.cpp` and confirmed both same-tree commit copies and their release-tag reachability.

```powershell
git clone --mirror https://gitcode.com/openharmony/miscservices_pasteboard.git miscservices_pasteboard.git
git clone --mirror https://gitcode.com/openharmony/distributeddatamgr_pasteboard.git distributeddatamgr_pasteboard.git
git clone --mirror https://gitee.com/openharmony/security.git security.git

git --git-dir=distributeddatamgr_pasteboard.git rev-parse --is-shallow-repository
git --git-dir=distributeddatamgr_pasteboard.git rev-list --count --all
git --git-dir=distributeddatamgr_pasteboard.git cat-file -p dd22c7cb5e5f207a6c38c50f45b7369ee8575840
git --git-dir=distributeddatamgr_pasteboard.git merge-base --is-ancestor dd22c7cb5e5f207a6c38c50f45b7369ee8575840 e73747b227104e6743e957ce31040edf58507221
git --git-dir=distributeddatamgr_pasteboard.git merge-base --is-ancestor f27fb584ee3dd14ec38b66d64e50cd7e70325bca e73747b227104e6743e957ce31040edf58507221
git --git-dir=distributeddatamgr_pasteboard.git log --all --reverse -S'CheckPastePermission' --format='%H %ad %s' --date=iso-strict -- services/core/src/pasteboard_service.cpp
git --git-dir=distributeddatamgr_pasteboard.git show e13a4ad3b72be7650ccb75de560790c04fa84795 -- services/core/src/pasteboard_service.cpp
git --git-dir=distributeddatamgr_pasteboard.git diff a8427a6b548db7a0f64f5d3f297f755ec4db804c^1 a8427a6b548db7a0f64f5d3f297f755ec4db804c --name-status
git --git-dir=distributeddatamgr_pasteboard.git show e73747b227104e6743e957ce31040edf58507221:services/core/src/pasteboard_service.cpp

git --git-dir=security.git show 3ab66b799f5fe23b58ad7e1793f576727710bc87:zh/security-disclosure/2025/2025-06.md
```

For blob checks, use `git cat-file blob <commit>:<path>`, save the bytes without newline conversion, then run `git hash-object <file>` and SHA-256 (`Get-FileHash -Algorithm SHA256`). Commit/tree/blob IDs are Git object identities; SHA-256 values in this report are SHA-256 of file bytes.

## Scope and limits

- Official source-history sources: Gitcode mirrors for the two component repositories; official OpenHarmony Gitee security repository for the advisory. Repo URLs: `https://gitcode.com/openharmony/miscservices_pasteboard`, `https://gitcode.com/openharmony/distributeddatamgr_pasteboard`, `https://gitee.com/openharmony/security`.
- Full mirror fetches were used. This research does not infer missing history from the local shallow OpenHarmony807 clone.
- The report establishes source lineage, tag contents, and a source correction path. It does not verify shipped firmware, downstream vendor forks, patch installation, or all configurations.
- No scanner implementation files were changed. D56 files are report artifacts only.
