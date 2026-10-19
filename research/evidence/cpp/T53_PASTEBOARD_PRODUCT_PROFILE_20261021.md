# T53 independent acceptance: Pasteboard product profile and caller permission

- Date: 2026-10-21 (Asia/Shanghai)
- Independent checkout: `D:/openHarmonyScanner/worktrees/t51-pasteboard-independent-20261020`
- Reviewed D53 evidence commit: `3f1c9aa72f245d7d7c6312970f2c3bdd11c3b8f2` (includes the final reproduction-command correction)
- D53 developer report paths: `research/data_sensitive/D53_PASTEBOARD_PRODUCT_PROFILE_20261021.{md,json}`
- Scope: independent read-only verification of source and product configuration Git objects, service profile/init permissions, caller authorization path, and build/product applicability.
- No detector, test, fixture, expected output, or configuration files were changed in this checkout.

## Decision

| Question | T53 result | Evidence limit |
|---|---|---|
| D53 source/object identity | **PASS after revision** | All four requested repository HEAD/tree identities match. All 31 final D53 file entries independently match their path blob, raw Git byte count, and raw Git SHA-256. |
| SA/profile and init process configuration | **PASS** | SA 3701 and `pasteboard_service` profile are bound to exact Git objects. The packaged init cfg runs the service with its configured uid/gids, capabilities and service permissions. |
| Caller permission check for current source | **PRESENT** | Current `GetPasteDataInner` calls `VerifyPermission` on the Binder caller token before fetching data, with documented token, Ctrl+V, SDK and developer test-server branches. |
| Product configuration correlation | **PRESENT FOR MULTIPLE DEFINITIONS** | Several HiHope product configs inherit templates that directly include `pasteboard`. These are product definitions and whitelist metadata, not evidence of an executed image. |
| Concrete single product build / installed applicability | **UNKNOWN** | No image, build output manifest, product fingerprint, or installed-device record was found. The repo snapshots do not prove which source revisions were built or shipped. |
| Relationship to historical D52 candidate | **UNKNOWN** | D52's exact source is in `miscservices_pasteboard`; the current source is in `distributeddatamgr_pasteboard`. Migration/ancestry between them was not established. The current guard cannot prove the historical candidate was fixed or absent from a product. |

## D53 report cross-check

The D53 evidence was frozen in commit `6a16f8d8c3013ec4f208a3ae3a64751a5e9611d9` and received a final Markdown reproduction-command correction in `3f1c9aa72f245d7d7c6312970f2c3bdd11c3b8f2`; the JSON evidence did not change in that last commit. The final D53 change is documentation-only. Its JSON parsed with `python -m json.tool`, and `git diff --check` passed for both commits. I independently recomputed each listed file's object identity with `git rev-parse HEAD:<path>` and computed bytes/SHA-256 from `git cat-file blob <blob>`. Result: **31 entries checked, 0 mismatches**. All four repository HEADs and trees also matched:

| Repository | HEAD | Tree |
|---|---|---|
| `distributeddatamgr_pasteboard` | `e73747b227104e6743e957ce31040edf58507221` | `4128cdf9ad11d393c30f2839f43419e97a5a466d` |
| `build` | `6b6d6533967db07e8e7d40d140fc63d0faabacbd` | `d58b57c4bc6273a51e182a1014eea26ae60df028` |
| `productdefine_common` | `c9317af4074bf0e445fe3fc3979e53c470687153` | `71f1c83472fbf4b0360bf9fbde23572c529cef21` |
| `vendor_hihope` | `b40eabbe69943126c65df1f9ff28057f56e93e46` | `aa95785ef84ddde8d1c3622e2c2d80d6b388caeb` |

The first D53 draft (`d3b517c0a0ede0389e4fa43eeea7b089c63cb54e`) recorded `vendor_hihope` config byte counts and SHA-256 from CRLF-converted worktree files while labeling them with the matching Git blob OIDs. For example, `rk3568/config.json` was reported as 11,026 bytes / SHA-256 `361502c686dd84100fc63d65d87885e953a9fb78b3b67aa3418729ab58214448`; the pinned Git blob is 10,569 bytes / SHA-256 `46dc640a6ca988687245de967f4e2ec3aebd20ed3423472c48b89bc845c28408`. The revised D53 JSON now declares raw Git blob bytes and corrects all 31 entries. It also adds the requested `build` repository and its whitelist objects; `device_hihope` is no longer substituted for `build`.

The last D53 Markdown correction replaced the stale `device_hihope` `rev-parse` command with the requested `build` repository command. The final reproduction block now matches the four-repository scope and JSON.

## SA 3701 profile and init process permissions

At `distributeddatamgr_pasteboard@e73747b...`, `profile/3701.json` names process `pasteboard_service`, SA ID `3701`, and library `libpasteboard_service.z.so`. `run-on-create` is false, `distributed` is false, and the profile requests on-demand start for `deviceonline=on`. `profile/BUILD.gn` packages this profile under `part_name = "pasteboard"`.

`etc/init/BUILD.gn` packages `etc/init/pasteboardservice.cfg` under the same part. The cfg starts `/system/bin/sa_main /system/profile/pasteboard_service.json` as uid `pasteboard`, gids `pasteboard`, `shell`, `dfs_share`, and `user_data_rw`; it sets `DAC_READ_SEARCH` and SELinux label `u:r:pasteboard_service:s0`.

The cfg contains 15 service-process permissions and a five-entry `permission_acls` subset. Neither list contains `ohos.permission.READ_PASTEBOARD`. These are service process credentials/grants in init configuration; they are not the permission decision for a Binder caller requesting paste data. The current caller permission decision is in the service implementation described below. The repository also has a legacy `.rc` file, but `etc/init/BUILD.gn` packages the `.cfg`; without a product build manifest this does not prove which init artifact is present in an image.

Key raw Git object identities (the complete 31-entry table is in the JSON companion):

| Repository path | Blob | Raw bytes | SHA-256 |
|---|---|---:|---|
| `pasteboard/profile/3701.json` | `1d6310875099c4f7557639564fc849c598bbf790` | 416 | `35671403dc3be890e47a6f75f2d390ba2e6a18c87e695a657ddde4b5f9fa63ac` |
| `pasteboard/etc/init/pasteboardservice.cfg` | `bad8c665a6aaec041bfd70482ff8a61143493172` | 1,774 | `94462316b2eb65c47eda973c86df79f1678f34e49340f6675e43dac36a97aa5a` |
| `pasteboard/services/core/src/pasteboard_service.cpp` | `fa6a08cdbaa18f34dcb6632babc70f22a700c860` | 245,309 | `2f18a183e6eaa75f996d221fac735703a534d00cf294d122cbc6637bb28fa78a` |

## Current caller authorization path

The current `services/IPasteboardService.idl` declares `GetPasteData` as IPC code 200. Its generated Binder glue is not checked in as a normal source file, so the source review binds the declared method to the service implementation rather than claiming a verified generated dispatch body.

In the current `services/core/src/pasteboard_service.cpp`:

1. `PasteboardService::GetPasteData` (lines 1316–1345) calls `GetPasteDataInner`.
2. `GetPasteDataInner` obtains `IPCSkeleton::GetCallingTokenID()` at line 1353 and calls `VerifyPermission(tokenId)` at line 1358. If verification fails, it returns `PERMISSION_VERIFICATION_ERROR` before `GetData` at line 1371.
3. The explicit test bypass is guarded by developer mode and `setPasteDataUId_ == TEST_SERVER_UID` at lines 1356–1358.
4. `VerifyPermission` (lines 1020–1054) checks caller-token grants for `ohos.permission.READ_PASTEBOARD` or `ohos.permission.SECURE_PASTE`. It also allows native or shell token types and a recognized Ctrl+V action. With none of these, SDK version 12 or newer fails closed; older SDK versions fall through to true. Invalid SDK version returns false.

Thus, the current source has a caller-side permission decision. This source snapshot does not prove that the same code is in any built or installed product.

## Product definitions and build evidence

Five shared product templates contain `pasteboard`: `inherit/2in1.json`, `inherit/phone.json`, `inherit/rich.json`, `inherit/tablet.json`, and `inherit/wearable.json`. The current HiHope definitions that inherit one of those profiles include `2in1_core_system`, `dayu210`, `default_core_system`, `rk3568`, `tablet_core_system`, and `wearable`. Other inspected definitions use templates without a direct `pasteboard` entry or declare no inherited profile. This confirms multiple configuration-level associations, rather than one uniquely identified product build.

The requested `build` repo is pinned at `6b6d6533967db07e8e7d40d140fc63d0faabacbd` / tree `d58b57c4bc6273a51e182a1014eea26ae60df028`. Its `indep_component_whitelist.json` lists `pasteboard` and `distributeddatamgr_pasteboard`; `component_compilation_whitelist.json` has pasteboard-related targets, including the pasteboard client, dialog HAP, and NAPI tests. These are build-system allowlist/target metadata, not evidence that a product build executed.

The local snapshot has source repositories, logs, and scan reports, but no identified product image, build output manifest, product fingerprint, or installed-device record. The research scan report itself says C/D are blocked and not production enabled; it is not build provenance. Therefore **product applicability remains unknown**, even though some HiHope product definitions list the component.

## D52 historical source versus current source

D52's candidate source is pinned to the different repository `openharmony/miscservices_pasteboard@dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`. In that historical source, `services/zidl/src/pasteboard_service_stub.cpp` has blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, 6,288 bytes, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`. Its `OnGetPasteData` body obtains data with `GetPasteData(pasteData)` and writes the parcel; that path has no explicit caller `VerifyPermission` guard. The matching historical core file is blob `c380ac266a85edd818caa811f11b99722d351788`, 17,335 bytes, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`; its `PasteboardService::GetPasteData(PasteData&)` reads the user clip without this current permission guard.

The current component snapshot is `openharmony/distributeddatamgr_pasteboard@e73747b227104e6743e957ce31040edf58507221`, tree `4128cdf9ad11d393c30f2839f43419e97a5a466d`, with a different interface/API shape and the caller guard in `GetPasteDataInner`. No repository migration or ancestry proof connects the two. Do not infer that the D52 historical case is fixed, migrated, or absent from any specific product based on the current snapshot alone.

## Reproduction and final status

The independent object check used `git rev-parse HEAD`, `git rev-parse HEAD^{tree}`, `git rev-parse HEAD:<path>`, and `git cat-file blob <blob_oid>` for each object. The D53 final JSON reports 31 file entries; all 31 object IDs, raw sizes, and SHA-256 values matched independently. JSON parsing and D53 frozen commit diff checks passed. This task is evidence-only; no product build or runtime permission test was available or run.

Machine-readable counterpart: [T53 JSON](T53_PASTEBOARD_PRODUCT_PROFILE_20261021.json).
