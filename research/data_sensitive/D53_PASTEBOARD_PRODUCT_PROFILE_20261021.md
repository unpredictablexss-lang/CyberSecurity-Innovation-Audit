# D53 Pasteboard product profile and caller permission evidence

Date: 2026-10-21 (Asia/Shanghai)

## Assessment

The current source snapshot implements a caller-side permission decision on the `GetPasteData` service path. The source and product configuration snapshots identify several HiHope product definitions whose inherited product profiles directly include the `pasteboard` component. This establishes source/config correlation only. **Applicability to a specific built or installed product remains unknown** because the local evidence set has no product build fingerprint, compiled image, build output manifest, or installed-device record.

The machine-readable companion records Git commit/tree and per-file blob plus SHA-256 identities: [D53 JSON](D53_PASTEBOARD_PRODUCT_PROFILE_20261021.json). File SHA-256 and byte counts are calculated over raw Git blob bytes (`git cat-file blob <oid>`), not working-tree files; all 31 file entries were mechanically checked against their path OID and recomputed raw blob digest.

## Source repositories

| Repository | HEAD | Tree | Worktree |
|---|---|---|---|
| `distributeddatamgr_pasteboard` | `e73747b227104e6743e957ce31040edf58507221` | `4128cdf9ad11d393c30f2839f43419e97a5a466d` | clean |
| `productdefine_common` | `c9317af4074bf0e445fe3fc3979e53c470687153` | `71f1c83472fbf4b0360bf9fbde23572c529cef21` | clean |
| `vendor_hihope` | `b40eabbe69943126c65df1f9ff28057f56e93e46` | `aa95785ef84ddde8d1c3622e2c2d80d6b388caeb` | clean |
| `build` | `6b6d6533967db07e8e7d40d140fc63d0faabacbd` | `d58b57c4bc6273a51e182a1014eea26ae60df028` | clean |

These are current local mirror checkouts, not a verified unified product build manifest. The build repository is included because it owns component and compilation whitelists; `device_hihope` is not used as a substitute for build metadata.

## SA ownership and process setup

At pasteboard HEAD above, `profile/3701.json` identifies process `pasteboard_service`, SA ID 3701 and `libpasteboard_service.z.so`. `run-on-create` is false; SA profile requests on-demand start on `deviceonline=on`, and sets `distributed=false`. `profile/BUILD.gn` packages this profile under `part_name = "pasteboard"`.

`etc/init/BUILD.gn` packages `pasteboardservice.cfg` as init configuration under the same `pasteboard` part. The cfg runs `/system/bin/sa_main /system/profile/pasteboard_service.json` as uid `pasteboard`, gids `pasteboard`, `shell`, `dfs_share`, `user_data_rw`, with `DAC_READ_SEARCH` and SELinux label `u:r:pasteboard_service:s0`. Its service permission list includes `DISTRIBUTED_DATASYNC`, `ACCESS_SERVICE_DM`, `ACCESS_SERVICE_DP`, `PROXY_AUTHORIZATION_URI`, `GET_BUNDLE_INFO`, `INPUT_MONITORING`, `MONITOR_DEVICE_NETWORK_STATE`, `PERMISSION_USED_STATS`, `GRANT_URI_PERMISSION_PRIVILEGED`, `MANAGE_LOCAL_ACCOUNTS`, `MANAGE_SECURE_SETTINGS`, `INTERACT_ACROSS_LOCAL_ACCOUNTS`, `REPORT_RESOURCE_SCHEDULE_EVENT`, `GET_WIFI_INFO`, and `MANAGE_WIFI_CONNECTION`. The `permission_acls` subset is `INPUT_MONITORING`, `MONITOR_DEVICE_NETWORK_STATE`, `GRANT_URI_PERMISSION_PRIVILEGED`, `GET_WIFI_INFO`, and `MANAGE_WIFI_CONNECTION`.

Those cfg entries describe the service process configuration. They are not the caller permission gate for retrieving paste data. There is also a legacy `pasteboardservice.rc` in the repository describing boot start as `system` user and groups `system,shell`; the inspected `etc/init/BUILD.gn` explicitly packages the `.cfg`. Without a build manifest, this source-level packaging relationship does not establish which init artifacts are installed in a product image.

## Caller authorization path for GetPasteData

`services/IPasteboardService.idl` declares `GetPasteData` as IPC code 200. `PasteboardService` derives from `SystemAbility` and generated `PasteboardServiceStub`; the service is registered via `MakeAndRegisterAbility` and published. The generated Binder glue is not checked in as a normal source file in this snapshot, so this report binds the declared interface to the implementation method, not to generated dispatch source lines.

In `services/core/src/pasteboard_service.cpp`:

1. `PasteboardService::GetPasteData` at lines 1316–1345 calls `GetPasteDataInner`.
2. `GetPasteDataInner` at lines 1347–1375 obtains the Binder caller token using `IPCSkeleton::GetCallingTokenID()` at line 1353 and calls `VerifyPermission(tokenId)` at line 1358. A false result returns `PERMISSION_VERIFICATION_ERROR` before the data fetch (`GetData`) at line 1371.
3. The only explicit bypass in this guard is the developer-mode test-server condition, `developerMode && setPasteDataUId_ == TEST_SERVER_UID`, at lines 1356–1358.
4. `VerifyPermission` at lines 1020–1054 checks `ohos.permission.READ_PASTEBOARD` and `ohos.permission.SECURE_PASTE` for the caller token. Either grant succeeds. It also allows native or shell token types and a recognized Ctrl+V action. If none applies, SDK version 12 or newer fails closed; versions below 12 fall through to true. Invalid SDK version returns false.

Accordingly, the source contains a caller-side authorization decision, with token type, Ctrl+V, developer test-mode, and SDK-version behavior that should be represented in any semantic assessment. This evidence does not show that a particular installed build contains this source revision.

## Product definition correlation

`productdefine_common` component templates directly contain `pasteboard` at:

- `inherit/2in1.json` line 507
- `inherit/phone.json` line 72
- `inherit/rich.json` line 75
- `inherit/tablet.json` line 135
- `inherit/wearable.json` line 268

The inspected HiHope `config.json` files inherit those templates as follows:

| HiHope product | Type / board | Inherited profile with direct pasteboard component |
|---|---|---|
| `2in1_core_system` | standard / rk3568 | `inherit/2in1.json` |
| `dayu210` | standard / rk3588 | `inherit/rich.json` |
| `default_core_system` | standard / rk3568 | `inherit/phone.json` |
| `rk3568` | standard / rk3568 | `inherit/rich.json` |
| `tablet_core_system` | standard / rk3568 | `inherit/tablet.json` |
| `wearable` | standard / rk3568 | `inherit/wearable.json` |

The other inspected HiHope definitions do not directly inherit a template with a pasteboard component: `ipcamera_core_system` uses `ipcamera.json`; `tv` uses `tv.json`; `rk3568_mini_system` uses `base/standard_system.json`; NearLink and Neptune configs declare no inherited product profile. This is a direct-template check and does not establish full transitive component resolution for a build.

## Build evidence and limitations

The mirror root contains `repos`, `logs`, `scan-results`, `gitcode-807.xml`, `progress.json`, and `projects.csv`; a targeted search found no product image, build.ninja output, build.prop, or installed-product manifest. `scan-results/build/report.md` says C/D are blocked and not production enabled and labels the run as research candidates. That report is not a compiled product artifact. The snapshot therefore cannot establish a concrete HiHope model, product configuration, software fingerprint, or shipped code revision.

Minimum external evidence needed to resolve product applicability: a specific product/build identifier and its build fingerprint, plus the corresponding build output manifest or image provenance binding the resolved product parts and pasteboard repository revision. Runtime confirmation would additionally require an installed-device manifest or equivalent device-side evidence.

## Reproduction commands

Commands were read-only against source mirrors; paths are Windows PowerShell paths.

```powershell
git -C D:\OpenHarmony807\repos\distributeddatamgr_pasteboard rev-parse HEAD 'HEAD^{tree}'
git -C D:\OpenHarmony807\repos\productdefine_common rev-parse HEAD 'HEAD^{tree}'
git -C D:\OpenHarmony807\repos\vendor_hihope rev-parse HEAD 'HEAD^{tree}'
git -C D:\OpenHarmony807\repos\device_hihope rev-parse HEAD 'HEAD^{tree}'
git -C D:\OpenHarmony807\repos\distributeddatamgr_pasteboard show HEAD:services/core/src/pasteboard_service.cpp
rg -n 'GetPasteDataInner|VerifyPermission|GetPasteData\(' D:\OpenHarmony807\repos\distributeddatamgr_pasteboard\services\core\src\pasteboard_service.cpp D:\OpenHarmony807\repos\distributeddatamgr_pasteboard\services\IPasteboardService.idl
rg -n '"component": "pasteboard"' D:\OpenHarmony807\repos\productdefine_common\inherit
rg --files D:\OpenHarmony807 | rg '(^|\\)(out|build|images)(\\|$)|build\.ninja$|product\.img$|build\.prop$|manifest\.xml$'
```

## Scope

Only the two requested D53 evidence files are intended to change. No scanner rule, ownership, or configuration changes were made. No product build or runtime test was available; this task is source/config evidence research.

## Build whitelist evidence and evidence boundary

The `build` repository at the recorded HEAD contains `indep_component_whitelist.json`, with `pasteboard` and `distributeddatamgr_pasteboard` entries, and `component_compilation_whitelist.json`, with pasteboard related targets including `pasteboard_client`, the pasteboard dialog HAP, and two NAPI tests. Their blob OIDs, raw Git byte lengths, and SHA-256 digests are in the JSON. These whitelist entries show build-system recognition/target inclusion metadata; they do not identify an executed product build.

The D52 historical candidate came from a different source repository and revision: `openharmony/miscservices_pasteboard@dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`, file `services/zidl/src/pasteboard_service_stub.cpp`. The current snapshot is `openharmony/distributeddatamgr_pasteboard@e73747b227104e6743e957ce31040edf58507221`, tree `4128cdf9ad11d393c30f2839f43419e97a5a466d`. Repository migration/ancestry between these source identities has not been verified. The current revision's permission guard cannot by itself establish that the historical candidate was fixed, migrated, or absent from any concrete product.

The JSON `files` array is the machine-checkable provenance table. For each entry, `blob` is the path object at the recorded repository HEAD; `sha256` and `bytes` refer to the raw object bytes returned by `git cat-file blob <blob>`. Working-tree newline conversion values are not used.
