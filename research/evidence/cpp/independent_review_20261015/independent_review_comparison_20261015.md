# A 线 shared_ptr 独立复核逐项对照

- 独立 reviewer：Codex independent reviewer
- 盲审冻结：`blind_review_labels_frozen_20261015.json`，SHA-256 `21104D9B9827C2877482A73B3018C43DAD9ABBDF63020E2C2DF35A3AAE09ACD3`
- 项目 checkout：`codex/full-runtime-performance-audit-20261014` / `0dd71fd78baa01283df081f9bd02fe4b7f2df326`；tree `20ec92e835803f486d088eef183c7db08564926b`；remote `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`
- 工作树：保留既有 tracked/untracked 改动，不覆盖历史 review；未打开首轮 review ledger。
- 最终标签统计：`{"vulnerable":0,"fixed":0,"safe":1,"unrelated":31,"unknown":13,"total":45}`；Precision/Recall：`not computed`。
- 口径：`safe` 只表示已观察 shared_ptr owner 访问集合同步闭合；`unrelated` 只排除已观察 owner-race 形状；两者都不等于产品安全。

## 00c8ae87a8576190

- Review item：`385d0407467c117c1bc471deaee058fa95493080dc74d75d3b12833bac0a3eff:holdout`；Candidate：`385d0407467c117c1bc471deaee058fa95493080dc74d75d3b12833bac0a3eff`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `29db5c04bd534bcd029d702e8df7867573b6f35d`；source SHA-256 `20706185efad40245b844eb5b1397da2de26a1f42b5d6dc4719ea5520f300348`；`interfaces/kits/napi/picture_in_picture_napi/js_pip_window_listener.h:32:22` `read` `jsCallBack_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Listener construction and NAPI callback dispatch may differ; post-construction owner operations are reads/copies.
- shared_ptr 发布顺序：Owner copied in constructor and into NAPI lambdas; no replacement/reset.
- 同步协议：No conflicting owner write after initialization.
- 冲突访问对：No same-object owner write/read pair.
- 触发窗口：No owner-race window established.
- 生命周期：Listener/NativeReference captured by callbacks.
- 入口/权限：PiP/floating-ball/float-view callback family only.
- CIA 依据：No concrete CIA impact.
- 独立结论：Stable owner initialization/read-only propagation excludes observed owner race.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 03ac81fdf0dad858

- Review item：`96d94fd92a003251ec386f66069c5a52f4bd88f63a0ff30d0679456ae6a3ce84:holdout`；Candidate：`96d94fd92a003251ec386f66069c5a52f4bd88f63a0ff30d0679456ae6a3ce84`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `3c325423cb185f8275e3eb62853ef9c16477aef9`；source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`；`interfaces/innerkits/wm/wm_animation_common.h:265:37` `read` `animationSystemParams`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 0984ba53e4891550

- Review item：`21a7bd798474558ed52232e03e58ace103497d48a30fb6f5b11a0f3cf8df66b4:holdout`；Candidate：`21a7bd798474558ed52232e03e58ace103497d48a30fb6f5b11a0f3cf8df66b4`；Scope：`holdout`
- 固定来源：repository `openharmony/security_access_token`；commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`；tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0`；blob `b6adec200d1500ae4148a5a801364fa38e81a99a`；source SHA-256 `ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed`；`interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h:117:71` `read` `data_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Constructor/member initialization or stable-owner read; no post-construction owner write shown.
- shared_ptr 发布顺序：Member initialized during construction; no later owner reassignment/reset found.
- 同步协议：No same-object conflicting owner pair.
- 冲突访问对：No same-object conflict in fixed source.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Owner-stable constructor/use shape.
- 入口/权限：Code location only; product entry/privilege unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee internal thread safety and safe publication remain outside this owner-race disposition.
- 最小复现方向：Only needed if a later owner assignment or cross-thread pointee mutation is discovered.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 0a21bb32264c7d75

- Review item：`98a2ac1ba0b1d0501fe6fc17e979d887a2623f843221e9582259eac902cc7e1a:holdout`；Candidate：`98a2ac1ba0b1d0501fe6fc17e979d887a2623f843221e9582259eac902cc7e1a`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `3c325423cb185f8275e3eb62853ef9c16477aef9`；source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`；`interfaces/innerkits/wm/wm_animation_common.h:261:37` `read` `animationParams`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 0c076a622b333f8d

- Review item：`0c3d001e4abbb837b5b164bade7dfca901342fca31a94ec355667827f2376e4c:holdout`；Candidate：`0c3d001e4abbb837b5b164bade7dfca901342fca31a94ec355667827f2376e4c`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `562b504ae819cd154f515bc264038f7f3cd3100c`；source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`；`previewer/include/wm_animation_common.h:281:54` `read` `excludeFromDock`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 0dcfabb07e3a819e

- Review item：`25ed03d67f1c9d5397936181c95cf65131311f145f8a9f42cd358eef8b4bf122:holdout`；Candidate：`25ed03d67f1c9d5397936181c95cf65131311f145f8a9f42cd358eef8b4bf122`；Scope：`holdout`
- 固定来源：repository `openharmony/security_access_token`；commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`；tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0`；blob `bc968e7ce325261154cc42d57134516a94ae454d`；source SHA-256 `96085536e15127518f88dce54536c151531eca8ec19e7fb9bae370e01acd351d`；`interfaces/kits/js/napi/accesstoken/include/napi_request_global_switch_on_setting.h:68:9` `write` `asyncContextPtr`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Constructor/member initialization or stable-owner read; no post-construction owner write shown.
- shared_ptr 发布顺序：Member initialized during construction; no later owner reassignment/reset found.
- 同步协议：No same-object conflicting owner pair.
- 冲突访问对：No same-object conflict in fixed source.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Owner-stable constructor/use shape.
- 入口/权限：Code location only; product entry/privilege unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee internal thread safety and safe publication remain outside this owner-race disposition.
- 最小复现方向：Only needed if a later owner assignment or cross-thread pointee mutation is discovered.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 109e777bac47451e

- Review item：`0089d85d5f9004679cf036196674b664847db9ed99f5b1bb4f74803ea2f3f427:holdout`；Candidate：`0089d85d5f9004679cf036196674b664847db9ed99f5b1bb4f74803ea2f3f427`；Scope：`holdout`
- 固定来源：repository `openharmony/distributeddatamgr_kv_store`；commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`；tree `3b92c53fde616d5a3f9487b0c295670a42c63023`；blob `6454f335e87e326ce97bfc405f15347e814aa700`；source SHA-256 `fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`；`kvstoremock/external_inner_kit/napi/include/extension_context.h:61:16` `read` `abilityInfo_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unrelated`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Production thread/event queue is not applicable; fixed path is under kvstoremock/external_inner_kit.
- shared_ptr 发布顺序：Mock getter/setler lifecycle only; no product publication sequence established.
- 同步协议：No production synchronization claim.
- 冲突访问对：Getter/setter owner pair is visible only in mock/support source.
- 触发窗口：No production trigger window established.
- 生命周期：Mock/support object lifecycle only.
- 入口/权限：No production entry or privilege boundary established.
- CIA 依据：No production CIA impact established.
- 独立结论：Explicit non-production mock/support path; unrelated excludes only a production shared_ptr vulnerability claim.
- 证据位置：kvstoremock/external_inner_kit/napi/include/extension_context.h:55-85
- 待补事实：No product fact is required to classify this specific item as out of production scope.
- 最小复现方向：No vulnerability PoC. Retain as an unrelated/scope-control item and exclude from production scoring.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 11a9e51881bba4a3

- Review item：`2c7fb8c5e56f8f2488762f1c65dec2f8a2c3cd9fb6f743df83c9e99c4687d679:holdout`；Candidate：`2c7fb8c5e56f8f2488762f1c65dec2f8a2c3cd9fb6f743df83c9e99c4687d679`；Scope：`holdout`
- 固定来源：repository `openharmony/update_updateservice`；commit `e4942a33cc5ed29040e5c720bea3b2a8e4a79221`；tree `b367991eed0272f54fe5ae712d18e24377d57949`；blob `1ab7136b8fcc050976b33febff457fcc9fa04177`；source SHA-256 `cd9dbbd3a2e16405198c2e6bc63f8178d4c45106b5d8a31a00f713d0f66bc6d9`；`services/core/ability/status_cache/include/status_cache.h:27:67` `read` `timeUtilsProxy_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Constructor/member initialization or stable-owner read; no post-construction owner write shown.
- shared_ptr 发布顺序：Member initialized during construction; no later owner reassignment/reset found.
- 同步协议：No same-object conflicting owner pair.
- 冲突访问对：No same-object conflict in fixed source.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Owner-stable constructor/use shape.
- 入口/权限：Code location only; product entry/privilege unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee internal thread safety and safe publication remain outside this owner-race disposition.
- 最小复现方向：Only needed if a later owner assignment or cross-thread pointee mutation is discovered.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 189d9dc2fec1ba7c

- Review item：`610820828f23db15834dde0632174496f43cf3de75f048e3936d217363e27a7c:plausible`；Candidate：`610820828f23db15834dde0632174496f43cf3de75f048e3936d217363e27a7c`；Scope：`plausible_unproven`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `d1a7f737dd18fe251713ae814bf8d817aaf96e58`；source SHA-256 `c2b49eea47ec9bc2fb3927e59f9629d5b944cd3fbb2ac360534171fe8138227a`；`wm/include/picture_in_picture_controller_ani.h:57:9` `write` `mainWindowXComponentController_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Setters/direct writes and source-rect/reset/ext-controller readers may use different event runners; exact ownership unknown.
- shared_ptr 发布顺序：Controller owner assignment/read has no proven lock, atomic protocol or publication order.
- 同步协议：No complete owner synchronization.
- 冲突访问对：Same-object getter/setter pair plus direct reads/writes in source-rect/reset/ext-controller paths.
- 触发窗口：Setter/direct replacement versus reader overlap while controller is shared between windows; not proven.
- 生命周期：Controller/XComponentController spans setup, source-rect, reset and extension operations.
- 入口/权限：PiP/window entry family only; privilege and attacker control unknown.
- CIA 依据：Window-state or memory-safety effect is hypothetical; no concrete CIA proof.
- 独立结论：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 证据位置：wm/include/picture_in_picture_controller.h:49-56；wm/include/picture_in_picture_controller_ani.h:52-59；wm/include/picture_in_picture_controller_base.h:140-147；wm/src/picture_in_picture_controller.cpp:62-63,175,283-289,475-492；wm/src/picture_in_picture_controller_ani.cpp:85-86,169,276-282,482-500
- 待补事实：Whether setters run on the same event runner as source-rect/reset/extension-controller readers.；Feasible interleaving while a controller is shared between main and PIP windows.；Reachable product trigger and concrete CIA impact.
- 最小复现方向：Create two controller variants and race SetXComponentController/SetMainWindowXComponentController against the source-rect and ResetExtController readers under TSan; repeat with a mutex-protected owner.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 18c96f591a6dca1e

- Review item：`8ab1907289a43e543ac716c3db76d8db1e06a9990741d1ecbdee109caf7f739e:holdout`；Candidate：`8ab1907289a43e543ac716c3db76d8db1e06a9990741d1ecbdee109caf7f739e`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `562b504ae819cd154f515bc264038f7f3cd3100c`；source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`；`previewer/include/wm_animation_common.h:257:37` `read` `animationSystemParams`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 1fae182b80e03b31

- Review item：`a652b1b68097421147c0051e3c8f75cd993e286907958c8c40bec5a8a4c8056a:holdout`；Candidate：`a652b1b68097421147c0051e3c8f75cd993e286907958c8c40bec5a8a4c8056a`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `eae1ac64199017f10cff98cc2a470a18b7205b41`；source SHA-256 `1864f6e38e779147011fadcd468da3e2594b3f883f30366f8a7e85b1ac0251cb`；`utils/include/ui_effect_controller_common.h:53:16` `read` `backgroundFilter_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：ConvertFromJsValue and IsEmpty are sequential in one NAPI flow; Unmarshalling writes a fresh object.
- shared_ptr 发布顺序：Writes precede IsEmpty read on a local/new object; no post-publication same-object mutation shown.
- 同步协议：No same-object conflicting pair for observed shape.
- 冲突访问对：No same-object post-publication owner pair.
- 触发窗口：No owner-race window established.
- 生命周期：Local/new UIEffectParams lifecycle only.
- 入口/权限：UI-effect NAPI family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Fresh-object/sequential shape excludes observed owner race, not product safety.
- 证据位置：utils/include/ui_effect_controller_common.h:46-62；utils/src/ui_effect_controller_common.cpp:50-76,110-130；interfaces/kits/napi/window_runtime/window_napi/js_ui_effect_controller.cpp:125-130,173-192；window_scene/session/host/src/ui_effect_controller_stub.cpp:41-56
- 待补事实：Pointee Filter/VisualEffect thread safety is outside this owner-race disposition.
- 最小复现方向：Only needed if a same UIEffectParams object is mutated after publication or concurrently parsed.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 216f43693c1ed53f

- Review item：`ead5f473d62f6d21712f7eb0ae59bc743f1d7222f5fba437120c4508668ea785:holdout`；Candidate：`ead5f473d62f6d21712f7eb0ae59bc743f1d7222f5fba437120c4508668ea785`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `3c325423cb185f8275e3eb62853ef9c16477aef9`；source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`；`interfaces/innerkits/wm/wm_animation_common.h:273:52` `read` `needAnimation`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 262e8786de8d4855

- Review item：`0ebba8620c4dd9cf41d5da993d590ba788befdeb941fbfca7d1aa148e3b9bf81:plausible`；Candidate：`0ebba8620c4dd9cf41d5da993d590ba788befdeb941fbfca7d1aa148e3b9bf81`；Scope：`plausible_unproven`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `d1a7f737dd18fe251713ae814bf8d817aaf96e58`；source SHA-256 `c2b49eea47ec9bc2fb3927e59f9629d5b944cd3fbb2ac360534171fe8138227a`；`wm/include/picture_in_picture_controller_ani.h:53:16` `read` `mainWindowXComponentController_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Setters/direct writes and source-rect/reset/ext-controller readers may use different event runners; exact ownership unknown.
- shared_ptr 发布顺序：Controller owner assignment/read has no proven lock, atomic protocol or publication order.
- 同步协议：No complete owner synchronization.
- 冲突访问对：Same-object getter/setter pair plus direct reads/writes in source-rect/reset/ext-controller paths.
- 触发窗口：Setter/direct replacement versus reader overlap while controller is shared between windows; not proven.
- 生命周期：Controller/XComponentController spans setup, source-rect, reset and extension operations.
- 入口/权限：PiP/window entry family only; privilege and attacker control unknown.
- CIA 依据：Window-state or memory-safety effect is hypothetical; no concrete CIA proof.
- 独立结论：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 证据位置：wm/include/picture_in_picture_controller.h:49-56；wm/include/picture_in_picture_controller_ani.h:52-59；wm/include/picture_in_picture_controller_base.h:140-147；wm/src/picture_in_picture_controller.cpp:62-63,175,283-289,475-492；wm/src/picture_in_picture_controller_ani.cpp:85-86,169,276-282,482-500
- 待补事实：Whether setters run on the same event runner as source-rect/reset/extension-controller readers.；Feasible interleaving while a controller is shared between main and PIP windows.；Reachable product trigger and concrete CIA impact.
- 最小复现方向：Create two controller variants and race SetXComponentController/SetMainWindowXComponentController against the source-rect and ResetExtController readers under TSan; repeat with a mutex-protected owner.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 28f5d974aafabd67

- Review item：`16da132f19039393f70288746451ca9bf29f3276beb08e9f4819448d60c6c710:holdout`；Candidate：`16da132f19039393f70288746451ca9bf29f3276beb08e9f4819448d60c6c710`；Scope：`holdout`
- 固定来源：repository `openharmony/security_access_token`；commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`；tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0`；blob `2c5c6dcf02cf1ae7e44ff7538055057ba4cf33f9`；source SHA-256 `01ff052ab114b27d548c974d522141e6fec8bb142b5e0f4dd27366f5711153b0`；`interfaces/kits/js/napi/accesstoken/include/napi_open_permission_on_setting.h:61:9` `write` `asyncContextPtr`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Constructor/member initialization or stable-owner read; no post-construction owner write shown.
- shared_ptr 发布顺序：Member initialized during construction; no later owner reassignment/reset found.
- 同步协议：No same-object conflicting owner pair.
- 冲突访问对：No same-object conflict in fixed source.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Owner-stable constructor/use shape.
- 入口/权限：Code location only; product entry/privilege unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee internal thread safety and safe publication remain outside this owner-race disposition.
- 最小复现方向：Only needed if a later owner assignment or cross-thread pointee mutation is discovered.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 2933d6f08739598b

- Review item：`228aa372f6f5454101891f359b3bedcad2cc55d90afbd43d9c50f8de35f27598:holdout`；Candidate：`228aa372f6f5454101891f359b3bedcad2cc55d90afbd43d9c50f8de35f27598`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `26e4a721b1f126e33af5c9fba7c908702ea49dbd`；source SHA-256 `b2de64e2e5bb197f96b1d7693dbe7aca4c5966cd31c9133b17f412c3615a40bc`；`interfaces/kits/napi/floating_ball_napi/js_fb_window_listener.h:33:22` `read` `jsCallBack_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Listener construction and NAPI callback dispatch may differ; post-construction owner operations are reads/copies.
- shared_ptr 发布顺序：Owner copied in constructor and into NAPI lambdas; no replacement/reset.
- 同步协议：No conflicting owner write after initialization.
- 冲突访问对：No same-object owner write/read pair.
- 触发窗口：No owner-race window established.
- 生命周期：Listener/NativeReference captured by callbacks.
- 入口/权限：PiP/floating-ball/float-view callback family only.
- CIA 依据：No concrete CIA impact.
- 独立结论：Stable owner initialization/read-only propagation excludes observed owner race.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 29c57a4203eeb950

- Review item：`6334c63528ae670fc6f7d17947c9275aa46a4a44e562a3285e0595b1ca9b6652:plausible`；Candidate：`6334c63528ae670fc6f7d17947c9275aa46a4a44e562a3285e0595b1ca9b6652`；Scope：`plausible_unproven`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `c634385cff8c3b0f2704ec5d92e278c3c8057d7a`；source SHA-256 `a0f47a883e30c7abffbf1fb49bb5f61251869b920b1aefd9a7086cae67327418`；`wm/include/picture_in_picture_controller_base.h:141:16` `read` `pipXComponentController_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Setters/direct writes and source-rect/reset/ext-controller readers may use different event runners; exact ownership unknown.
- shared_ptr 发布顺序：Controller owner assignment/read has no proven lock, atomic protocol or publication order.
- 同步协议：No complete owner synchronization.
- 冲突访问对：Same-object getter/setter pair plus direct reads/writes in source-rect/reset/ext-controller paths.
- 触发窗口：Setter/direct replacement versus reader overlap while controller is shared between windows; not proven.
- 生命周期：Controller/XComponentController spans setup, source-rect, reset and extension operations.
- 入口/权限：PiP/window entry family only; privilege and attacker control unknown.
- CIA 依据：Window-state or memory-safety effect is hypothetical; no concrete CIA proof.
- 独立结论：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 证据位置：wm/include/picture_in_picture_controller.h:49-56；wm/include/picture_in_picture_controller_ani.h:52-59；wm/include/picture_in_picture_controller_base.h:140-147；wm/src/picture_in_picture_controller.cpp:62-63,175,283-289,475-492；wm/src/picture_in_picture_controller_ani.cpp:85-86,169,276-282,482-500
- 待补事实：Whether setters run on the same event runner as source-rect/reset/extension-controller readers.；Feasible interleaving while a controller is shared between main and PIP windows.；Reachable product trigger and concrete CIA impact.
- 最小复现方向：Create two controller variants and race SetXComponentController/SetMainWindowXComponentController against the source-rect and ResetExtController readers under TSan; repeat with a mutex-protected owner.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 2c4b4625bf41f268

- Review item：`5d677d300a9ffdbe76a0ad582decd272f11d78557c140950dd03f346b830bb6b:plausible`；Candidate：`5d677d300a9ffdbe76a0ad582decd272f11d78557c140950dd03f346b830bb6b`；Scope：`plausible_unproven`
- 固定来源：repository `openharmony/security_access_token`；commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`；tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0`；blob `f5f6974f1d47ed2456af573b62e975e28e499276`；source SHA-256 `2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7`；`services/tokensyncmanager/include/remote/remote_command_executor.h:41:9` `write` `ptrChannel_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Device-online/listener and command execution may target one executor; exact runners unknown.
- shared_ptr 发布顺序：SetChannel/CreateChannelIfNeeded write versus GetChannel/command reads; mutex coverage is partial.
- 同步协议：Partial, inconsistent mutex coverage; no complete owner protocol.
- 冲突访问对：Header getter/setter plus CreateChannelIfNeeded write versus command/GetChannel reads.
- 触发窗口：Device-online channel creation/reset versus command processing; not proven.
- 生命周期：Executor is retained while channel and command state outlive calls.
- 入口/权限：Token-sync/device-online family only; privilege/authentication boundary unknown.
- CIA 依据：Availability/integrity effects remain hypothetical.
- 独立结论：Partial synchronization and incomplete reachability/impact evidence; retain unknown.
- 证据位置：services/tokensyncmanager/include/remote/remote_command_executor.h:35-41；services/tokensyncmanager/src/remote/remote_command_executor.cpp:84-96；services/tokensyncmanager/src/remote/remote_command_executor.cpp:307-317；services/tokensyncmanager/src/remote/remote_command_manager.cpp:176-190；services/tokensyncmanager/src/remote/remote_command_manager.cpp:276-287
- 待补事实：Exact thread/event-runner ownership for NotifyDeviceOnline, GetExecutorChannel, and command execution.；A happens-before proof or a controlled race/fixed run for ptrChannel_ publication and reset.；Real product entry, privilege boundary, trigger, and CIA consequence.
- 最小复现方向：Build a narrow RemoteCommandExecutor harness that concurrently calls SetChannel/GetChannel and CreateChannelIfNeeded/ProcessOneCommand under TSan, then repeat with one owner mutex or atomic shared_ptr protocol.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 2fd1e3c72dcb88d7

- Review item：`4e9afc5ec4b9b2c8418de2868780ce9c410e056cda6a5a76c803ad5216b75701:holdout`；Candidate：`4e9afc5ec4b9b2c8418de2868780ce9c410e056cda6a5a76c803ad5216b75701`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `562b504ae819cd154f515bc264038f7f3cd3100c`；source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`；`previewer/include/wm_animation_common.h:214:37` `read` `animationConfig`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 42a9712edb1f3512

- Review item：`844d11acd6b225eb4782a2b67c1e8fcc3f5b3c3483d9cbcdf454e821ff9e148c:plausible`；Candidate：`844d11acd6b225eb4782a2b67c1e8fcc3f5b3c3483d9cbcdf454e821ff9e148c`；Scope：`plausible_unproven`
- 固定来源：repository `openharmony/distributeddatamgr_kv_store`；commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`；tree `3b92c53fde616d5a3f9487b0c295670a42c63023`；blob `19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46`；source SHA-256 `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`；`frameworks/common/js_proxy.h:42:16` `read` `instance_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：SetInstance(nullptr) in result-set close/release may overlap GetInstance in NAPI operations; NAPI execute/complete queue affinity is unknown.
- shared_ptr 发布顺序：SetInstance move-assigns/clears instance_; GetInstance copies it; no happens-before or atomic owner protocol is shown.
- 同步协议：No complete owner mutex/atomic shared_ptr protocol.
- 冲突访问对：Same-object owner pair: js_proxy.h:37 write and :42 read, including release-time SetInstance(nullptr) versus queued/operation-time GetInstance.
- 触发窗口：Possible close/release versus queued operation overlap; not proven.
- 生命周期：Result-set wrapper and inner instance lifetimes may overlap across NAPI operations.
- 入口/权限：Representative result-set NAPI entry only; privilege/attacker control unknown.
- CIA 依据：Potential memory-safety/availability impact remains hypothetical.
- 独立结论：Real owner pair but unresolved queue, trigger, entry/privilege and CIA facts; retain unknown.
- 证据位置：frameworks/common/js_proxy.h:29-44；frameworks/jskitsimpl/distributeddata/src/js_kv_store_resultset.cpp:73-286；frameworks/jskitsimpl/distributedkvstore/src/js_kv_store_resultset.cpp:79-297；frameworks/jskitsimpl/distributedkvstore/src/napi_data_share_adapter.cpp:89-111
- 待补事实：NAPI execute/complete thread affinity and callback queue ordering for each JSProxy subtype.；Whether SetInstance(nullptr) can overlap a queued GetInstance operation.；Product entry, attacker control, and concrete CIA impact.
- 最小复现方向：Run concurrent SetInstance(nullptr) and GetInstance calls for a representative result-set wrapper under TSan, then repeat after serializing owner mutation through the actual NAPI queue.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 43861dc7e550047d

- Review item：`48ff783415251c95ed5e93eabe1817f941d11c8f4727222408d25a6480416e20:holdout`；Candidate：`48ff783415251c95ed5e93eabe1817f941d11c8f4727222408d25a6480416e20`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `3c325423cb185f8275e3eb62853ef9c16477aef9`；source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`；`interfaces/innerkits/wm/wm_animation_common.h:297:56` `read` `excludeFromRecent`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 475c88d0bbd639f7

- Review item：`a662e84f949b68d0fba943db9acf075d1ab54a4b4ff4934608a21a1ea9eebc2d:holdout`；Candidate：`a662e84f949b68d0fba943db9acf075d1ab54a4b4ff4934608a21a1ea9eebc2d`；Scope：`holdout`
- 固定来源：repository `openharmony/distributeddatamgr_kv_store`；commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`；tree `3b92c53fde616d5a3f9487b0c295670a42c63023`；blob `6454f335e87e326ce97bfc405f15347e814aa700`；source SHA-256 `fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`；`kvstoremock/external_inner_kit/napi/include/extension_context.h:81:16` `read` `abilityInfo_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unrelated`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Production thread/event queue is not applicable; fixed path is under kvstoremock/external_inner_kit.
- shared_ptr 发布顺序：Mock getter/setler lifecycle only; no product publication sequence established.
- 同步协议：No production synchronization claim.
- 冲突访问对：Getter/setter owner pair is visible only in mock/support source.
- 触发窗口：No production trigger window established.
- 生命周期：Mock/support object lifecycle only.
- 入口/权限：No production entry or privilege boundary established.
- CIA 依据：No production CIA impact established.
- 独立结论：Explicit non-production mock/support path; unrelated excludes only a production shared_ptr vulnerability claim.
- 证据位置：kvstoremock/external_inner_kit/napi/include/extension_context.h:55-85
- 待补事实：No product fact is required to classify this specific item as out of production scope.
- 最小复现方向：No vulnerability PoC. Retain as an unrelated/scope-control item and exclude from production scoring.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 4d1c3c0f1eb52fed

- Review item：`de8642d38c52fbba01c43f4d7425d29330fb03e273de8ab740e5b2cc00d2a1d5:holdout`；Candidate：`de8642d38c52fbba01c43f4d7425d29330fb03e273de8ab740e5b2cc00d2a1d5`；Scope：`holdout`
- 固定来源：repository `openharmony/distributeddatamgr_kv_store`；commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`；tree `3b92c53fde616d5a3f9487b0c295670a42c63023`；blob `6454f335e87e326ce97bfc405f15347e814aa700`；source SHA-256 `fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`；`kvstoremock/external_inner_kit/napi/include/extension_context.h:65:9` `write` `abilityInfo_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Production thread/event queue is not applicable; fixed path is under kvstoremock/external_inner_kit.
- shared_ptr 发布顺序：Mock getter/setler lifecycle only; no product publication sequence established.
- 同步协议：No production synchronization claim.
- 冲突访问对：Getter/setter owner pair is visible only in mock/support source.
- 触发窗口：No production trigger window established.
- 生命周期：Mock/support object lifecycle only.
- 入口/权限：No production entry or privilege boundary established.
- CIA 依据：No production CIA impact established.
- 独立结论：Explicit non-production mock/support path; unrelated excludes only a production shared_ptr vulnerability claim.
- 证据位置：kvstoremock/external_inner_kit/napi/include/extension_context.h:55-85
- 待补事实：No product fact is required to classify this specific item as out of production scope.
- 最小复现方向：No vulnerability PoC. Retain as an unrelated/scope-control item and exclude from production scoring.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 50d42b057f4213b2

- Review item：`df1d89f286c9727a550f92b5c451d9126cd66adeb96a10be52415868b6fe2eb1:holdout`；Candidate：`df1d89f286c9727a550f92b5c451d9126cd66adeb96a10be52415868b6fe2eb1`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `5554d63b22a4de01654c415717b13e9579ba9fdf`；source SHA-256 `6ddefa22004292cbb0d771f76fc317864493478b2f6366be56c259ff75a57fb7`；`utils/include/surface_capture_future.h:73:29` `read` `hdrPixelMap_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：OnSurfaceCapture callback and GetHDRResult waiter may overlap on different threads.
- shared_ptr 发布顺序：OnSurfaceCapture resets hdrPixelMap_ before FutureCall locks; GetHDRResult reads under mutex_.
- 同步协议：Most accesses are locked, but the reset is outside the mutex.
- 冲突访问对：hdrPixelMap_ reset at surface_capture_future.h:32 versus locked read at :73.
- 触发窗口：Timed-out GetHDRResult versus late OnSurfaceCapture reset; feasibility unproven.
- 生命周期：Late callback can arrive after timeout on the same future.
- 入口/权限：Surface-capture family only; product trigger/privilege unknown.
- CIA 依据：Memory-safety/availability effect hypothetical.
- 独立结论：Out-of-lock owner write/read remains unresolved; retain unknown.
- 证据位置：utils/include/future.h:22-52；utils/include/surface_capture_future.h:30-58,66-95
- 待补事实：Whether an OnSurfaceCapture callback can overlap a timed-out GetHDRResult caller in product paths.；Controlled TSan evidence for the out-of-lock hdrPixelMap_ reset.；Product trigger and CIA consequence.
- 最小复现方向：Race OnSurfaceCapture with GetHDRResult around timeout under TSan, then repeat after moving hdrPixelMap_ = nullptr inside the mutex.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 5c64a5975b7d348e

- Review item：`a3080f2b2c90a12166ec6d4ad76a3c7886033b47e9356f124a74c00fb1426a80:holdout`；Candidate：`a3080f2b2c90a12166ec6d4ad76a3c7886033b47e9356f124a74c00fb1426a80`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `d0fcbe8d24b7b47d83e2bf6fcf65954aac3e4428`；source SHA-256 `9e59f4470eb1d59efaa1b12643d579b4f5315dc69a61250fbf3a05823f2efa23`；`wmserver/include/drag_controller.h:68:9` `read` `vsyncCallback_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Owner initialized in controller construction; RequestVsync/callback may run elsewhere.
- shared_ptr 发布顺序：make_shared initialization precedes registration; no replacement/reset.
- 同步协议：No conflicting shared_ptr owner pair.
- 冲突访问对：No same-object owner mutation pair.
- 触发窗口：No owner-race window established.
- 生命周期：Controller/VsyncCallback lifetime spans registration/callback.
- 入口/权限：Move/drag vsync family only.
- CIA 依据：No concrete CIA impact.
- 独立结论：Stable owner initialization/use is not an owner race.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 61fadc5b5d197135

- Review item：`fc90aa9eaa7a862404445c7a7b340636035341caf97d661223a49f930f6bc5d3:holdout`；Candidate：`fc90aa9eaa7a862404445c7a7b340636035341caf97d661223a49f930f6bc5d3`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `562b504ae819cd154f515bc264038f7f3cd3100c`；source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`；`previewer/include/wm_animation_common.h:253:37` `read` `animationParams`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 6dbe3a1c389d9083

- Review item：`b7add44fd9df2d261854292572cc006c1a94a0db75a8338dd8af2162bd455ea6:holdout`；Candidate：`b7add44fd9df2d261854292572cc006c1a94a0db75a8338dd8af2162bd455ea6`；Scope：`holdout`
- 固定来源：repository `openharmony/security_access_token`；commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`；tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0`；blob `93c786e28ddd7dc390dbe6a2f24c784cb2f9a872`；source SHA-256 `287d462edbeb4376031415b0e7171d409f04e4772ab819ad882341a9669a5cb1`；`interfaces/kits/cj/accesstoken/include/at_manager_impl.h:115:86` `read` `data_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Constructor/member initialization or stable-owner read; no post-construction owner write shown.
- shared_ptr 发布顺序：Member initialized during construction; no later owner reassignment/reset found.
- 同步协议：No same-object conflicting owner pair.
- 冲突访问对：No same-object conflict in fixed source.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Owner-stable constructor/use shape.
- 入口/权限：Code location only; product entry/privilege unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee internal thread safety and safe publication remain outside this owner-race disposition.
- 最小复现方向：Only needed if a later owner assignment or cross-thread pointee mutation is discovered.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 72b468b6e62a3bfc

- Review item：`951e6357190d927ffab7a4d1970a623403d3879e6d735343ef99afa480aa04af:plausible`；Candidate：`951e6357190d927ffab7a4d1970a623403d3879e6d735343ef99afa480aa04af`；Scope：`plausible_unproven`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `c634385cff8c3b0f2704ec5d92e278c3c8057d7a`；source SHA-256 `a0f47a883e30c7abffbf1fb49bb5f61251869b920b1aefd9a7086cae67327418`；`wm/include/picture_in_picture_controller_base.h:145:9` `write` `pipXComponentController_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Setters/direct writes and source-rect/reset/ext-controller readers may use different event runners; exact ownership unknown.
- shared_ptr 发布顺序：Controller owner assignment/read has no proven lock, atomic protocol or publication order.
- 同步协议：No complete owner synchronization.
- 冲突访问对：Same-object getter/setter pair plus direct reads/writes in source-rect/reset/ext-controller paths.
- 触发窗口：Setter/direct replacement versus reader overlap while controller is shared between windows; not proven.
- 生命周期：Controller/XComponentController spans setup, source-rect, reset and extension operations.
- 入口/权限：PiP/window entry family only; privilege and attacker control unknown.
- CIA 依据：Window-state or memory-safety effect is hypothetical; no concrete CIA proof.
- 独立结论：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 证据位置：wm/include/picture_in_picture_controller.h:49-56；wm/include/picture_in_picture_controller_ani.h:52-59；wm/include/picture_in_picture_controller_base.h:140-147；wm/src/picture_in_picture_controller.cpp:62-63,175,283-289,475-492；wm/src/picture_in_picture_controller_ani.cpp:85-86,169,276-282,482-500
- 待补事实：Whether setters run on the same event runner as source-rect/reset/extension-controller readers.；Feasible interleaving while a controller is shared between main and PIP windows.；Reachable product trigger and concrete CIA impact.
- 最小复现方向：Create two controller variants and race SetXComponentController/SetMainWindowXComponentController against the source-rect and ResetExtController readers under TSan; repeat with a mutex-protected owner.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 7c0cc08d2a792c8c

- Review item：`0017e7042647b7ec0b39b9fc086697a7d66cd696d0dd334c05b7ca174222b77b:plausible`；Candidate：`0017e7042647b7ec0b39b9fc086697a7d66cd696d0dd334c05b7ca174222b77b`；Scope：`plausible_unproven`
- 固定来源：repository `openharmony/security_access_token`；commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`；tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0`；blob `f5f6974f1d47ed2456af573b62e975e28e499276`；source SHA-256 `2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7`；`services/tokensyncmanager/include/remote/remote_command_executor.h:37:16` `read` `ptrChannel_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Device-online/listener and command execution may target one executor; exact runners unknown.
- shared_ptr 发布顺序：SetChannel/CreateChannelIfNeeded write versus GetChannel/command reads; mutex coverage is partial.
- 同步协议：Partial, inconsistent mutex coverage; no complete owner protocol.
- 冲突访问对：Header getter/setter plus CreateChannelIfNeeded write versus command/GetChannel reads.
- 触发窗口：Device-online channel creation/reset versus command processing; not proven.
- 生命周期：Executor is retained while channel and command state outlive calls.
- 入口/权限：Token-sync/device-online family only; privilege/authentication boundary unknown.
- CIA 依据：Availability/integrity effects remain hypothetical.
- 独立结论：Partial synchronization and incomplete reachability/impact evidence; retain unknown.
- 证据位置：services/tokensyncmanager/include/remote/remote_command_executor.h:35-41；services/tokensyncmanager/src/remote/remote_command_executor.cpp:84-96；services/tokensyncmanager/src/remote/remote_command_executor.cpp:307-317；services/tokensyncmanager/src/remote/remote_command_manager.cpp:176-190；services/tokensyncmanager/src/remote/remote_command_manager.cpp:276-287
- 待补事实：Exact thread/event-runner ownership for NotifyDeviceOnline, GetExecutorChannel, and command execution.；A happens-before proof or a controlled race/fixed run for ptrChannel_ publication and reset.；Real product entry, privilege boundary, trigger, and CIA consequence.
- 最小复现方向：Build a narrow RemoteCommandExecutor harness that concurrently calls SetChannel/GetChannel and CreateChannelIfNeeded/ProcessOneCommand under TSan, then repeat with one owner mutex or atomic shared_ptr protocol.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 8523ddac356a47a3

- Review item：`1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7:plausible`；Candidate：`1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7`；Scope：`plausible_unproven`
- 固定来源：repository `openharmony/communication_dsoftbus`；commit `652f88e0261ce4d0610f73cc451c26b84d2597af`；tree `f8a14c30ef815217fa4d267939cff84db1fd5057`；blob `1f8eb2e331021766be3485a3b56746c074be4687`；source SHA-256 `66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100`；`sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67:86` `read` `streamListener_`
- Git 对象核验：commit=False / tree=False / blob=False / source_sha256=False；provenance_verified=False
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Channel creation, SetStreamRecvListener and socket callbacks may overlap; exact queues unknown.
- shared_ptr 发布顺序：Constructor initialization, later listener reassignment and callback publication order are unproven.
- 同步协议：No complete synchronization proof; pinned Git object provenance also remains unavailable.
- 冲突访问对：Candidate SetStreamRecvListener write versus channel-creation read; focus constructor read is not itself a conflicting write.
- 触发窗口：Listener replacement versus channel creation/callback setup; not proven.
- 生命周期：StreamManager/listener/socket callback lifetime overlap is unknown.
- 入口/权限：SoftBus stream/channel family only; product privilege and attacker control unknown.
- CIA 依据：Concrete CIA impact unknown.
- 独立结论：Source provenance and concurrency obligations unresolved; retain unknown.
- 证据位置：sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67,87-110；sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.cpp:58-61,88-95,172-185
- 待补事实：Whether channel creation and SetStreamRecvListener can execute concurrently on one StreamManager.；Publication ordering between streamListener_, socketListener_, and the socket callback.；Reachable trigger and CIA consequence in the product.
- 最小复现方向：Race SetStreamRecvListener with CreateStreamClientChannel/CreateStreamServerChannel in a controlled StreamManager harness under TSan, then repeat with a common mutex or immutable listener publication.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 8bc53a1a1abb0b3c

- Review item：`91a26bea4359381a25147a29a0d7e4e7d03ff4e6c92f79138b379d98ca095d0d:plausible`；Candidate：`91a26bea4359381a25147a29a0d7e4e7d03ff4e6c92f79138b379d98ca095d0d`；Scope：`plausible_unproven`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `02928bb18057a2485b0dfbbb83e21c88ebd7f1d8`；source SHA-256 `5185852d3a0b6be8ac178984036863571abf1400c0f83089e29bcf10b3fa9c8c`；`wm/include/picture_in_picture_controller.h:54:9` `write` `mainWindowXComponentController_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Setters/direct writes and source-rect/reset/ext-controller readers may use different event runners; exact ownership unknown.
- shared_ptr 发布顺序：Controller owner assignment/read has no proven lock, atomic protocol or publication order.
- 同步协议：No complete owner synchronization.
- 冲突访问对：Same-object getter/setter pair plus direct reads/writes in source-rect/reset/ext-controller paths.
- 触发窗口：Setter/direct replacement versus reader overlap while controller is shared between windows; not proven.
- 生命周期：Controller/XComponentController spans setup, source-rect, reset and extension operations.
- 入口/权限：PiP/window entry family only; privilege and attacker control unknown.
- CIA 依据：Window-state or memory-safety effect is hypothetical; no concrete CIA proof.
- 独立结论：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 证据位置：wm/include/picture_in_picture_controller.h:49-56；wm/include/picture_in_picture_controller_ani.h:52-59；wm/include/picture_in_picture_controller_base.h:140-147；wm/src/picture_in_picture_controller.cpp:62-63,175,283-289,475-492；wm/src/picture_in_picture_controller_ani.cpp:85-86,169,276-282,482-500
- 待补事实：Whether setters run on the same event runner as source-rect/reset/extension-controller readers.；Feasible interleaving while a controller is shared between main and PIP windows.；Reachable product trigger and concrete CIA impact.
- 最小复现方向：Create two controller variants and race SetXComponentController/SetMainWindowXComponentController against the source-rect and ResetExtController readers under TSan; repeat with a mutex-protected owner.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 8bf2c12c014dda78

- Review item：`3f33ecdd5899ae2cbbff6aae95eeef494c583c294112752e69c72f3ab569dbba:holdout`；Candidate：`3f33ecdd5899ae2cbbff6aae95eeef494c583c294112752e69c72f3ab569dbba`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `3c325423cb185f8275e3eb62853ef9c16477aef9`；source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`；`interfaces/innerkits/wm/wm_animation_common.h:220:37` `read` `animationConfig`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 9428dad22daecdb4

- Review item：`3f69ba23ee35ab8b695eb5b3019703343504bae60835da22335e2ab165116dde:holdout`；Candidate：`3f69ba23ee35ab8b695eb5b3019703343504bae60835da22335e2ab165116dde`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `562b504ae819cd154f515bc264038f7f3cd3100c`；source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`；`previewer/include/wm_animation_common.h:265:52` `read` `needAnimation`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 99ce5dad55f7c1af

- Review item：`cf54aeb9706c25f3043ea685b7cf3ce168c05796cb71cc36d9095d7b2a29e495:holdout`；Candidate：`cf54aeb9706c25f3043ea685b7cf3ce168c05796cb71cc36d9095d7b2a29e495`；Scope：`holdout`
- 固定来源：repository `openharmony/security_access_token`；commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`；tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0`；blob `7828aceaf6d50c98c2b70d49f7ea17bda654a982`；source SHA-256 `c1c33169daa4d39acf5ef5f42e72c867f2d1a175e59e4917b54d1abc6b313560`；`interfaces/kits/js/napi/accesstoken/include/napi_request_permission_on_setting.h:63:9` `write` `asyncContextPtr`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Constructor/member initialization or stable-owner read; no post-construction owner write shown.
- shared_ptr 发布顺序：Member initialized during construction; no later owner reassignment/reset found.
- 同步协议：No same-object conflicting owner pair.
- 冲突访问对：No same-object conflict in fixed source.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Owner-stable constructor/use shape.
- 入口/权限：Code location only; product entry/privilege unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee internal thread safety and safe publication remain outside this owner-race disposition.
- 最小复现方向：Only needed if a later owner assignment or cross-thread pointee mutation is discovered.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 9a7da68327154c5f

- Review item：`c722752a78ed08cfb6cc59dd310836450dae9cfa7a26e6f417e84591aaf9c3d8:plausible`；Candidate：`c722752a78ed08cfb6cc59dd310836450dae9cfa7a26e6f417e84591aaf9c3d8`；Scope：`plausible_unproven`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `02928bb18057a2485b0dfbbb83e21c88ebd7f1d8`；source SHA-256 `5185852d3a0b6be8ac178984036863571abf1400c0f83089e29bcf10b3fa9c8c`；`wm/include/picture_in_picture_controller.h:50:16` `read` `mainWindowXComponentController_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Setters/direct writes and source-rect/reset/ext-controller readers may use different event runners; exact ownership unknown.
- shared_ptr 发布顺序：Controller owner assignment/read has no proven lock, atomic protocol or publication order.
- 同步协议：No complete owner synchronization.
- 冲突访问对：Same-object getter/setter pair plus direct reads/writes in source-rect/reset/ext-controller paths.
- 触发窗口：Setter/direct replacement versus reader overlap while controller is shared between windows; not proven.
- 生命周期：Controller/XComponentController spans setup, source-rect, reset and extension operations.
- 入口/权限：PiP/window entry family only; privilege and attacker control unknown.
- CIA 依据：Window-state or memory-safety effect is hypothetical; no concrete CIA proof.
- 独立结论：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 证据位置：wm/include/picture_in_picture_controller.h:49-56；wm/include/picture_in_picture_controller_ani.h:52-59；wm/include/picture_in_picture_controller_base.h:140-147；wm/src/picture_in_picture_controller.cpp:62-63,175,283-289,475-492；wm/src/picture_in_picture_controller_ani.cpp:85-86,169,276-282,482-500
- 待补事实：Whether setters run on the same event runner as source-rect/reset/extension-controller readers.；Feasible interleaving while a controller is shared between main and PIP windows.；Reachable product trigger and concrete CIA impact.
- 最小复现方向：Create two controller variants and race SetXComponentController/SetMainWindowXComponentController against the source-rect and ResetExtController readers under TSan; repeat with a mutex-protected owner.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 9b3f9c97a527cc4e

- Review item：`1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7:holdout`；Candidate：`1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7`；Scope：`holdout`
- 固定来源：repository `openharmony/communication_dsoftbus`；commit `652f88e0261ce4d0610f73cc451c26b84d2597af`；tree `f8a14c30ef815217fa4d267939cff84db1fd5057`；blob `1f8eb2e331021766be3485a3b56746c074be4687`；source SHA-256 `66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100`；`sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67:86` `read` `streamListener_`
- Git 对象核验：commit=False / tree=False / blob=False / source_sha256=False；provenance_verified=False
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：Channel creation, SetStreamRecvListener and socket callbacks may overlap; exact queues unknown.
- shared_ptr 发布顺序：Constructor initialization, later listener reassignment and callback publication order are unproven.
- 同步协议：No complete synchronization proof; pinned Git object provenance also remains unavailable.
- 冲突访问对：Candidate SetStreamRecvListener write versus channel-creation read; focus constructor read is not itself a conflicting write.
- 触发窗口：Listener replacement versus channel creation/callback setup; not proven.
- 生命周期：StreamManager/listener/socket callback lifetime overlap is unknown.
- 入口/权限：SoftBus stream/channel family only; product privilege and attacker control unknown.
- CIA 依据：Concrete CIA impact unknown.
- 独立结论：Source provenance and concurrency obligations unresolved; retain unknown.
- 证据位置：sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67,87-110；sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.cpp:58-61,88-95,172-185
- 待补事实：Whether channel creation and SetStreamRecvListener can execute concurrently on one StreamManager.；Publication ordering between streamListener_, socketListener_, and the socket callback.；Reachable trigger and CIA consequence in the product.
- 最小复现方向：Race SetStreamRecvListener with CreateStreamClientChannel/CreateStreamServerChannel in a controlled StreamManager harness under TSan, then repeat with a common mutex or immutable listener publication.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 9c78273d5197f6b0

- Review item：`4e5f35efb3f6c9480e5016776b81acd7e82b5fd3aacbd5aa211c0ed7dda3dc2d:holdout`；Candidate：`4e5f35efb3f6c9480e5016776b81acd7e82b5fd3aacbd5aa211c0ed7dda3dc2d`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `40fbde49afe414ccb8efd625d05b12a1bc71daae`；source SHA-256 `2ff4b5f81e9305bb595477281b49ff744d516c90ac962e4c0baf8f34416eb9af`；`wmserver/include/window_common_event.h:41:64` `read` `eventHandler_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Nested EventSubscriber constructor and CommonEvent callback; event queue unknown.
- shared_ptr 发布顺序：Nested member initialized from parameter and not reassigned.
- 同步协议：No same-object owner pair for selected nested member.
- 冲突访问对：Constructor initialization and callback read only.
- 触发窗口：No owner-race window established.
- 生命周期：Subscriber/handler shared_ptr lifetime.
- 入口/权限：Common-event family only.
- CIA 依据：No concrete CIA impact.
- 独立结论：Selected nested member is owner-stable in fixed source.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## a434fff861916fd3

- Review item：`7aa20f345a3a8e08566e1b7d2187ff5652e709007c2f1dcae385ce39256548ef:plausible`；Candidate：`7aa20f345a3a8e08566e1b7d2187ff5652e709007c2f1dcae385ce39256548ef`；Scope：`plausible_unproven`
- 固定来源：repository `openharmony/distributeddatamgr_kv_store`；commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`；tree `3b92c53fde616d5a3f9487b0c295670a42c63023`；blob `19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46`；source SHA-256 `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`；`frameworks/common/js_proxy.h:37:9` `write` `instance_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unknown`；最终标签：`unknown`
- 分歧：none: blind label and A-line technical suggestion agree
- 线程/事件队列归属：SetInstance(nullptr) in result-set close/release may overlap GetInstance in NAPI operations; NAPI execute/complete queue affinity is unknown.
- shared_ptr 发布顺序：SetInstance move-assigns/clears instance_; GetInstance copies it; no happens-before or atomic owner protocol is shown.
- 同步协议：No complete owner mutex/atomic shared_ptr protocol.
- 冲突访问对：Same-object owner pair: js_proxy.h:37 write and :42 read, including release-time SetInstance(nullptr) versus queued/operation-time GetInstance.
- 触发窗口：Possible close/release versus queued operation overlap; not proven.
- 生命周期：Result-set wrapper and inner instance lifetimes may overlap across NAPI operations.
- 入口/权限：Representative result-set NAPI entry only; privilege/attacker control unknown.
- CIA 依据：Potential memory-safety/availability impact remains hypothetical.
- 独立结论：Real owner pair but unresolved queue, trigger, entry/privilege and CIA facts; retain unknown.
- 证据位置：frameworks/common/js_proxy.h:29-44；frameworks/jskitsimpl/distributeddata/src/js_kv_store_resultset.cpp:73-286；frameworks/jskitsimpl/distributedkvstore/src/js_kv_store_resultset.cpp:79-297；frameworks/jskitsimpl/distributedkvstore/src/napi_data_share_adapter.cpp:89-111
- 待补事实：NAPI execute/complete thread affinity and callback queue ordering for each JSProxy subtype.；Whether SetInstance(nullptr) can overlap a queued GetInstance operation.；Product entry, attacker control, and concrete CIA impact.
- 最小复现方向：Run concurrent SetInstance(nullptr) and GetInstance calls for a representative result-set wrapper under TSan, then repeat after serializing owner mutation through the actual NAPI queue.
- 签字：`Codex-independent-reviewer/2026-10-15`

## addd5418e89eb1f1

- Review item：`2c8c1796905c2ba3189b24ea3fb4537419cfc3fa215adebc63b65a36bffba8bc:holdout`；Candidate：`2c8c1796905c2ba3189b24ea3fb4537419cfc3fa215adebc63b65a36bffba8bc`；Scope：`holdout`
- 固定来源：repository `openharmony/security_access_token`；commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`；tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0`；blob `b6adec200d1500ae4148a5a801364fa38e81a99a`；source SHA-256 `ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed`；`interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h:72:9` `write` `asyncContextPtr`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Constructor/member initialization or stable-owner read; no post-construction owner write shown.
- shared_ptr 发布顺序：Member initialized during construction; no later owner reassignment/reset found.
- 同步协议：No same-object conflicting owner pair.
- 冲突访问对：No same-object conflict in fixed source.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Owner-stable constructor/use shape.
- 入口/权限：Code location only; product entry/privilege unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee internal thread safety and safe publication remain outside this owner-race disposition.
- 最小复现方向：Only needed if a later owner assignment or cross-thread pointee mutation is discovered.
- 签字：`Codex-independent-reviewer/2026-10-15`

## b578e1c0b3670993

- Review item：`93c2385311e2c10ecbfe8c0f78776474bc6264b5cbd0baeb50e33caaf4aeeb30:holdout`；Candidate：`93c2385311e2c10ecbfe8c0f78776474bc6264b5cbd0baeb50e33caaf4aeeb30`；Scope：`holdout`
- 固定来源：repository `openharmony/security_access_token`；commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`；tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0`；blob `5ee7e75ff720127386ef77cc515d979613ee81b5`；source SHA-256 `1e6804e8f930cab69885c4d8e493768ad2dc5ce33e7faa3e1a92d906e5b4e0b2`；`interfaces/kits/cj/accesstoken/include/request_global_switch_on_setting.h:51:9` `write` `asyncContextPtr`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Constructor/member initialization or stable-owner read; no post-construction owner write shown.
- shared_ptr 发布顺序：Member initialized during construction; no later owner reassignment/reset found.
- 同步协议：No same-object conflicting owner pair.
- 冲突访问对：No same-object conflict in fixed source.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Owner-stable constructor/use shape.
- 入口/权限：Code location only; product entry/privilege unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee internal thread safety and safe publication remain outside this owner-race disposition.
- 最小复现方向：Only needed if a later owner assignment or cross-thread pointee mutation is discovered.
- 签字：`Codex-independent-reviewer/2026-10-15`

## bc7c8154a71b4ae2

- Review item：`1e0688494c36112e34cd1f27f9c35be050c26bb3ffec36ed41e8b0de1cb9fa00:holdout`；Candidate：`1e0688494c36112e34cd1f27f9c35be050c26bb3ffec36ed41e8b0de1cb9fa00`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `562b504ae819cd154f515bc264038f7f3cd3100c`；source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`；`previewer/include/wm_animation_common.h:289:56` `read` `excludeFromRecent`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## bffe538666df990b

- Review item：`a786eb0afcb5cd995219af27c26d2770b3d5e9560a394868769adfdbb3c03fee:holdout`；Candidate：`a786eb0afcb5cd995219af27c26d2770b3d5e9560a394868769adfdbb3c03fee`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `8c6a9f3774155f25d1deb5f431faef5ca26f5f1f`；source SHA-256 `fe3710593c477a3c4e450eee87e8ab89267a0312738bacece7f34686d7fa2e1b`；`interfaces/kits/napi/float_view_napi/js_float_view_listener.h:32:22` `read` `jsCallBack_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Listener construction and NAPI callback dispatch may differ; post-construction owner operations are reads/copies.
- shared_ptr 发布顺序：Owner copied in constructor and into NAPI lambdas; no replacement/reset.
- 同步协议：No conflicting owner write after initialization.
- 冲突访问对：No same-object owner write/read pair.
- 触发窗口：No owner-race window established.
- 生命周期：Listener/NativeReference captured by callbacks.
- 入口/权限：PiP/floating-ball/float-view callback family only.
- CIA 依据：No concrete CIA impact.
- 独立结论：Stable owner initialization/read-only propagation excludes observed owner race.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## cacae956a5a61860

- Review item：`869e521a61c57900b90bc59f13ce6c298aa86da99f03996db8340bfccc09ebe9:holdout`；Candidate：`869e521a61c57900b90bc59f13ce6c298aa86da99f03996db8340bfccc09ebe9`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `eae1ac64199017f10cff98cc2a470a18b7205b41`；source SHA-256 `1864f6e38e779147011fadcd468da3e2594b3f883f30366f8a7e85b1ac0251cb`；`utils/include/ui_effect_controller_common.h:53:48` `read` `effect_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：ConvertFromJsValue and IsEmpty are sequential in one NAPI flow; Unmarshalling writes a fresh object.
- shared_ptr 发布顺序：Writes precede IsEmpty read on a local/new object; no post-publication same-object mutation shown.
- 同步协议：No same-object conflicting pair for observed shape.
- 冲突访问对：No same-object post-publication owner pair.
- 触发窗口：No owner-race window established.
- 生命周期：Local/new UIEffectParams lifecycle only.
- 入口/权限：UI-effect NAPI family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Fresh-object/sequential shape excludes observed owner race, not product safety.
- 证据位置：utils/include/ui_effect_controller_common.h:46-62；utils/src/ui_effect_controller_common.cpp:50-76,110-130；interfaces/kits/napi/window_runtime/window_napi/js_ui_effect_controller.cpp:125-130,173-192；window_scene/session/host/src/ui_effect_controller_stub.cpp:41-56
- 待补事实：Pointee Filter/VisualEffect thread safety is outside this owner-race disposition.
- 最小复现方向：Only needed if a same UIEffectParams object is mutated after publication or concurrently parsed.
- 签字：`Codex-independent-reviewer/2026-10-15`

## cc38ebb39a402845

- Review item：`f6f50c28e7e1dd49302cecc20d4ecbd713d0e5e7f97d0e813bf3aa6c49e633f9:holdout`；Candidate：`f6f50c28e7e1dd49302cecc20d4ecbd713d0e5e7f97d0e813bf3aa6c49e633f9`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `3c325423cb185f8275e3eb62853ef9c16477aef9`；source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`；`interfaces/innerkits/wm/wm_animation_common.h:289:54` `read` `excludeFromDock`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Marshalling reads; Unmarshalling writes a newly allocated distinct object.
- shared_ptr 发布顺序：Fresh object is filled before return; no same-object publication/mutation sequence shown.
- 同步协议：No same-object conflicting pair established.
- 冲突访问对：Marshalling read and Unmarshalling assignment target distinct objects.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Parcelable construct/serialize/deserialize lifecycle.
- 入口/权限：Window/animation parcel family only; privilege/CIA unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Observed sites are not a same-object concurrent owner pair.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现方向：Only needed if a same-object owner mutation path is found.
- 签字：`Codex-independent-reviewer/2026-10-15`

## ce61b4591bfb3ad9

- Review item：`a1278c524438add8635a68621e5f4b9d5bd8b9f98775d34ab6f8d39b783dc116:holdout`；Candidate：`a1278c524438add8635a68621e5f4b9d5bd8b9f98775d34ab6f8d39b783dc116`；Scope：`holdout`
- 固定来源：repository `openharmony/security_access_token`；commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`；tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0`；blob `5ac2150911a4e2cc107ce1d28f0553c93bbe0512`；source SHA-256 `a8108746a4d3f7817bdf6e95e50df46d56f9cf6871d616abf214af4d0fc62450`；`interfaces/kits/cj/accesstoken/include/request_permission_on_setting.h:49:9` `write` `asyncContextPtr`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`unrelated`；最终标签：`unrelated`
- 分歧：blind=unknown vs A-line=unrelated; recorded as disagreement. Final=unrelated is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Constructor/member initialization or stable-owner read; no post-construction owner write shown.
- shared_ptr 发布顺序：Member initialized during construction; no later owner reassignment/reset found.
- 同步协议：No same-object conflicting owner pair.
- 冲突访问对：No same-object conflict in fixed source.
- 触发窗口：No feasible owner-race window established.
- 生命周期：Owner-stable constructor/use shape.
- 入口/权限：Code location only; product entry/privilege unknown.
- CIA 依据：No concrete CIA impact.
- 独立结论：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据位置：See the per-item source context generated from the pinned Git blob.
- 待补事实：Pointee internal thread safety and safe publication remain outside this owner-race disposition.
- 最小复现方向：Only needed if a later owner assignment or cross-thread pointee mutation is discovered.
- 签字：`Codex-independent-reviewer/2026-10-15`

## ea22cf515d93fc90

- Review item：`91a5f46b96a11a6166bccc207946d7524912938daf1cb7058fd89d79cd8ce881:holdout`；Candidate：`91a5f46b96a11a6166bccc207946d7524912938daf1cb7058fd89d79cd8ce881`；Scope：`holdout`
- 固定来源：repository `openharmony/window_window_manager`；commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`；tree `24e60146ba2fe4af3aaef20b306a1e306df44617`；blob `5554d63b22a4de01654c415717b13e9579ba9fdf`；source SHA-256 `6ddefa22004292cbb0d771f76fc317864493478b2f6366be56c259ff75a57fb7`；`utils/include/surface_capture_future.h:73:18` `read` `pixelMap_`
- Git 对象核验：commit=True / tree=True / blob=True / source_sha256=True；provenance_verified=True
- 盲审标签：`unknown`；A 线技术建议：`safe`；最终标签：`safe`
- 分歧：blind=unknown vs A-line=safe; recorded as disagreement. Final=safe is based on independent fixed-object/source analysis, not on treating the A-line suggestion as truth.
- 线程/事件队列归属：Callback writes and waiter reads may be on different threads; all observed pixelMap_ accesses are mutex-serialized.
- shared_ptr 发布顺序：Writes and reads use mutex_; notify occurs after writes under the lock.
- 同步协议：Complete observed pixelMap_ owner access set uses mutex_; scoped owner-race proof only.
- 冲突访问对：GetHDRResult read versus Call write is present but serialized by mutex_.
- 触发窗口：No unsynchronized owner window remains for the observed set.
- 生命周期：Future object remains alive across callback/waiter; owner synchronization established.
- 入口/权限：Product entry/privilege not established; label is only shared_ptr owner scope.
- CIA 依据：PixelMap pointee safety and product CIA remain outside scope.
- 独立结论：Independent fixed-source check supports safe only for observed owner synchronization.
- 证据位置：utils/include/future.h:22-52；utils/include/surface_capture_future.h:30-58,66-95
- 待补事实：Pointee PixelMap thread safety and product-level CIA impact are outside this owner-race disposition.
- 最小复现方向：Keep as a safe synchronization control and verify that concurrent callback/GetResult runs remain clean under TSan.
- 签字：`Codex-independent-reviewer/2026-10-15`

## 签字边界

- 未参与首轮候选分诊；盲审标签在打开 key 与 A 线补充前冻结。
- 本对照记录不把 A 线建议当真值，不升级 candidate/review/case/confirmed/reportable。
- 未证明入口/权限、触发、可达敏感操作、同步交错和 CIA 的项目保持 `unknown`。
- 未计算 Precision/Recall。

