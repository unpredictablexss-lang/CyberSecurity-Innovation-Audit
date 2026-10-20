# Pasteboard AUTH-02 候选：本地授权路径与外部服务策略边界

复核日期：2026-10-19
固定目标：openharmony/miscservices_pasteboard @ dd22c7cb5e5f207a6c38c50f45b7369ee8575840；Git tree e374a0d61c9ec664ddd29fc17002797828c480ee。
检测器：B 线 ohscanner.interface.ipc 0.12.12；规则 ipc.auth.missing。
候选键：7779a7b5e28e2bbf（GET_PASTE_DATA，line 77）、4dfe40f12a62f809（SET_PASTE_DATA，line 107）。归一化复测将宿主文件从 partial 改为 complete，两个候选键和源码锚点未变。

## 结论

固定源码中两条派发路径都完整可读，stub 执行 descriptor 校验后直接调用 GetPasteData / SetPasteData。被调服务方法将来访 UID 映射为 OS user ID，以该 user ID 读取或替换该用户的剪贴板；这些方法本身没有看到按应用身份、前台状态或 pasteboard 权限执行拒绝的逻辑。

当前材料不足以把这两条标成 false positive，也不足以确认漏洞。组件 init 配置将服务启动配置指向 /system/profile/pasteboard_service.xml，但该产品侧 SA profile 不在固定仓库快照内；目标版本的 SAMGR/SA 获取策略、客户端前台限制是否可由普通应用绕过、特定构建部署的 access-control 均未核实。因此准确结论是 **source-local authorization not observed; product reachability and external policy unknown**。两条候选应保留为 unassessed/unknown，不能删掉，也不能升级为 confirmed。

GET 与 SET 分别涉及剪贴板内容读取与全用户剪贴板写入，候选键和证据必须分开保留。按同一根因把它们合并成一条会丢掉不同操作的影响与授权策略。

## 固定路径

1. PasteboardServiceStub::OnRemoteRequest 读取接口 token 并比对自身 descriptor；随后按 code 查 memberFuncMap_，未发现本地 caller/permission guard。
2. OnGetPasteData（stub :73-88）调用 GetPasteData；返回的 PasteData 被序列化写入 reply。
3. OnSetPasteData（stub :98-111）反序列化请求中的 PasteData 后调用 SetPasteData。
4. PasteboardService::GetPasteData（core :155）调用 GetUserId，根据该 userId 从 clips_ 读取并复制剪贴板数据；没有应用级 caller check。
5. PasteboardService::SetPasteData（core :190）同样按 userId 替换该用户 clips_ 内容并通知 observers；没有应用级 caller check。
6. GetUserId（core :211）调用 IPCSkeleton::GetCallingUid() 后映射 OS account local ID。它证明的是同 OS 用户数据分区，不等价于 per-app 授权。
7. 仓内 etc/init/pasteboardservice.cfg 将 service path 指向 /system/profile/pasteboard_service.xml；该 XML 和实际产品的 SA ACL/访问策略不在本次扫描输入中。
8. 客户端 NAPI 包装、前台/焦点策略及真实设备 system ability 获取路径尚未在此固定提交上闭环；不能假定客户端约束可以保护直接 IPC 调用，也不能假定普通 app 能直接获得服务句柄。

## 候选判定

| Candidate | 当前建议 | 已验证 | unknown |
|---|---|---|---|
| 7779a7b5e28e2bbf | 保留 candidate / unassessed；不因“按 UID 分用户”降级 | descriptor gate、read dispatch、reply 写出、按 calling UID 派生 userId、按 userId 读剪贴板 | 普通 app 是否能取得该 SA 句柄；SA profile ACL；产品前台/焦点访问要求；数据暴露的调用者/用户场景 |
| 4dfe40f12a62f809 | 保留 candidate / unassessed；不因“按 UID 分用户”降级 | descriptor gate、write dispatch、parcel 输入、按 calling UID 派生 userId、按 userId 替换剪贴板并通知 observer | 同上；另外写入是否受系统策略限制、跨应用覆盖的产品安全语义 |

这只是源码复核结论，不是漏洞确认。字段 validated_vulnerability 仍为 0；没有设备 PoC、产品构建或动态测试。

## 下一步证据与检测器改进

- 获取该固定产品版本对应的 pasteboard_service.xml、SA profile 与 SAMGR 访问策略，固定其 commit/blob/hash；不能拿新版本 ACL 替代旧 commit 的产品配置。
- 以真实产品构建确认普通应用能否 GetSystemAbility(3008) 或通过公开 API 获得句柄；若无法直接取得，记录构建/签名/权限证据。若能够取得，再以测试应用分别调用 GET/SET 做受控行为验证。
- 检查 NAPI/客户端路径的前台限制，并确认服务端是否存在可绕过的直接 IPC 路径；客户端限制本身不能作为服务端 authorization。
- 对 AUTH-02 增加 authorization boundary source 证据分类：stub/helper 内策略、系统服务层策略、构建/SA profile 外部策略、未解析。只有固定版本产品证据才能把外部策略从 unknown 收敛。
- 保留当前原始候选输出；新增复核侧车记录 source-local 结论和外部义务，不用规则名或 candidate message 替代策略证明。

## 源码绑定

| 文件 | Git blob | 内容 SHA-256 |
|---|---|---|
| services/zidl/src/pasteboard_service_stub.cpp | 3dbc3150ada27a765938f06ea6e8cfd0a2d7146b | d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868 |
| services/core/src/pasteboard_service.cpp | c380ac266a85edd818caa811f11b99722d351788 | 73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52 |

哈希由固定 commit 的 git show <commit>:<path> 计算。没有修改跟踪源码、检测器、测试或产品配置。当前分支此前全量测试为 727 tests OK、36 skipped；本轮仅新增复核文档，没有重跑测试。本报告补充八仓归一化复测，不据此声称 parser 改进本身提升了漏洞准确率。
