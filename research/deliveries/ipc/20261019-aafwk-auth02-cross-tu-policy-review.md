# AAFWK AUTH-02 跨文件授权策略复核

复核日期：2026-10-19
复核对象：openharmony/aafwk_standard，固定 commit 834a566b1372268c7bbb0c40362322f812ca6efc，tree c3744c8c230573a4bcdb76bf49493a1ea61c72d1。
检测器：B 线 ohscanner.interface.ipc 0.12.12；规则 ipc.auth.missing。
目的：对成员函数指针语法归一化后由 partial 变为 complete 的六条 AUTH-02 观察，沿固定源码复核 stub 到服务端实现的完整策略路径。

## 结论

六条观察都能从 IPC stub 连到 AbilityManagerService 中的集中策略路径。固定源码显示：五条经过目标权限、可见性或 URI 策略；StartAbilityByCall 经过专用 caller/target 关系及目标类型检查。它们不支持“这些 IPC 入口没有授权/策略”的原始解释。

本轮建议将这六条的人工复核分类设为 **likely false positive：stub 局部规则漏掉跨文件集中策略**。这不是“所有目标都可访问”的证明：普通 Ability 是否允许被调用取决于该目标的静态权限、visible、类型与调用者身份。扫描器没有为这些泛化入口绑定具体应用 manifest/设备策略，因此不能据此确认任何目标安全，也不能把结果升级为 confirmed 或写成 validated_vulnerability。

这批样本揭示的可改进点是 AUTH-02 的授权识别边界：它目前能在局部路径找到守卫，却不能可靠地将 stub 派发与服务端策略摘要关联。下一步应增加窄、可审计的跨文件服务端策略摘要；不要通过扩大函数名词表或看到任意权限检查就压掉候选。

## 候选与复核结果

六个候选在旧三态候选表中保存为 candidate_confidence=unassessed；归一化复测的 candidate_parse_status.csv 对应行显示 parse_status_after=complete。本报告只增补人工复核，不改写候选身份、原始 JSON、旧首轮 triage 或扫描统计。

| 候选键 | Stub 锚点 | 固定源码中的服务端策略 | 复核 |
|---|---|---|---|
| 6b647cabf7f0f066 | AbilityManagerStub::StartAbilityInner，ability_manager_stub.cpp:354 | AbilityManagerService::StartAbilityInner（service :332）先执行账号/调用 token 与用户校验，再执行 CheckStaticCfgPermission(:365)、JudgeAbilityVisibleControl(:371)，之后才进入启动逻辑 | likely FP：stub-local 授权模型未看到集中策略 |
| 35037c7457b37cc7 | AbilityManagerStub::StartAbilityAddCallerInner，:415 | 服务端另一入口在 :323 汇入同一 StartAbilityInner(:332)，使用同一权限及可见性路径 | likely FP：同上 |
| 77205eb05a91a43d | AbilityManagerStub::ConnectAbilityInner，:437 | ConnectAbility 校验账户权限；本地连接进入 ConnectLocalAbility(:1251)，检查目标静态权限 :1272、URI 授权，并检查目标可见性 :1282 与目标类型 | likely FP：授权在服务端目标解析后集中执行 |
| c03cc11b2e973da3 | AbilityManagerStub::StartAbilityForSettingsInner，:523 | 对应 StartAbility overload 在 service :414 起执行目标静态权限检查 :465 与可见性检查 :472，然后进入启动逻辑 | likely FP：设置参数没有绕过目标策略 |
| f8f258fa942240eb | AbilityManagerStub::StartAbilityForOptionsInner，:549 | 对应 overload 在 service :535 起执行 CheckStaticCfgPermission(:587) 与可见性检查 :594 | likely FP：选项参数没有绕过目标策略 |
| fc232fa03f25b655 | AbilityManagerStub::StartAbilityByCallInner，:1008 | 服务端 StartAbilityByCall(:3453) 执行 CheckCallPermissions(:3483)；helper :3519 对普通应用核对 caller/target bundle 与 UID 关系，并限制目标为 singleton page ability | likely FP：专用调用授权路径存在 |

## 关键策略语义

- CheckStaticCfgPermission（ability_manager_service.cpp:4245）读取解析出的目标 Ability 权限；对配置的权限用调用者 AccessToken 校验。对 DATA / DATASHARE 另检查 read/write permission。
- 该函数在目标没有静态权限配置时返回 granted（permissions.empty()，约 :4264）。这表示可公开目标按产品策略允许调用，不是“缺失检查被绕过”。
- JudgeAbilityVisibleControl（ability_util.h:151）对不可见目标，要求调用者为系统侧或与目标同 bundle；可见目标本身可以由普通调用者访问。因此不能把它粗略等价为“所有 caller 必须有系统权限”。
- StartAbilityByCall 的 CheckCallPermissions 规则不同于普通启动：非 SA、非系统特权 caller 需要与目标 bundle/UID 满足约束，且目标类型/启动模式受限。
- 本仓源码证明服务端策略路径存在并被这些入口调用；它不包含此次复核所有可能目标应用的 manifest、设备上实际安装配置或运行时 caller 身份，故影响面的目标化结论仍未知。

## 对检测器的具体建议

1. 在 AUTH-02 上建立有限的跨文件摘要：stub transaction → 唯一服务端 override → 服务端 helper → 检查对象/检查结果 → 敏感操作。只在源码身份和调用关系唯一时建立关联；缺实现、多实现、外部调用或解析 partial 时保留 unknown。
2. 为 AbilityManager 模式单独建策略摘要：目标静态权限、目标 visibility、调用者 bundle/UID/SA 身份、目标类型。报告说明实际识别到的策略条件，不将“存在同名 helper”作为授权证据。
3. 若目标元数据不在扫描快照中，候选应说明“目标策略未绑定”，而不声称“一定缺少授权”。可把这类结果分为 centralized_policy_observed / target_policy_unbound，但状态字段或 taxonomy 变更需先走公共契约评审。
4. 新规则验收至少包括：本报告六条作为跨 TU 正例；同名但未调用 helper、检查发生在副作用之后、检查调用结果未用于拒绝、目标策略不匹配四类负例；另加一个真实存在的无授权服务端入口作为阳性对照。复跑八仓固定对象并逐条解释集合变化。
5. 在这些对照完成前，不改现有候选，不把这六条计为已确认漏洞，也不以候选数量减少单独宣称准确率提高。

## 固定源码绑定

| 文件 | Git blob | Git blob 内容 SHA-256 |
|---|---|---|
| services/abilitymgr/src/ability_manager_stub.cpp | 9d9d65813728e6d6da0716f93813e63228f3a3fd | 182fc1f0f1d52a3c543b3dd360871334af41d41a3189782eee37af0e6f9e6d4c |
| services/abilitymgr/src/ability_manager_service.cpp | 92db77f364c30ead75d060748a092847c64539d2 | d49042ecc16a55eddcc158dc64cae0c8918310ce9e126afab0d0c54ce2694669 |
| services/abilitymgr/include/ability_util.h | bae48ab909e88dfc11b4b8d811138877719d6b8a | 3dda6a9e07ee2da8cdaca2afc8d97fb2502adefc44474147eb2571a6104a9801 |

哈希均由固定仓库的 git show <commit>:<path> | sha256sum 计算，不取自可变工作树。复核命令示例：

    TARGET=/home/audit/oh-audit-targets/bline-campaign-100-retest-20261018/aafwk_standard
    COMMIT=834a566b1372268c7bbb0c40362322f812ca6efc
    git -C "$TARGET" show "$COMMIT:services/abilitymgr/src/ability_manager_service.cpp" | sed -n '332,412p'
    git -C "$TARGET" show "$COMMIT:services/abilitymgr/src/ability_manager_service.cpp" | sed -n '4245,4295p'
    git -C "$TARGET" show "$COMMIT:services/abilitymgr/src/ability_manager_service.cpp" | sed -n '3453,3559p'

归一化前后八仓候选键逐条相同（30→30，身份变化 0），该 parser-normalization 回归为 727 tests OK、36 skipped。此报告只对上表六条做了跨文件人工复核；其余从 partial 变 complete 的观察及仍 partial 的观察均未因此自动重新判定。未运行产品构建或设备运行时验证。
