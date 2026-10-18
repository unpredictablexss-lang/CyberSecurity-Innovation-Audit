# D1 / T1 / T2 独立测试审计（2026-10-18）

## 结论

本审计只核对现有交付，不替作者补写或改写 D1/T1/T2 的证据，不作漏洞可利用性判断。D1 按 D 敏感日志检测器首阶段交付解释；T1 按 Contacts `PortraitFileName` 产品证据补充解释；T2 按 2026-10-17 产品技术文档的“官方目录 / Git 缓存”里程碑解释。没有找到单独命名为 T2 的验收包。

| 交付 | 判定 | 可供 owner/mainline 审阅 | 关键结论 |
|---|---|---|---|
| D1 | **partial** | 可作研究原型审阅；不可据此准入产品或确认漏洞 | exact D1 commit/tree、代码和 10 项专属测试可核验；9 个目标源 blob 本机缺失；无 D ownership lane；真实扫描 0 candidate 且 3 partial / 6 not analyzed；无独立 holdout。 |
| T1 | **block** | 需要先统一报告状态并解决越界/重放缺口 | Contacts/DataShare 8 个 A0 源对象与 97 项包内文件 hash 复核通过；产品 build/权限/SELinux 未证明，PoC 镜像 digest 不匹配；旧总览和 adjacent finding 标 `confirmed`，独立补充正确降为 `partial/unknown`；补充文件在 detached worktree 且 scope check 报 1 项越界。 |
| T2 | **block** | 目前是规划项，不是可验收交付 | 规范要求 10 个官方仓库及 clone/fetch、断网/过期/重定向/不完整历史测试；无 T2 交付、来源授权清单或该故障矩阵。已有 source manifest/planner 明确不验证官方归属，也不是 repository catalog/cache 实现。 |

**漏洞状态：**`ohscanner-contacts-path-traversal-001` 保持候选/产品状态 `partial` / `unknown`；D1 也保持 syntax candidate。当前证据均不足以建议 `confirmed/reportable`。A0 的 mechanism/harness `confirmed` 不能替代 A1 产品证据门。

## 基线、对象与 worktree

### D1

- D1 commit：`f11d5fdf4ab01a345a1ffb702b18edb6b5109a38`；tree：`88a9bd447443efb3b739f41a268e0530c6baafad`；parent/base：`e510c99c67f31ec6c73365f9ab749c79ca6ff0a1`。
- detector：`src/ohscanner/detectors/data/sensitive_exposure.py`，在 D1 commit 中重算 SHA-256 `710f0eaef8f26dc6295a724a0554caf456d399e1a5f69acabd7b9b951a9d5d3d`，17,884 bytes。
- D1 manifest 固定目标 `openharmony/communication_dsoftbus@0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132`，tree `bd915661eedd139df17f249191e2a691e76f7565`、9 文件。该 commit/tree 可读，但当前 OpenHarmony `.repo` 对象库不含此 commit。独立 bare fetch 可取 commit/tree；blob 懒加载时 GitHub 443 连接失败，因此 9 个 source SHA-256/blob 本轮未能独立重算。D1 manifest 自述的 hash 不能等同于本轮 source-byte 复核。
- 精确 D1 commit 的 detached 测试工作树：`D:\openHarmonyScanner\worktrees\audit-d1-f11d5fd`，HEAD 固定为 `f11d5fdf…`，clean。命令 `python -m unittest tests.detectors.data.test_sensitive_exposure -v`：10 tests，pass。D1 交付的全仓记录是历史快照：522 total / 511 passed / 11 skipped / 0 failed；未在本审计完整重跑。
- D1 `validation.json`：32 synthetic controls、`independent_holdout=false`、真实 replay 9 文件 / 0 candidates / 0 complete、3 partial、6 not_analyzed、`validated_vulnerability=0`、`catalog_registered=false`。统计与候选/确认分离准确，但只支持有限研究原型。
- D1 工作树基线 e510 不含 `config/collaboration/ownership.json`，也没有 `data` lane；同一时点 scope checker 不存在。用 D1 base 调用后续 checker 因 ownership 文件缺失失败；D1 commit 也不是后来集成 SHA `1c21ac60890fca0ce6be5d50d82e4757dd5e4623` 的后代，不能伪称在集成 base 上 scope pass。D1 commit 的 changed paths 还包括 `docs/项目现状与下一步.md`，越出 D2 handoff 所列的 D-only 范围。责任：D 交付 owner / 集成人补齐可信 ownership/base 并重新给出 scope 结果。
- 最新可见 D 分支是 `origin/feat/teammate-d-sensitive-exposure-20261017@c9447e4`；D1 本身是该后续分支的历史阶段，不等于当前 D 版本。未修改远端分支/PR 状态。

### T1

- A0 绑定 Contacts：repo `openharmony/applications_contacts_data`，commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`，tree `2054824c04bb403eeea128a9262edfb3001efa4f`，path `dataBusiness/contacts/src/contacts_data_ability.cpp`，blob `c93e950725adc93276916b3c96c5ac7a5bb5b6b7`，source SHA-256 `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`。
- 独立从 Git 原始对象核对 Contacts/DataShare 共 8 个 manifest 文件：两 repo tree 匹配；8/8 字节数、blob SHA-1、source SHA-256 全通过。T1 独立补充记录 SHA-256 `9c6c41c0794ba207d492365454e89601ea89d3ac36830b8fabca9007e64ee61f`。
- A0 交付包 `evidence/hashes.json` 中 97/97 文件大小和 SHA-256 通过。release 对象复核与 T1 补充表一致：5.0.2、5.1.0、6.1 Release、6.1-LTS、7.0 对象存在；5.0.3 和 6.0 commit 本机缺失，保持 blocked。已存在对象中，6.1-LTS / 7.0 / 当前 master 代码快照保留路径链；这不是设备固件/产品版本映射。
- PoC 证据不是固定镜像重放：记录声称的 PoC digest `sha256:1f28ead56a68352c2bbbbd4fb45523a237f271dc3be827b073b9274986a2a829` 与保存的通用 `image_inspect.json` digest `sha256:e92d5365460142169ddd21d489bc9157d003c61e3382351c8f8516f3e38f96ae` 不同；T1 补充还指出没有完整外层 Docker argv。当前 WSL Docker integration 不可用，不能复跑。历史 adapter 的 vulnerable/fixed/safe/fixed-safe 结果只证明测试文件树机制；`patched_target_adapter` 不是上游 fixed patch。ASan/UBSan probe exit 139 按失败/限制保留。
- 产品证据不足：没有匹配产品 HAP/镜像、真实 bundle 签名/授权授予、服务 UID/DAC/SELinux 策略、可删除路径边界、官方 fixed patch 与 build mapping。T1 补充已正确写 `partial/unknown`；其上游 README、`technical-report.md`、`evidence/adjacent_findings.json` 仍把同一 finding 标为 `confirmed`，并宣称可删除服务可访问的“任意文件”。该状态违反 technical report 自己第 2.2 节的 confirmed gate（入口权限、具体影响、可复现产品构建/运行）。这不是单纯措辞差异，必须统一机器记录、README、报告、Excel 与远端包计数。
- 独立 T1 文件只作为未跟踪文件存在于 detached worktree `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit-t1-independent-20261018`，HEAD 为 immutable base `1c21ac60890fca0ce6be5d50d82e4757dd5e4623`，worktree status 一项 untracked。检查命令 `python -m scripts.check_change_scope --base 1c21ac60890fca0ce6be5d50d82e4757dd5e4623 --lane cpp --repo .` 返回 `violations=[research/deliveries/a-line-sample30/20261018/T1_independent_followup_20261018.md]`。基线 policy 只允许 `research/deliveries/cpp/**`，故零越界门未通过。责任：A/T1 作者将交付放进获准目录并保留来源；样本包 owner 统一 `confirmed` 状态与计数，再由集成人在可信 base 重跑 scope。

### T2

- 需求来源 `research/product/20261017/技术文档1.0.md` 的来源 manifest SHA-256 `75e97f54a5cb4844cd904e09ba4d578892b0484334ed6b5478aa2d95f996f061`；T2 定义为“官方目录/Git 缓存”，验收至少 10 个 official repos，并测试断网、过期、重定向、不完整历史。
- 未找到 T2 实施交付、10 repo source manifest、clone/fetch cache 结果或相关测试日志。`src/workbench/sources/manifest.py` 的模块说明是绑定调用方提供的身份而非认证官方仓库；`src/workbench/planning/audit.py` 明列 repository name 不能证明官方归属、plan digest 不是执行缓存身份。`settings.py` 创建 `repo-cache` 目录及 `operations.py` 对路径的防护不足以证明 Git catalog/cache 功能。
- 责任：产品/平台 owner 提供 T2 implementation commit、官方目录来源与版本、固定 10 repo manifest、缓存失效/离线/重定向/不完整历史测试及原始日志；当前只能标 `blocked/not delivered`。

## 当前 A 线远端更新与范围

- A path candidate branch：`codex/a-path-source-sink-20261018`，base `1c21ac60890fca0ce6be5d50d82e4757dd5e4623`。审计开始时 HEAD `d90535ed22fdaf860c08c35c0e8f6560192c7cce`；工作期间外部更新为 `77a13bf5a85a8f662f615b1e86bcad8752a1dbaa`，现已核对 `origin/codex/a-path-source-sink-20261018` 同步到该 SHA。
- `python -m scripts.check_change_scope --base 1c21ac60890fca0ce6be5d50d82e4757dd5e4623 --lane cpp --repo .` 在父提交及其 20 个路径上为 0 violations；加入本审计文件和 exact excerpt 后，最终检查为 21 paths / 0 violations。
- 当前 path detector SHA-256 `f1d2742c1e131b0a4e7e1954ceeec68554749056696a16742efa54d45e54589d`。本轮复跑专属 detector 当前为 7 tests pass；A detector suite 为 138 tests pass。A_PATH delivery 仍记录 8 项 / 139 项，这与当前测试树计数不一致。父提交 `77a13bf` 未包含 `contacts_exact_excerpt.cpp`；本次推送会带上该源码文件。当前 7 项测试未对 exact excerpt 建立独立断言。原始 excerpt 精确保留两行尾随空格，因此对新增文件执行 `git diff --check` 会在 excerpt 行 65、115 报 trailing whitespace；这是为保持 raw excerpt hash 而保留的字节，仍需 owner 决定保留原始 excerpt 并记录例外，还是规范化后同时记录 raw/normalized hashes。责任：A detector author 校准交付统计并补齐该 excerpt 对应回归，再重跑并推送；本审计不替代该实现修复。

## 最小修复任务与责任

1. **D lane / 集成人**：在集成流程中定义 D ownership 与可信 base；独立检查 D1/D 后续分支改动范围，处理 D1 的 docs 路径例外；取回 9 个 DSoftBus source blobs 后逐项核验 SHA/blob/size。holdout、真实日志样本、产品可读性和 PoC 仍独立未完成，禁止 `confirmed`。
2. **A T1 样本包 owner**：将总体结论、adjacent JSON、README、technical report、Excel 和 remote-package canonical counts 统一为 `partial/unknown` / `candidate`，保留机制控制结果但删去未经产品验证的 arbitrary-file 确认表述；取得匹配 PoC image digest + 完整 argv 后才可重放。官方 fixed commit/build 不可由 adapter patch 替代。
3. **A T1 delivery author / 集成人**：把补充交付放入 A ownership 允许路径，提交 source/报告哈希和 scope 结果。
4. **T2 产品/平台 owner**：尚无交付，按 T2 验收定义实现并提交完整 10 仓库及故障模式证据。
5. **A path detector author**：同步报告测试计数与当前版本，处理未跟踪 exact Contacts fixture 后重跑 targeted/A suite、scope/diff 并推送。

在上述产品证据缺口关闭前，本审计不建议任何 D1/T1/A1 结果标为 `confirmed/reportable`。本审计没有更改 D1/T1/T2 的交付、没有修改 PR 状态，也没有修改原 A 脏树。
