# OpenHarmony A 线 30 份报告抽查与沙箱验证技术报告

- 报告日期：2026-10-18
- 抽样总体：`openharmony-full-scan-20261017` 中 378 份具备 `report.md`、`result.json`、`run_meta.json` 的有效报告
- 固定随机种子：`20261018`
- 样本：30 份，其中 20 份有候选、10 份零候选
- 扫描候选：345 条，其中风险验证高优先级 283 条、普通优先级 62 条
- 最终结论：**扫描候选 0 个 confirmed；相邻上下文审计确认 1 个漏洞；专用 PoC 1 个**

## 1. 执行结论

本轮从 378 份 A 线完成报告中进行确定性分层随机抽样。30 份样本覆盖 345 条扫描诊断，逐条完成源码绑定、入口/权限边界、可达性、触发条件、CIA 影响和沙箱方法复核。扫描器直接候选中没有一条同时满足 confirmed/reportable 完整证据门，因此扫描候选 confirmed 数保持 0。

对样本 2 `openharmony/distributeddatamgr_data_share` 的权限/模式候选进行上下文审计时，在相邻的 `openharmony/applications_standard_contacts_data` 实现中确认 1 个独立路径穿越漏洞：`ohscanner-contacts-path-traversal-001`。该发现不是扫描器直接命中，必须与 345 条扫描候选分开展示。拥有 `ohos.permission.WRITE_CONTACTS` 的调用者可以通过 `BatchInsert` 向 Contacts DataShare 提供包含 `../` 的 `PortraitFileName`，导致 Contacts 服务在保存头像失败后删除服务进程可访问的任意文件，形成完整性与可用性影响。

专用 PoC 使用真实源码片段和目标适配器，在固定 Docker 镜像中以无网络、只读根文件系统、`cap-drop ALL`、`no-new-privileges` 和资源限制运行。攻击、修复和安全对照均为 3/3 稳定；`fixed-safe` 为 3/3 稳定。ASan/UBSan 探针在进程退出阶段出现段错误，状态为 `asan_ubsan_probe_exit=139`，不将其描述为成功 sanitizer 验证。

## 2. 范围、假设和证据门

### 2.1 范围

- 扫描总体为 378 份有效报告，共 1,645 条诊断；100 份失败/无报告记录不进入抽样总体。
- 抽样使用固定种子 `20261018`，分别从 100 份有候选报告抽取 20 份、从 278 份零候选报告抽取 10 份。
- 本轮不修改扫描器公共 API、历史报告、历史候选 ID 或已有 Git 提交，不访问或攻击线上服务。
- 原扫描结果的 `severity` 全部为 `unassessed`。本文的“高危”是风险验证优先级，不是漏洞定级。

### 2.2 Confirmed 证据门

只有同时满足以下条件才升级为 `confirmed`：

1. 真实产品入口与调用者权限边界成立；
2. 可达具体敏感操作；
3. 攻击者可控且可重复的触发条件成立；
4. 具体机密性、完整性或可用性影响成立；
5. 仓库、commit、tree、blob、snapshot、源码哈希和构建/运行环境可审计绑定。

编译崩溃、sanitizer 输出、AST 命中或通用控制 harness 触发都不能单独证明漏洞。动态触发但缺少产品可达性时，不得称为已确认漏洞。

## 3. 确定性抽样与源码绑定

抽样算法按 `SHA-256(UTF-8(seed NUL repository NUL snapshot_sha256))` 生成稳定排序，并列项按 repository、snapshot_sha256 排序。重复执行的选择指纹为：

`16e7da3a1fe9fda80ae66dcda856b5e776b649c0d3ce9fd40de9240ddf56a979`

30/30 commit、30/30 Git tree、30/30 snapshot SHA-256 匹配；345/345 诊断的源码 SHA-256 与引用行匹配。扫描候选复核结果为 9 条 `not_reproduced`、336 条 `not_testable`；没有扫描候选被升级为 `confirmed`。

| 指标 | 数量 |
|---|---:|
| 有效总体报告 | 378 |
| 有候选总体报告 | 100 |
| 零候选总体报告 | 278 |
| 总体诊断 | 1,645 |
| 抽样报告 | 30 |
| 有候选样本 | 20 |
| 零候选样本 | 10 |
| 扫描候选 | 345 |
| 高优先级候选 | 283 |
| 普通优先级候选 | 62 |
| 扫描候选 confirmed | 0 |
| 相邻审计 confirmed | 1 |
| 专用 PoC | 1 |

## 4. 扫描候选沙箱复核

高优先级规则包括 `ohcpp-shared-ptr-race-candidate-001`、`ipc.parcel.copy-range`、`ipc.auth.*` 和 `ipc.capability.export`。`ipc.relay.descriptor-boundary` 等其余候选进入明细但保持普通优先级。

已有 `shared_ptr`、`lifetime`、`auth01` harness 仅作为方法和阳性/阴性控制参考，不冒充被抽样组件的逐条证明。通用 TSan 正/负控制各 3/3 稳定，只能说明验证方法可用，不能证明抽样组件存在数据竞争。345 条扫描候选没有获得完整真实入口、权限边界、目标构建和 CIA 影响证明，因此保持 `not_reproduced` 或 `not_testable`，不生成扫描候选 PoC。

## 5. 相邻上下文审计确认漏洞

### 5.1 身份与入口

- Finding ID：`ohscanner-contacts-path-traversal-001`
- 组件：`openharmony/applications_standard_contacts_data`
- 发现来源：样本 2 的 DataShare 权限/模式候选上下文审计
- 状态：`confirmed`
- 主 CWE：CWE-22 路径穿越
- 辅 CWE：CWE-73 外部控制的文件名或路径
- 入口：`ContactsDataAbility`
- URI：`datashare://com.ohos.contactsdataability`
- 权限边界：`ohos.permission.WRITE_CONTACTS`

Contacts 仓库固定到 commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`、tree `2054824c04bb403eeea128a9262edfb3001efa4f`。DataShare 仓库固定到 commit `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`、tree `f731230c116c94d7619f5514c828b33ffac69924`，snapshot SHA-256 为 `68007b3ab440834b9aaafbba4c3e35515c482e1786c88e3cbf8bda97183cb568`。逐文件 SHA-256 与 Git blob SHA-1 见 `evidence/provenance_adjacent.json` 和 PoC 的 `source_manifest.json`。

### 5.2 调用链

1. `DataShareStub::CmdBatchInsert` 反序列化 URI 和 `DataShareValuesBucket` 后调用 provider 的 `BatchInsert`。
2. `UnmarshalValuesBucketToBuffer` 接受字符串 key/value，不禁止路径分隔符或点段。
3. `ContactsDataShareStubImpl::BatchInsert` 将请求转交给 `ContactsDataAbility::BatchInsert`。
4. `ContactsDataAbility::BatchInsert` 检查 `WRITE_CONTACTS` 后进入 `batchInsertHandleOneByOne`。
5. `HandleContactPortrait` 将 `groupPath` 与 `PortraitFileName`、`contactId`、`rawContactId` 直接拼接；图片保存失败时执行 `DeleteFile(srcFilePath)`。
6. `FileUtils::DeleteFile` 直接调用 `unlink(filePath)`，没有 canonical path allowlist。

### 5.3 可控触发与影响

攻击输入：

```text
PortraitFileName = ../../../base/files/victim.txt
contactId = 1
rawContactId = 1
```

解析路径：

```text
/data/storage/el2/group/com.ohos.contactsdataability/photo/../../../base/files/victim.txt
```

规范化后落到：

```text
/data/storage/el2/base/files/victim.txt
```

由于目标不是合法图片，`SavePortraitFileAndBlob` 失败，但上层仍执行 `unlink(srcFilePath)`。拥有 `WRITE_CONTACTS` 的调用者因此可删除 Contacts 服务进程可访问的任意文件，影响完整性与可用性。该结论由固定源码调用链、真实权限入口、可控字段和隔离环境下的 3/3 攻击重放共同支持。

## 6. Docker 沙箱与 PoC

PoC 目录：

```text
poc/ohscanner-contacts-path-traversal/
```

容器使用固定镜像 ID：

```text
sha256:1f28ead56a68352c2bbbbd4fb45523a237f271dc3be827b073b9274986a2a829
```

Docker Engine 为 29.1.3。运行参数包括 `--network none`、`--read-only`、`--cap-drop ALL`、`--security-opt no-new-privileges`、`--cpus=1`、`--memory=512m`、`--memory-swap=512m`、`--pids-limit=64` 和 `--ulimit nofile=64:64`；`/tmp` 与 `/data` 使用 tmpfs。编译器为 Debian g++ 12.2.0。没有使用普通宿主进程回退。

| 用例 | 重复 | 预期 | 实际 | 结果 |
|---|---:|---|---|---|
| attack | 3/3 | 越界 victim 被删除 | victim 被删除 | 通过 |
| fixed | 3/3 | 越界路径被拒绝，victim 保留 | victim 保留 | 通过 |
| safe | 3/3 | photo 目录内合法文件正常处理 | 生成 `photo/1_1` | 通过 |
| fixed-safe | 3/3 | 补丁版本不破坏合法路径 | 生成 `photo/1_1` | 通过 |

每次运行的 argv、环境、退出码、源码/二进制哈希和原始日志保存在 `poc/ohscanner-contacts-path-traversal/results-ubsan/`。ASan/UBSan 二进制均编译成功，但运行探针退出码为 139；该限制单独记录，不计入稳定功能结果。

### 6.1 PoC 复现命令

在仓库根目录执行：

```text
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --cpus=1 --memory=512m --memory-swap=512m --pids-limit=64 --ulimit nofile=64:64 -v <poc>:/sandbox/work:ro -v <output>:/sandbox/out --tmpfs /tmp --tmpfs /data <fixed-image-id> /bin/sh /sandbox/work/run_ubsan.sh
```

实际运行脚本以 `run_ubsan.sh` 记录的固定参数为准；不要将该命令用于线上服务。

## 7. 修复建议

1. `PortraitFileName` 只接受 basename，拒绝 `/`、`\`、`.`、`..` 和空字节。
2. `contactId`、`rawContactId` 使用严格数字或格式白名单，禁止路径字符。
3. 构造路径后使用 `realpath`/canonical path，并确认结果仍位于预期 photo 目录内。
4. `DeleteFile` 前再次执行 canonical path allowlist 校验；文件 helper 使用显式 allowlist，避免直接 `unlink` 外部输入。
5. `BatchInsert` 增加 schema/字段白名单和类型校验，拒绝非预期字段组合。
6. 将 positive、fixed、safe、unrelated 四类控制纳入持续回归；补丁变体必须重跑 attack/fixed/safe/fixed-safe 并保留前后差异。
7. 产品集成验证应补齐完整 OpenHarmony 镜像、目标构建配置、SELinux 域策略和真实 IPC 客户端。

## 8. 扫描器改进建议

- 建模 IPC 入口、调用者 UID/权限和数据提供者可见性，避免只看局部 AST。
- 对权限检查增加 guard dominance 分析，区分检查存在与检查支配敏感操作。
- 对 shared_ptr/生命周期候选输出所有权转移、别名、析构时序和原子操作证明义务。
- 将目标构建配置、编译选项、线程模型和 sanitizer 结果绑定到候选 provenance。
- 对同文件、同字段和同 sink 的候选聚类，降低重复告警并突出边界违反。
- 根据入口、权限、sink 和触发条件自动生成目标适配 harness，明确区分方法控制与产品 PoC。
- 将风险验证优先级与漏洞定级分离，禁止 `unassessed` 直接显示为 confirmed severity。
- 为路径拼接类候选增加 basename、canonical path、allowlist 和删除/写入 sink 的专门规则。

## 9. 局限与剩余证明义务

- 没有完整 OpenHarmony 产品镜像，未在完整系统策略、构建和 SELinux 域策略下复测。
- PoC 是从真实源码提取的窄化目标适配器，不是整机产品镜像执行；它证明了源码路径、权限入口和触发条件，但仍需上游产品集成验证。
- ASan/UBSan 探针在退出阶段段错误；功能稳定性采用 UBSan 3/3 结果，不宣称 ASan 完整通过。
- Docker Hub 不可访问，验证镜像来自本地固定镜像；严格可重建发布仍应归档镜像和完整构建上下文。
- 上游补丁尚未审阅，`patched_target_adapter` 的 fixed/fixed-safe 重验只说明补丁变体有效，不等于上游补丁已验收。

## 10. 交付物

- `report/technical-report.md`：本报告。
- `report/technical-report.pdf`：正式评审版。
- `openharmony-a-line-sample30.xlsx`：总览、候选明细、样本与方法、PoC 索引四个页签。
- `evidence/`：样本、逐条候选判定、相邻发现、provenance、Docker 日志、环境指纹、哈希与对账。
- `poc/ohscanner-contacts-path-traversal/`：确认漏洞的源码绑定 manifest、harness、运行脚本、attack/fixed/safe/fixed-safe 原始输出。
