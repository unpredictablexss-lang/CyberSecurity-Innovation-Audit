# 队友 D：D2 阶段验收文档

日期：2026-10-17。本文依据本轮保存的测试、覆盖与发布回执整理；编写本文未重新运行扫描。

## 1. 本轮验收结论

D2 的局部传播修复、回归测试、固定源码覆盖解释和历史线索调查已完成，已更新原草稿 PR，等待队长审核。当前成果属于敏感信息进入日志的静态检测器原型，尚不能认定已完成真实产品漏洞验证。

| 项目 | 本轮结果 |
| --- | --- |
| 研究检测器 ID | `ohscanner.data.sensitive_exposure`，尚未注册到 Catalog / 面板 |
| 当前规则 | `data.log.sensitive-value`；CWE-532 为暂定分类 |
| 检测器版本 / Source、Sink 语义模型 | 0.2.0 / 0.1.0 |
| 原有控制样例 | 32 个，文件与预期保持不变 |
| D2 新控制样例 | 39 个；合计 71 个设计与回归控制，均非独立留出集 |
| D 专项测试 | 16 个 unittest 测试方法通过，方法内部包含矩阵与子用例 |
| 全量测试 | 528 项：517 通过、11 跳过、0 失败或错误 |
| 其他检查 | compileall、git diff --check 通过 |
| 真实已确认漏洞 / 动态 PoC | 0 / 未执行 |

## 2. 检测了什么

原型追踪已建模的敏感材料，观察它经过局部赋值、复制或格式化后，是否进入明确公开的日志参数。例如：敏感缓冲区先复制给另一变量，再以公开格式输出。它区分材料本身与长度、状态码等字段，不依赖变量名含 password、token 就报漏洞。

模型绑定指定仓库和提交。当前主要研究对象为 `openharmony/communication_dsoftbus`，固定提交：

```text
0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132
```

输出是需要人工复核的语法级候选与限制信息，不是完整控制流、跨函数或产品攻击可达性证明。报告不输出真实秘密值。

## 3. 修复的问题及方法

| 原问题 | 示例含义 | D2 处理 |
| --- | --- | --- |
| 退出分支继续污染后继状态 | 某分支赋敏感值后已经 return，后面的日志却被当成继承该值 | 合并时只使用仍能继续执行的分支状态，单独记录退出 |
| else 与嵌套块处理不完整 | 真正执行的 else 路径可能漏掉，嵌套退出可能未生效 | 补充 else_clause、单语句分支、嵌套退出处理 |
| 局部同名变量影响外层 | 内层声明与外层变量同名，被当作同一个变量 | 保存词法作用域及遮蔽信息，离开块时恢复外层绑定 |
| 执行顺序混淆 | 日志之后才发生的赋值，被错误用来解释之前日志 | 按语句顺序处理副作用和值传播 |
| 参数与格式槽位混淆 | 把复制函数返回状态、长度或私有槽位当公开秘密 | 校验已支持调用的参数位置，改进公开/私有格式与宽度精度对齐 |

修复前先加入 33 个新控制，在 D1 实现上暴露 12 个失败子用例；修复并增加防御性控制后，D2 共 39 个新控制通过。旧 32 个控制及预期未修改，避免通过改答案掩盖退化。

短路表达式、条件表达式、复杂循环、动态格式、PRI 宏及未知调用仍存在保守处理或 partial / unknown；此次修复不代表这些语义已全部解决。

## 4. 真实源码覆盖验收

使用同一固定提交、同一 9 文件范围及同一 0.1.0 语义模型比较 D1、D2：

| 指标 | D1 | D2 |
| --- | --- | --- |
| complete | 0 | 0 |
| partial | 3 | 3 |
| not_analyzed | 6 | 6 |
| failed | 0 | 0 |
| 候选 | 0 | 0 |

D2 重复运行得到相同观察和覆盖；报告含耗时，因此不声称报告字节或哈希完全相同。候选为零只能说明此范围没有产生符合模型的候选，不能说明源码安全。

三个 partial 文件为 `auth_hichain.c`、`auth_hichain_adapter.c`、`auth_log.c`。其余文件受到宏、条件编译、头文件结构或解析错误影响。私有研究探针在 `auth_session_key.c` 观察到 30 个函数，其中 15 个未直接与解析错误重叠，但公共 Runner 仍将该文件列为 not_analyzed；这 15 个函数不能直接算成正式扫描完成。

## 5. 历史调查验收

已核验两组父子提交中的日志删除硬化线索：

| 文件 | 旧提交 → 日志删除提交 |
| --- | --- |
| `core/discovery/coap/nstackx_coap/src/disc_nstackx_adapter.c` | `05ca843ed7f6968686a47283916b7553f12932ed` → `273637945ecb7b53d5d9af3bfd4e48a40bb88252` |
| `core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_message.c` | `d33177135ec6c6aaf4a4c42de1f6878652b330e3` → `63efce3ff7f2708527eb29216decaf5fe2dc33d0` |

已记录查询范围、父子关系、文件哈希和排除理由。尚未证明材料确为秘密、非授权用户能读取日志，也未将旧日志 API 纳入当前默认模型，因此不能称为检测器已检出的真实漏洞或已修复真值。GitCode 的具体 API 请求返回 404，后续使用 OpenHarmony 官方组织的 GitHub 镜像；未完成跨镜像身份核验。

## 6. 提交与开发纪律

- 分支：`feat/teammate-d-sensitive-exposure-20261017`。
- 实现提交：`3b646c881716eb6b0c86195cdeeb1012ac9c921b`。
- 本轮发布 HEAD：`0867eac5ddaab3d32fe8cb6d32a0549a2857ec20`。
- [草稿 PR #17](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/pull/17) 保持 Draft，未合并。
- 保存的[CI 回执](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/actions/runs/39031256720)显示 Python 测试及 Workbench TypeScript / 生产构建成功。

D2 增量只涉及 D 检测模块、专属测试/样例及 `research/data_sensitive`。未修改公共 Runner、协议、Catalog、UI 或其他队友检测器。PR 聚合差异中的公共状态文档属于 D1 遗留，D2 未再次修改。

11 个跳过来自环境或既有依赖：性能语料缺失 1 项、仅限 Docker 的测试 2 项、固定源码 Store 不可用 6 项、历史源码材料不可用 2 项；不能把跳过计为通过，也不是 11 个 D 新测试跳过。

## 7. Ubuntu 复现入口

当前开发目录：`/home/lzc/projects/OHScanner-teammate-D`。以下路径针对本机，其他机器需准备相应环境和源码对象。

```bash
cd /home/lzc/projects/OHScanner-teammate-D
PY=/home/lzc/projects/CyberSecurity-Innovation-Audit/.venv-web/bin/python
$PY -m unittest tests.detectors.data.test_sensitive_exposure tests.detectors.data.test_d2_semantics -v
TMPDIR="$PWD/.tmp" $PY -m unittest discover -s tests -v
$PY -m compileall -q src/ohscanner/detectors/data tests/detectors/data research/data_sensitive
$PY -m research.data_sensitive.d2_coverage --repo-dir /mnt/c/Users/86150/Documents/Codex/2026-10-08/w/outputs/dsoftbus-replay.git --output-dir outputs/reports/d-sensitive/d2
git diff --check
```

队长可重点核对：旧控制哈希不变；退出路径与活跃 else 的正负例；正式覆盖总数为 9；候选与确认漏洞分开；未知语义保留限制；PR 保持草稿。

## 8. 证据位置与待验收边界

仓库 `research/data_sensitive/` 中：`D2_VALIDATION.json` 保存测试记录；`D2_COVERAGE.json` 保存逐文件覆盖、函数与错误区域；`D2_HISTORY_MANIFEST.json` 保存历史源码身份；`D2_FREEZE.json` 保存冻结记录。

本机发布回执：`C:\Users\86150\Documents\Codex\2026-10-08\w\outputs\队友D_D2发布核验.json`。

后续仍需队长决定局部事实准入接口、独立评估数据及隔离验证条件。本阶段未执行独立留出集、动态 PoC，也未取得产品受影响版本、真实准确率或 CVE 结论。
