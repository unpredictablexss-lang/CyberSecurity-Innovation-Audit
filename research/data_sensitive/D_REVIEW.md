# D 首轮审查与交付说明

日期：2026-10-17。独立工作区 `/home/lzc/projects/OHScanner-teammate-D`，分支
`feat/teammate-d-sensitive-exposure-20261017`，基线 `e510c99c67f31ec6c73365f9ab749c79ca6ff0a1`。
原工作区 main 的未提交面板修复原样保留；没有重启面板、没有修改旧 B 分支。

## D1 只读审查结论

已实际查询最新 main、所有远端分支和开放 PR。开放 PR #8/#9/#10/#11/#12/#16；
#16 是 C TypedArray 类型来源研究，#11 是 B 同文件委托守卫，A 为生命周期/并发。
当前 main Catalog 注册三个研究检测器和一个示例，不含 D 敏感值日志数据流规则。
已读 AGENTS、docs/README、当前状态、架构与协议、协作指南、contracts、catalog、runner、
execution、indexing、frontend、facts 与 src/parser/ast 的实际实现。

可复用：SourceUnit/ScanRequest/ScanContext、required_facts=ast、DetectorFinding、
EvidenceObligation、source_sha256、file_outcomes、DetectorRegistry、run_all_with_coverage、
run_reviewed_detectors 和固定 Git 对象 prepare_git_context。
共享 outlines 只有函数/调用/变量摘要，无完整表达式、赋值边、绑定、CFG 或宏实例。
本线私有详细语句遍历使用已安装 Tree-sitter 基础设施，不创建另一套平台/全局 IR。

不修改 contracts/runner/catalog/indexing/execution、数据库、Web UI 或 A/B/C 模块。
拟议 ID 尚未由负责人确认，未注册，现有面板不能选 D。这是独立送审模块，不是主线功能。

## 固定目标与来源

官方组织 GitHub 镜像：openharmony/communication_dsoftbus，commit
`0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132`，tree
`bd915661eedd139df17f249191e2a691e76f7565`。
实际取得浅 Git 对象，Windows 本地只读对象路径为
`C:/Users/86150/Documents/Codex/2026-10-08/w/outputs/dsoftbus-replay.git`。
Linux 可读路径 `/mnt/c/Users/86150/Documents/Codex/2026-10-08/w/outputs/dsoftbus-replay.git`。
不是完整 OpenHarmony 发布 manifest，也没有证明某产品固件启用此配置。
日志文档/接口参考：openharmony/hiviewdfx_hilog @
`393d7e9a690edb76ed27e710b472623daf650dc8`。
14 个参考文件含 LICENSE 的 commit/blob/SHA256 清单见 source_manifest.json；
精确行号见 source_locations.json。第三方原文件仅在忽略缓存/外部 Git 对象，不随提交分发。

## 来源模型：6 类，不按变量名猜

| 来源 | 语义/固定证据 | 本轮处理 |
|---|---|---|
| SessionKey.value | auth_session_key_struct.h，实际会话密钥字节 | 只标 value，不标 len |
| AesGcmCipherKey.key | softbus_adapter_crypto.h 的 AES-GCM 密钥字段 | 不把 IV/keyLen 当密钥 |
| AesGcm128CipherKey.key | 同头文件 GCM128 密钥字段 | 类型/初始化待编译器绑定 |
| AesCtrCipherKey.key | 同头文件 CTR 密钥字段 | 同上 |
| SoftBusGenerateSessionKey 第0输出参数 | 声明与 openssl 实现：调用随机生成，返回码与输出分离 | 输出缓冲区污染，状态返回值不污染 |
| OnSessionKeyReturned 第1形参 | auth_hichain.c 固定回调，将收到的值传入 AuthSessionSaveSessionKey | 精确文件/函数/参数定位 |

这里字段类型名字属于受限模型，不是编译器级 typedef/别名解析。局部冒名类型、
同名函数定义和同名函数指针参数被抑制并标未知；跨文件身份仍需审查。

## 8 个 Sink 模型及格式语义

AUTH_LOGF/E/W/I/D 共5个，format参数索引1；HiLogPrint、OH_LOG_Print、HILOG_IMPL
共3个，format参数索引4。AUTH_LOG 的定义及转发位于固定 auth_log.h/softbus_log.h；
HiLog API 定义与默认 private 语义来自固定 hilog/log.h。
只对显式 public 的敏感实参产生本规则候选，逐占位符对应参数，不把一个 public
误应用到所有参数。private/default-private 的潜在敏感值不报本规则，但标注运行时
隐私配置需复核，不能因此认定全环境安全。DEBUG/FATAL 等等级是观察条件，不假定
量产默认可见；LiteOS/工程构建与隐私开关仍是明确的证据缺口。

## 人工对照与研究风险

真实生产源码中的4个低风险/非目标对照：OnSessionKeyReturned 的 authSeq/len 日志、
invalid sessionKey 常量日志、GetLatestSessionKey 的 index/type/time 日志、EncryptData 的
sessionKey.len 日志。均不能因包含 key/token 字样就判为密钥泄露。
真实高风险日志候选尚未建立，不能伪造4个真实危险样例；direct/alias/copy/format
四类危险对照为明确标注的合成 fixture。Anonymize/哈希/截断不是无条件安全，未知
包装保留可能依赖和 partial。没有官方漏洞修复对/CVE，也没有利用真实系统日志。

首轮3个主要风险：宏/格式串错位导致误报或漏报；同名类型/函数与指针别名不可靠；
日志运行配置和非授权可读性未知。测试专门覆盖这些风险，无法证明的保留 unknown。

## D2 交付内容

独立 models.py、sensitive_exposure.py、README；单规则 data.log.sensitive-value。
支持直线赋值/覆盖、有限局部别名、memcpy_s/strcpy_s、snprintf/snprintf_s 格式化、
局部块作用域、分支 may-join；循环、复杂指针、宏和跨函数不足明确标注。
输出 source -> assign/copy/format -> public sink 的位置链，证据标 syntax；
不把这种局部依赖说成 CFG 可达性或已确认泄露。32个合成设计控制，10个 unittest
方法还覆盖真实 Runner v2、源码哈希、义务、快照漂移、解析失败/partial与确定性。

## D3 真实范围复测

9个固定文件，两次同scope/commit/model运行，来源逐文件核对 blob/SHA256。
结果0候选；coverage complete=0、partial=3、not_analyzed=6、failed=0。
3个 partial 为 auth_hichain.c、auth_hichain_adapter.c、auth_log.c；6个因公共 Runner
对 partial AST 文件跳过而未进入本检测器。零命中有明显覆盖前提，不代表组件安全。
同范围两次候选身份和覆盖相同，新增/移除各0。这是同版本复跑一致性，不是相对
旧算法的效果提升；本仓库此前没有 D baseline，不能编造算法 before/after。
精简真实结果与报告哈希见 fixed_scope_summary.json，大报告/原始日志留本机 outputs。
首轮实测约3.8秒/两次，实际新运行耗时与峰值RSS以summary为准，不是产品性能承诺。

## 复现命令

```bash
cd /home/lzc/projects/OHScanner-teammate-D
PY=/home/lzc/projects/CyberSecurity-Innovation-Audit/.venv-web/bin/python
$PY -m unittest tests.detectors.data.test_sensitive_exposure -v
$PY -m research.data_sensitive.replay --repo-dir /mnt/c/Users/86150/Documents/Codex/2026-10-08/w/outputs/dsoftbus-replay.git --output-dir outputs/reports/d-sensitive
TMPDIR="$PWD/.tmp" $PY -m unittest discover -s tests -v
$PY -m compileall -q src/ohscanner/detectors/data tests/detectors/data research/data_sensitive/replay.py
git diff --check
```

全量实际结果在validation.json更新；不得把旧512/4引用为本轮实测。
独立holdout尚未实施，参见holdout_plan.md。不计算Precision/Recall。
负责人仍需确认ID、语义模型和详细语句事实接口；注册和选择性合入归负责人。
