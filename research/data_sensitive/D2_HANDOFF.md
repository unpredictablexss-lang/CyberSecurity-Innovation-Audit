# D2 交付与停止条件核对

日期2026-10-17；原分支 feat/teammate-d-sensitive-exposure-20261017；原 Draft PR #17。
D1已发布提交f11d5fdf4ab01a345a1ffb702b18edb6b5109a38，不再误称未push。
主线/merge-base核对为e510c99c67f31ec6c73365f9ab749c79ca6ff0a1；开始时ahead1/behind0。
D2实现提交3b646c881716eb6b0c86195cdeeb1012ac9c921b，回归和固定范围实验在该HEAD实际执行。
之后证据/文档提交只补材料，冻结算法SHA见D2_FREEZE.json；最终PR head以GitHub回执为准。

## 本轮验收项

- [x] D2_BASELINE.md/json记录实时PR、HEAD、merge-base、初始干净状态和旧控制哈希。
- [x] 先用33个新控制暴露D1的12个失败子用例，再修复活跃后继合并/退出/词法作用域。
- [x] D2共39个控制，旧32控制及预期哈希完全不变；D专项16个方法通过。
- [x] &&/?:、顺序覆盖、单语句else、格式槽位、状态/长度和同名调用有明确正负/未知回归。
- [x] 全量528项：517通过、11跳过、0失败/错误；compileall通过；diff检查通过。
- [x] 固定9文件同commit、scope、Source/Sink语义0.1.0，分别运行D1算法0.1和D2算法0.2。
- [x] 正式覆盖仍0complete/3partial/6not_analyzed/0failed、候选0→0；D2双跑相同观察与覆盖。
- [x] 逐文件错误与函数/模型审计已记录，私有探针结果明确不是正式准入或生产扫描。
- [x] 真实历史检索有查询/排除记录及两组可核实日志删除硬化对；未伪造成当前支持的真实漏洞。
- [x] 规则已冻结，独立holdout与可选Docker-only PoC计划已交付；未伪造执行结果或准确率。
- [x] 最小函数局部事实/错误区域与日志operand RFC已更新，未修改公共内核。
- [x] 已完成更新原Draft #17的本地发布准备；推送成功和Draft状态以本轮GitHub回执核对，不把本地文档当作远端凭据。

## 关键代码与边界

只在D模块引入LocalState/ExitState/BlockResult。合并只用非None的后继状态，return退出、
else_clause、嵌套块和遮蔽恢复有回归；不能据此宣称完整CFG/可达性/并发/跨函数证明。
循环/复杂副作用、PRI/动态格式、类型身份/初始化及产品日志可读性仍partial/unknown。
默认模型保持一个已研究精确commit，不关键词扫全库，也不为历史样本临时篡改模型。

D2增量以f11d5fd为边界：只改src/ohscanner/detectors/data、D专属测试/fixture和
research/data_sensitive。PR聚合差异中的docs/项目现状与下一步.md是已发布D1遗留；D2未再次修改。
按任务书更严格的D-only范围，当前D2状态记录在本文件，不修改公共文档/Runner/Catalog/协议/UI。

## 复现（Ubuntu）

```bash
cd /home/lzc/projects/OHScanner-teammate-D
PY=/home/lzc/projects/CyberSecurity-Innovation-Audit/.venv-web/bin/python
$PY -m unittest tests.detectors.data.test_sensitive_exposure tests.detectors.data.test_d2_semantics -v
TMPDIR="$PWD/.tmp" $PY -m unittest discover -s tests -v
$PY -m compileall -q src/ohscanner/detectors/data tests/detectors/data research/data_sensitive
$PY -m research.data_sensitive.d2_coverage --repo-dir /mnt/c/Users/86150/Documents/Codex/2026-10-08/w/outputs/dsoftbus-replay.git --output-dir outputs/reports/d-sensitive/d2
git diff --check
```

来源commit/blob/SHA及双跑报告SHA见D2_COVERAGE.json；实际回归命令/计数/日志SHA与skip理由
见D2_VALIDATION.json；历史父子/tree/blob/sourceSHA见D2_HISTORY_MANIFEST.json。
本地命令路径不是其它机器的固定路径；第三方原文件、Git对象、虚拟环境和大日志不上传。

## 负责人待定与剩余未知

1. 局部错误隔离、声明/日志宏事实与partial资格策略，尤其auth_session_key.c。
2. 历史两组线索的材料敏感性、旧Sink语义和非授权日志读取条件。GitCode具体请求404，
   只确认GitHub镜像/API身份与源码hash，不声称双源一致，也不自动换HEAD。
3. 独立标注人员/数据及隔离镜像/Harness审批。暂不执行holdout/PoC，不报告真实Precision/Recall。
4. 拟议ID仍是研究用途，未注册Catalog/面板，无confirmed/CVE/产品受影响版本结论。

目标停止条件：D2-0至D2-4材料与P0代码/回归/覆盖解释完成，按授权更新原Draft #17并核对远端
提交及Draft状态后停止。不继续扩规则、不自动Ready/Merge，不越过公共接口审批。
