# 队友 B：IPC 接口安全本地研究包

开发目录 D:\ICP；主线基线 main dcd9629f50a34545d75abc92c0a16c79723197db。
本包为独立本地研究，未接入主线、未 push、未执行漏洞触发。

## 当前交付
- 保留用户已有 attack_surface_inventory.md；修订依据见 mmi_entry_verification.md，原文中运行证据没有提供，不能作为本次已核验实验。
- 12 份文件（11 个源码文件及 LICENSE）的 Git blob SHA-1 / SHA-256 / 字节数清单，以及离线核验器；真实源码只在忽略目录 local_sources，不进交付包。
- permission_prototype.py：在自建显式图上验证按调用者/权限/资源绑定的授权状态和缺失义务，真实输入默认 blocked。
- 7 个 design/regression synthetic fixtures；不是已公开漏洞集或独立 holdout。
- 33 项本地测试，包括拒绝分支继续执行、错误身份/权限/资源、绕过分支、身份变化、预算、错误路径、哈希篡改。

## 运行
在 PowerShell 中：
```powershell
cd D:\ICP
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m research.experiments.interface.replay_fixtures
.\.venv\Scripts\python.exe -m research.experiments.interface.verify_sources
```
Ubuntu/WSL 中：
```bash
cd /mnt/d/ICP
python3 -m venv .venv-linux
.venv-linux/bin/python -m unittest discover -s tests -v
.venv-linux/bin/python -m research.experiments.interface.replay_fixtures
```
原型和测试仅用标准库，无需安装外部扫描器。本次实际使用 Windows Python 3.10.11；未验证 WSL 运行，不混用 Windows .venv 与 Linux 环境。长期 Linux 开发可迁移代码到 Linux 文件系统。

## 边界
private research_schema=interface-graph-fixture-v0 仅为测试数据协议，不是 Detector v1 或新的全局 Finding。
不得把人工图视为从源码提取的 CFG。synthetic control_flow 只描述模拟图事实，不是目标设备路径证明。
不得把 no_uncovered_sink_in_fixture 写成 safe，或把 candidate 写成权限绕过。
源码提取、条件可满足性、类型、宏、跨函数/跨语言映射尚未实现。INPUT_MONITORING 与 socket 建连权限要求尚需区分。
负责人需实现并冻结 Detector v1；后续经批准桥接到现有 ToolRunResult，不改公共 schema/CLI/provider。

## 文件组织
使用 src/ohscanner/detectors/interface 和 tests/detectors/interface；原来的 detertors/deterctors 空目录保留。
第三方源码保持原始许可证头；manifest 记录精确来源。自身原型为独立实现，不复制扫描工具实现。
仅交付本地文件包与报告给负责人，远端提交和合并由负责人决定。


## 第二轮：C++源码输入

详见docs/reviews/interface_attack_surface/cpp_source_handoff.md。新增受限AST分析，可读取源码并输出语法候选和未知项；与前述人工图原型分开。
安装：`python -m pip install -r requirements.txt`；回归：`python -m unittest discover -s tests -v`；复放：`python -m research.experiments.interface.replay_cpp_sources`。
第二轮依赖tree-sitter 0.25.2和tree-sitter-cpp 0.23.4；60项测试通过。真实MMI三个函数目前unknown；不证明漏洞。前文标准库/33项描述属于第一轮图算法。


## 第三轮：自动入口与源码权限索引

最新说明见docs/reviews/interface_attack_surface/third_round_handoff.md。自动识别map/switch IPC分发，有限跨文件追踪和宏处理。固定MMI实跑33入口/23条源码约束（3条monitor）；92项测试通过。正式安全政策、宏完整效果和复杂调用覆盖仍需独立证据。
复放：`python -m research.experiments.interface.replay_ipc_inventory`。
