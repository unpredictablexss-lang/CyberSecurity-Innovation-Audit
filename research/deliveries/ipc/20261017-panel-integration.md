# B/IPC 接入面板主线：本地验收记录（2026-10-17）

## 范围与来源

- B 源分支：`work/ipc-20261017`，远端/本地一致 HEAD `04201e708538706a8bfb633ff5e22c50d643fb6a`。旧 B 路径仍有 dirty `PROGRAM_STATUS.md`，未触碰。
- 面板集成基线：`integration/parallel-baseline-20261017@149baf74f0094ef82e2a0e715c09b9956df2b33e`。
- 工作分支：`integration/ipc-panel-20261017`，本地合并 B 代码并 cherry-pick review fix `50f101050a67096a61e8321299cb8586153c24fb`，随后完成以下集成修改。负责人主工作区 dirty 内容未覆盖。

## 改动与面板行为

1. Catalog 注册 `ohscanner.oh.arkts_js`，JS/TS/ETS 通过统一 frontend parse status 路径；固定 Tree-sitter JS/TS grammar 依赖并计入环境指纹。Workbench API/Worker 测试用动态 JS 合成样例验证 candidate 进入扫描结果。此为自动化 API/Worker 验收，不是浏览器视觉验收，也不提供 ETS 类型或安全语义证明。
2. IPC 增加窄规则 `ipc.parcel.fd-backing-size`。仅在 caller 至唯一 implementation 的跳转、同一 FD 和长度流向 mmap 可追踪时输出候选；拒绝不唯一方法、不同 FD、延迟检查和仅日志检查。无法解出的控制流/别名保留 unknown/partial 义务。规则为 CWE-20/CWE-125 候选提示，非已确认漏洞。
3. 固定真实 Pasteboard vulnerable/fixed 版本对，静态规则在 vulnerable revision 产生 caller candidate，在 fixed revision 不产生；固定 c_utils 输入由 Git objects 归档构建，输入哈希进入新 Harness 结果 schema。既有历史 `result.json` 未覆盖。
4. 公共 IPC Detector 版本更新为 0.9.2、模型版本 v11；新增回归 fixtures/controls。Web 源代码没有改变，浏览器静态构建产物与已验证相同 Web 源的集成基线一致；本轮未运行 Node 构建或浏览器专项验收。

## 固定源码对与动态组件证据

证据细节、精确源文件与哈希、限制见 [fd backing fix pair](../../evidence/interface/ipc/fd_backing_fix_pair_20261017/README.md)。组件 Harness A/B/C/D 场景符合 vulnerable/fixed 预期，且构建使用 c_utils 固定 Git commit。它证明固定组件和 Harness 输入的行为差异；没有证明真实系统 IPC 请求可达、攻击者权限边界、产品部署配置或 CIA 影响。漏洞等级维持 candidate/unknown，`validated_vulnerability=0`。

## 验证

- 定向 Workbench、Catalog、API/Worker/CLI 及 ArkTS 回归：48 tests passed。
- IPC detector 与 workbench 扩展定向回归：113 tests passed；partial parser 调整后 IPC 定向测试另 34 tests passed。
- 最终代码全量回归：`.venv-web/bin/python -m unittest discover -s tests -q`，668 tests run，664 passed、4 skipped、0 failed。
- `sh -n` 检查 Harness build script；`py_compile` 检查 build/assemble；固定 c_utils 输入重建并运行两端 Harness，A/B/C/D 行为符合预期。
- 固定源版本 API/CLI 扫描：vulnerable 一条 caller candidate，fixed 零条；两个源单元有 complete/partial 混合解析，限制仍附在结果上。

## 交付边界

此成果是隔离 worktree 上的本地集成分支。未 push、未合并远端 main、未把 PR/Draft 标 Ready。尚需真实浏览器 UI 专项验收、完整语料性能/精确率召回率评价、产品调用入口与权限证明、独立产品 PoC 和修复复验。
