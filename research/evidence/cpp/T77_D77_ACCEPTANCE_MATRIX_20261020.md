# T77 D77 独立验收矩阵与结果

## 冻结输入

- D77 commit `a99334031575a184840fff9ed9a486237543fd64`，父提交 `88b357fa0f7d4906e3baff9392c6b27126c88d40`。
- 作者 worktree：`D:/openHarmonyScanner/worktrees/d76-samgr-profile-policy-20261020/worktrees/d77-pasteboard-adversarial-20261020`，HEAD 与冻结提交一致，工作树干净。
- D77 报告、JSON、脚本路径记录在 [T77 独立报告](T77_D77_ACCEPTANCE_20261020.md) 和机器结果 [JSON](T77_D77_ACCEPTANCE_20261020.json)。

## 检查结果

| ID | 检查项 | 结果 | 证据概要 |
|---|---|---|---|
| T77-01 | 冻结身份 | PASS | commit/parent 精确匹配；作者 worktree clean。 |
| T77-02 | 源码 pin/tree/blob/SHA-256 | PASS | 独立 D52/SAMgr bare clone 重算 tree；12 个 D52 文件与 2 个 SAMgr 文件身份匹配；D76 init/AccessToken tree 也匹配。 |
| T77-03 | 行引用与语义 | PASS | 独立读 GET_PASTE_DATA、stub、core 路径；D52 候选行 41 是方法开头，不是 guard。 |
| T77-04 | 正反控制 | PASS（source-only） | route 是正控制；descriptor mismatch、invalid user、no clip 只证明传输/身份/数据边界，不冒充权限控制。 |
| T77-05 | JSON 重复键/严格解析 | PASS | 用拒绝重复键的 object-pairs hook 解析；重放 JSON 与冻结 JSON 结构完全一致。 |
| T77-06 | 独立复现 | PASS | 独立克隆上运行 replay，退出码 0，D52/SAMgr tree 匹配，完整输出等于冻结 JSON。 |
| T77-07 | 结论边界 | PASS（有限制） | `SUPPORT_PENGLAI_MODE` 加编译宏及 `isPengLai_` 运行态门控属 SA 获取/加载；不证明 D52 产品配置，也不代表 Pasteboard 每次 Binder 调用都重新授权。 |
| T77-08 | 变更范围与 diff hygiene | PASS | 验收只新增 T77 报告、矩阵和 JSON；`git diff --check` 通过。复现临时 clone/JSON 不纳入提交。 |

## 结论

`ACCEPTED_WITH_LIMITATIONS`。差异列表为空，无需 D77 修正。产品版本、安装映射、构建旗标、运行态策略和服务方法授权仍未知；D52 保持 narrow source-only 候选。
