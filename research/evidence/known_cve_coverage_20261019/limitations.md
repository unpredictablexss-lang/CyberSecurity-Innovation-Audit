# 残余限制

1. 本线只迁移 source-identity 测试修复，不修改 `known_cves.py`、fixture、Ark 源码/测试、contracts、Runner 或 Catalog。
2. 测试读取固定 `db77164fdc2af0da02e4d3efc056d84694fd68e8` 的 Git blob 字节，并保留上游期望 Git blob SHA-1；worktree SHA-256 和 normalized-LF SHA-256 只作观测，不能冒充 blob identity。
3. 17 个公开 CVE 是已披露回归集，不是独立盲标注 holdout，不能计算或宣称 Precision/Recall、零 FP/FN。
4. 所有危险形状命中仍为 `candidate/unassessed`；命中不证明 ownership、调用可达、攻击者控制、并发竞争或 CIA 影响。
5. fixed/safe/unrelated 的 0 findings 只证明局部控制行为，不是组件或产品安全结论。
6. CVE-2026-92392 对审查到的 curl 8.8.0 为 `not-affected`；其他构建仍需精确版本绑定。CVE-2026-9079 保持 unknown/疑似 fixed。
7. `compileall` 首两次受 Windows Unicode/长路径限制失败，证据已保留；成功运行通过临时 `W:` 映射指向本证据目录内的 `pycache`，运行后立即解除映射。
8. `git diff --check` 的 stderr 只包含既有 Ark `receiver_guard.py` LF→CRLF 提示；本线没有触碰该文件。
9. 产品构建、入口/权限边界、攻击者控制、触发条件、CIA 影响、动态 PoC 和修复重验仍未闭合。
