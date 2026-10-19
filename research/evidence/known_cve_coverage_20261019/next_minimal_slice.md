# 下一最小切片

1. 将 source-identity 测试修复与 `known_cves.py` 0.16.0 回归证据迁移到集成分支时，继续保持 pinned Git blob 读取，不启用 CRLF worktree hash 替代。
2. 为 CVE-2026-67216 等缺口补 pinned upstream vulnerable/fixed blob 对，并为缺少独立 unrelated 形状的 CVE 增加语义负例。
3. 建立 CVE-2026-58313 公告根因/修复提交到精确源码 hunk 的映射；确认 CVE-2026-33636 的 Flutter/libpng pin。
4. 固定 CVE-2026-92392/9079 实际构建版本与修复提交，冲突或缺失继续保持 unknown。
5. 独立盲 holdout 和产品入口/权限/触发/CIA/PoC/修复重验闭合前，不发布 Precision/Recall 或 confirmed/reportable。
