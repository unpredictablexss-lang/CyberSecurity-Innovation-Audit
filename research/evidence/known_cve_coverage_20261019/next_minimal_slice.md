# 下一最小切片

1. 为 17 个公开 CVE 各补一份固定上游 vulnerable/fixed blob 对；目前 CVE-2026-67216 只有 vulnerable 与 local safe，没有 pinned upstream fixed blob。
2. 为缺少独立 unrelated 源码形状的 CVE 补不依赖“错误路径”的语义负例，避免把 source-path gate 当成 unrelated 证明。
3. 对 CVE-2026-58313 建立公告根因/修复提交到精确源码 hunk 的映射，再决定是否需要最小语义规则调整。
4. 对 CVE-2026-33636 确认 Flutter/libpng 产品 pin 与补丁覆盖；对 CVE-2026-92392/9079 固定实际 curl 版本与修复提交。
5. 在独立、盲标注且适合的 holdout 上再评价 precision/recall；当前公开 CVE 只做回归与已知危险形状保真。
