# PoC 索引

本轮扫描候选 confirmed 数为 0；样本上下文审计另行确认 1 个漏洞，因此总 confirmed vulnerabilities 为 1，专用 PoC 为 1。

- `ohscanner-contacts-path-traversal-001`：CWE-22/CWE-73，拥有 `WRITE_CONTACTS` 的调用者可触发 Contacts 头像路径穿越并删除任意可访问文件。
- PoC：`ohscanner-contacts-path-traversal/`，包含真实源码提取 manifest、目标适配器、补丁变体、Docker 运行脚本和 `results-ubsan/` 原始日志。
- 稳定性：attack 3/3、fixed 3/3、safe 3/3、fixed-safe 3/3。
- ASan/UBSan 探针退出码 139，作为限制保留；不将其写成 sanitizer 成功。

其他 `shared_ptr`、`lifetime`、`auth01` 控制仅为方法验证，不是本轮确认漏洞的 PoC。
