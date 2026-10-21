# OpenHarmony A 线 30 份报告抽查与沙箱验证

本目录是 A 线 30 份报告抽查、候选复核、相邻上下文审计和 Docker 沙箱验证的远端交付。

## 结论

- 固定种子 `20261018` 抽取 30 份报告：20 份有候选、10 份零候选。
- 345 条扫描候选全部复核：高优先级 283 条、普通优先级 62 条。
- 扫描候选 confirmed 为 0；相邻上下文审计确认 1 个漏洞；专用 PoC 为 1。
- 确认漏洞 `ohscanner-contacts-path-traversal-001`：CWE-22/CWE-73，`WRITE_CONTACTS` 调用者可删除 Contacts 服务可访问的任意文件。
- “高危候选”仅表示验证优先级，不表示扫描器已经确认高危漏洞。

## 文件

- `report/technical-report.md`：完整技术报告。
- `report/technical-report.pdf`：正式评审版 PDF。
- `openharmony-a-line-sample30.xlsx`：四页签低认知负担 Excel。
- `evidence/`：抽样、溯源、逐条判定、相邻发现、Docker 日志、环境、对账和哈希。
- `poc/ohscanner-contacts-path-traversal/`：确认漏洞的源码绑定、harness、运行命令、攻击/固定/安全对照和原始输出。
- `poc/index.json`：PoC 索引。

## 验证边界

PoC 在固定 Docker 镜像中运行，使用无网络、只读根文件系统、`cap-drop ALL`、`no-new-privileges` 和资源限制；没有宿主进程回退。attack/fixed/safe/fixed-safe 各 3/3 稳定。ASan/UBSan 探针退出码 139，完整产品镜像、目标构建和 SELinux 域策略仍待上游集成验证。
