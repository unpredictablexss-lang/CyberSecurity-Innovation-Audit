# Scripts

辅助脚本目录，例如：数据集准备、Benchmark 执行、批量扫描、实验统计和结果转换。

## semgrep_ruleset_scan.sh

历史 benchmark 用的 Semgrep 扫描入口，替代已弃用的本地通用规则（含噪音规则
`deref-after-arrow`）。规则集由三部分组成：

1. `rules/cpp/vendor/raptor/` —— 0xdea/semgrep-rules（MIT），唯一维护中的公开 C/C++ 规则集；
2. `rules/cpp/` —— OpenHarmony 专用规则（`oh_shared_ptr_uaf`、`oh_nothrow_null_deref`）；
3. `p/security-audit` —— 官方 registry（仅 C 规则；免费 registry 无 C++ 规则）。

```sh
# 联网（含官方 C registry 规则）
scripts/semgrep_ruleset_scan.sh path/to/file.cpp path/to/dir

# 完全离线（仅 vendor + OH 专用规则）
WITH_REGISTRY=0 scripts/semgrep_ruleset_scan.sh path/to/file.cpp
```

结果写入 `outputs/reports/semgrep/`（Git 忽略）。
