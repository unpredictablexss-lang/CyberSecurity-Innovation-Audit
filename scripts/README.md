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

## joern_nothrow_guard.sc

Joern CPG 查询脚本，输出 `src/providers/joern.py` 约定的 findings JSON。

对每条 `$v = new (std::nothrow) T(...)` 判定：方法内存在 `$v->...` 解引用，且方法内
**没有把 `$v` 本身与 null-ish 字面量比较**，才报为候选缺失空指针守卫（CWE-476）。
这是 v2：相比 v1 的"方法级比较计数"，它消除了安全封装（只分配并 return）的假阳性，
以及无关比较（如 `strcmp(...) != 0`）造成的假阴性。它仍是**结构性启发式**，不是数据流
证明，也不识别自定义守卫函数或调用方的判空。

```sh
joern-parse <file> -o cpg.bin
JOERN_CPG=cpg.bin JOERN_OUT=findings.json JOERN_VERSION=4.0.649 \
    joern --script scripts/joern_nothrow_guard.sc
python -m src.cli normalize-tool-output --provider joern \
    --input findings.json --target-id <id> --commit <sha> \
    --scope-files 1 --scope-loc <loc> --elapsed-seconds 1.0 \
    --json-out outputs/reports/joern.json --md-out outputs/reports/joern.md
```

当前运行/验证见 [开发协作与交付指南](../docs/开发协作与交付指南.md)；原阶段记录可用 `git show 143fa63:PROGRAM_STATUS.md` 查阅。
