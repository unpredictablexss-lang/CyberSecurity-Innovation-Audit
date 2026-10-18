# A-UNSAFE-01 C/C++ unsafe memory/format call specification

`ohscanner.cpp.unsafe_memory_call` 0.1.3 是 P2 研究 Detector，默认 `candidate/unassessed`。

## 触发

- `gets`、`strcpy`、`strcat`、`sprintf`：unbounded memory call candidate，CWE-242/120。
- `printf/fprintf/syslog/vprintf/vfprintf` 的非字面 format expression：format-string candidate，CWE-134。
- `fprintf/vfprintf/syslog` 的 format 参数是第 1 个实参，流/优先级是第 0 个；0.1.2 修复了把 stream 当 format 的误报。
- `scanf("%s", dst)`：unbounded input candidate，CWE-120。

## 排除和 unknown

- `strcpy_s`、`strcat_s`、`sprintf_s`、`snprintf`、`vsnprintf`、`fgets` 和带宽度的 `scanf("%15s", ...)` 作为安全对照。
- 字面 format、宏/包装函数、varargs、destination alias、输入控制和产品入口仍按 EvidenceObligation 保持 unknown。
- `LOG_TAG ": "...` 等仅由全大写宏标识符和字符串字面量组成的格式表达式按 `unknown_macro_format` 处理，不产生候选；这是 0.1.1 修复的已知误报形状。

## Controls

`tests/detectors/fixtures/cpp_unsafe_calls/manifest.json` 绑定 positive/fixed/safe/unrelated/unknown controls，包括宏格式 quiet 和真实非字面量 format 正例；`tests/detectors/test_cpp_unsafe_memory_call_detector.py` 固定 source hash、determinism 和资源预算。没有独立产品 truth 前不计算 Precision/Recall。

The 0.1.2 fixed-corpus replay is recorded in
`research/evidence/cpp/a_line_scan_20261018_v6_comparison.json`; candidate and
group totals remain 33/22 with no new real-source hit.
