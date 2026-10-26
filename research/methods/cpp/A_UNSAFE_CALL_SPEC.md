# A-UNSAFE-01 C/C++ unsafe memory/format call specification

`ohscanner.cpp.unsafe_memory_call` 0.1.0 是 P2 研究 Detector，默认 `candidate/unassessed`。

## 触发

- `gets`、`strcpy`、`strcat`、`sprintf`：unbounded memory call candidate，CWE-242/120。
- `printf/fprintf/syslog/vprintf/vfprintf` 的非字面 format expression：format-string candidate，CWE-134。
- `scanf("%s", dst)`：unbounded input candidate，CWE-120。

## 排除和 unknown

- `strcpy_s`、`strcat_s`、`sprintf_s`、`snprintf`、`vsnprintf`、`fgets` 和带宽度的 `scanf("%15s", ...)` 作为安全对照。
- 字面 format、宏/包装函数、varargs、destination alias、输入控制和产品入口仍按 EvidenceObligation 保持 unknown。
- `LOG_TAG ": "...` 等宏拼接 format 在当前 lexical parser 中仍可能产生低价值候选，已列为已知 precision 缺口。

## Controls

`tests/detectors/fixtures/cpp_unsafe_calls/manifest.json` 绑定 positive/fixed/safe/unrelated/unknown controls；`tests/detectors/test_cpp_unsafe_memory_call_detector.py` 固定 source hash、determinism 和资源预算。没有独立产品 truth 前不计算 Precision/Recall。
