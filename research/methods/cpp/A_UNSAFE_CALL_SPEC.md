# A-UNSAFE-01 C/C++ unsafe memory/format call specification

`ohscanner.cpp.unsafe_memory_call` 0.5.0 是 P2 研究 Detector，默认 `candidate/unassessed`。

## 触发

- `gets`、`strcpy`、`strcat`、`sprintf`：unbounded memory call candidate，CWE-242/120。
- `printf/vprintf` 第 1 个参数、`fprintf/vfprintf` 第 2 个参数、`syslog` 第 2 个参数为非字面 format expression 时：format-string candidate，CWE-134。Detector 0.2.0 起按 API 各自的 format 参数位置取值；0.3.0 起，限定调用或源码中存在同名函数声明时保留 partial/unknown，不猜测符号解析结果；0.4.0 起，直接字符串字面量以及两分支均为字符串字面量的条件表达式不再作为非字面候选；0.5.0 起，普通与 C++ raw string 字面量均识别为编译期格式字面量，raw-string 内容中的标点不会参与调用实参切分。宏 token、变量、函数调用和混合动态分支继续保留候选/unknown。
- `scanf("%s", dst)`：unbounded input candidate，CWE-120。

## 排除和 unknown

- `strcpy_s`、`strcat_s`、`sprintf_s`、`snprintf`、`vsnprintf`、`fgets` 和带宽度的 `scanf("%15s", ...)` 作为安全对照。
- 字面 format、宏/包装函数、varargs、destination alias、输入控制和产品入口仍按 EvidenceObligation 保持 unknown。
- `LOG_TAG ": "...` 等宏拼接 format 在当前 lexical parser 中仍可能产生低价值候选，已列为已知 precision 缺口。

## Controls

`tests/detectors/fixtures/cpp_unsafe_calls/manifest.json` 绑定 positive/fixed/safe/unrelated/unknown、API 参数位与 raw-string controls；`tests/detectors/test_cpp_unsafe_memory_call_detector.py` 固定 source hash、determinism、API 参数位置和资源预算。没有独立产品 truth 前不计算 Precision/Recall。

旧版 `fprintf`/`vfprintf` 错把第一个参数 stream 当作 format。固定扫描重放证明该参数位错误影响旧 `fprintf`/`vfprintf` 候选；v8 影响范围、源码身份和两侧依赖 hash 见 `research/evidence/cpp/a_unsafe_memory_review_20261018/format_argument_positions_before_after_20261019_v8.json`。共享实参切分器对旧 unsafe-memory-call 子集的影响见 `unsafe_memory_call_argument_split_replay_20261019_v3.json`；条件格式与 raw string literal 重放见 `literal_format_conditional_replay_20261019_v4.json`。这些都是定点开发回归，不能代替全库重扫或人工 TP/FP 复核。
