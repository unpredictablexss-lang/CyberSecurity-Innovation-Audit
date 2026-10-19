# Owner RFC request — prepared, not approved

1. Optional shared detailed expression/statement facts with source ranges, lexical binding IDs,
   assignment/copy edges, function parameters and return-status effects. Example:
   SessionKey *k; const char *p=(const char*)k->value; AUTH_LOGI(...,"%{public}s",p).
   Expected: material member -> alias -> exact public operand, with SHA/coverage and no secret values.
2. Source-qualified type/API identity, include resolution, typedef/function-pointer conflicts;
   D cannot assume same-name SessionKey/LOG or commit origin proves actual target identity.
3. Per-call modelled macro variants, format expansions and privacy markers/build flags; distinguish
   status/length from secret buffers and public/private operands. PRI/dynamic format needs unknown.
4. Reviewed policy for partial AST local inspection with explicit file_outcomes. Current runner
   skips six of nine selected real files; D has not modified runner to change that behavior.
5. Production log visibility/privacy switches, level enablement and reader permissions as optional
   evidence facts; do not add mandatory private AST objects to global contract.

Proposed ID ohscanner.data.sensitive_exposure needs owner confirmation before production submission/
registration. No global files modified. Scope remains native local log rule, not B/A/C tasks.

## D2 最小请求（2026-10-17，未获公共修改批准）

固定commit0e0c18c4的auth_session_key.c因LIST_FOR_EACH_ENTRY缺失标点被整文件跳过；私有探针
30函数中15个无直接错误交叠。这不是自动准入证据。优先请求一个可选函数事实：
file/blob/SHA、profile/解析器版本、函数范围、错误范围、局部绑定/赋值和日志operand，
并保留外围宏/类型依赖缺口。负责人先定义错误隔离/资格及兼容性测试，再考虑准入；
D不修改Runner。头文件单独提供受审声明/宏事实，不把无函数头文件说成flow complete。
验收最小对照：返回分支不流向后继、存活else继续产生候选；相同固定9文件覆盖计数闭合；
partial候选与unknown独立保留，不改A/B/C语义。完整依据见D2_COVERAGE.md/json。
