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
