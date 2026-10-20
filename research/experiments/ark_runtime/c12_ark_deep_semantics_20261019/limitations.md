# C12 limitations

- Helper contracts are local, syntax-bounded and source-hash-bound. Calls with macros, templates, overloads, recursion, lambdas or unknown external definitions remain explicit unknown.
- Effect contracts do not prove purity, ownership, concurrency, exception behavior or CIA impact. Effectful helpers invalidate identity and are not safe conclusions.
- Numeric sign-width analysis is lexical and bounded to typed multiplication, allocation and copy-loop shapes. It does not prove C++ integer promotion, range, overflow, macro expansion or path feasibility.
- Loop backedges cover only generated `LoopBegin`/`LoopEnd` label pairs. Host C++ loops, unresolved labels and arbitrary CFGs remain unsupported/unknown.
- Forwarding summaries are a bounded fixed point over one same-typed parameter and exact one-return helper bodies. Cross-function points-to, side-effect summaries and recursion are not solved.
- No product build, authorized dynamic PoC, attacker entry/permission boundary or CIA impact evidence was added. Candidate/unknown outcomes are not confirmed/reportable and no Precision/Recall is computed.
