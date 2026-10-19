# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/hiviewdfx_faultloggerd`
- Pinned commit: `50c7dffc057a32987d5eeb7626c20e1b3717c77b`
- Git tree: `8b54f17921ba15ff306bcbef280078003a7b1055`
- Snapshot SHA-256: `cb5f512feb52edfd8074c2e1ce9cfbedb53531b04bbf847cd92d7306b7cdf497`
- Source files indexed: 11
- Parsing coverage: `{"complete": 11}`
- Detector runs: 1
- Total unverified diagnostics: 11
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.shared_ptr_race` | completed | 11 | 11 | 0 | 0 | 11 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:825a4e514c81aaec` | `interfaces/innerkits/backtrace/fp_backtrace.cpp:80` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:43071211c68328f4` | `interfaces/innerkits/backtrace/fp_backtrace.cpp:81` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:072aad444b4c0cad` | `interfaces/innerkits/backtrace/fp_backtrace.cpp:85` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:08e55eb42d49c393` | `interfaces/innerkits/backtrace/fp_backtrace.cpp:86` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:3113990f32f9e532` | `interfaces/innerkits/backtrace/fp_backtrace.cpp:92` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:9e6a516877c1c8d1` | `interfaces/innerkits/unwinder/include/thread_context.h:105` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:30c5704b904e3cff` | `tools/process_dump/coredump/coredump_note_segment_writer.h:103` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:e8bc5bf3de23df86` | `tools/process_dump/dfx_process.h:55` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:b95bbc62436d4be7` | `tools/process_dump/dfx_process.h:60` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:93f311701435a067` | `tools/process_dump/dfx_process.h:69` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:6d5edfb3cf9c579b` | `tools/process_dump/dfx_process.h:74` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.shared_ptr_race`: complete, 11/11 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/backtrace/fp_backtrace.cpp: pairwise analysis of 'interfaces/innerkits/backtrace/fp_backtrace.cpp::OHOS::FpBacktraceImpl::maps_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/stack_printer/src/stack_printer.cpp: modeled accesses to 'interfaces/innerkits/stack_printer/src/stack_printer.cpp::OHOS::StackPrinter::root_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/unwinder/include/dfx_accessors.h: modeled accesses to 'interfaces/innerkits/unwinder/include/dfx_accessors.h::OHOS::DfxAccessorsCustomize::accessors_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/unwinder/include/dfx_elf_parser.h: modeled accesses to 'interfaces/innerkits/unwinder/include/dfx_elf_parser.h::OHOS::ElfParser::mmap_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/unwinder/include/dwarf_cfa_instructions.h: modeled accesses to 'interfaces/innerkits/unwinder/include/dwarf_cfa_instructions.h::OHOS::DwarfCfaInstructions::memory_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/unwinder/include/dwarf_op.h: modeled non-atomic accesses to 'interfaces/innerkits/unwinder/include/dwarf_op.h::OHOS::DwarfOp::memory_' are constructor initialization followed only by stable reads and do not form a potential conflicting pair in this narrow model.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/unwinder/include/thread_context.h: pairwise analysis of 'interfaces/innerkits/unwinder/include/thread_context.h::OHOS::LocalThreadContextMix::maps_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/unwinder/include/unwind_entry_parser.h: modeled accesses to 'interfaces/innerkits/unwinder/include/unwind_entry_parser.h::OHOS::UnwindEntryParser::memory_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/unwinder_refactor/include/unwinder_base.h: modeled non-atomic accesses to 'interfaces/innerkits/unwinder_refactor/include/unwinder_base.h::OHOS::UnwinderBase::state_' are constructor initialization followed only by stable reads and do not form a potential conflicting pair in this narrow model.
- `ohscanner.cpp.shared_ptr_race`: tools/process_dump/coredump/coredump_note_segment_writer.h: pairwise analysis of 'tools/process_dump/coredump/coredump_note_segment_writer.h::OHOS::user_fpsimd_struct::keyRegs_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: tools/process_dump/dfx_process.h: pairwise analysis of 'tools/process_dump/dfx_process.h::OHOS::DfxProcess::keyThread_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: tools/process_dump/dfx_process.h: pairwise analysis of 'tools/process_dump/dfx_process.h::OHOS::DfxProcess::regs_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `d60475f6bbd509685209f1080ab5d5d857db860e6d6736a17f63080046f48e73`
- Language matching plans attempts; actual coverage remains in the results above.
