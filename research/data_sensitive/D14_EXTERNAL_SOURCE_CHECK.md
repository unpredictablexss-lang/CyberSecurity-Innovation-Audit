# D14 external source interface check

## Pinned inputs

Downloaded into /tmp/ohscanner-extra-sources as shallow, read-only clones from OpenHarmony Gitee:

- openharmony/communication_dsoftbus: ccb1a86fff03a6b2de19d39b90a81351ced5acd6
- openharmony/hiviewdfx_hilog: edbfe7c162e1d3be5838dbb8d6f88080a01206a5

These are experiment snapshots at their observed HEAD, not the historical DSoftBus commit required by the current sensitive-source profile.

## Evidence and resulting sink coverage

In communication_dsoftbus, the dfx/interface/include/{auth,trans,comm,lnn,conn,disc}_log.h headers define level macros with (label, fmt, ...) shape, so format index 1 is modeled. The check-and-return wrappers place fmt at index 3 when a return value is present and index 2 otherwise. components/nstackx/nstackx_core/dfile/include/nstackx_dfile_log.h and components/nstackx/nstackx_ctrl/include/nstackx_dfinder_log.h also put the format at index 1. components/nstackx/fillp/src/public/include/log.h defines the FILLP_LOGERR/WAR/INF/DTL/DBG/BUTT wrappers with format index 0. FillP's build flags and callback state remain unresolved runtime/build obligations.

In hiviewdfx_hilog/interfaces/native/innerkits/include/hilog_base/log_base.h, HiLogBasePrint has the same (type, level, domain, tag, fmt, ...) signature as HiLogPrint (format index 4), and each HILOG_BASE_* macro uses (type, fmt, ...) (format index 1). A caller example exists in test/moduletest/common/hilog_base_ndk_test.cpp; it is test code, not a production exposure.

Regression tests now exercise these exact call shapes, sensitive and non-sensitive operands, and the public/private format variants. They establish parser/model behavior for synthetic call bodies only.

## Boundary

This was targeted header and invocation reconnaissance, not a complete product scan of either repository. The active source model remains bound to the historical, reviewed communication_dsoftbus commit; new repository commits and hiviewdfx_hilog have no approved sensitive-source model here. The added tests therefore show that known sink syntax is recognized when a modeled sensitive flow reaches it; they do not show that either repository has a real exposure, nor establish a vulnerability or product impact. Any external source findings must remain candidate/unknown pending exact source binding and independent review.
