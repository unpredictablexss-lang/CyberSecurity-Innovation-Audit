# A memory-safety pinned scan: communication_dsoftbus

> Candidate-only report; `validated_vulnerability=0`.

- Repository: `openharmony/communication_dsoftbus`
- Commit: `652f88e0261ce4d0610f73cc451c26b84d2597af`
- Git tree: `f8a14c30ef815217fa4d267939cff84db1fd5057`
- Snapshot SHA-256: `5c8702d6cafab30fdfc12c2b146f23a9afc33fcf296b45d75a8a6a1b77b1dbe7`
- Scope manifest SHA-256: `bfe5509394b8cc176849bde1a49448d8f756736442ba929a35cb84d35869281f`
- Selected files/bytes: 1656/15243597
- Wall seconds: 85.032422
- Candidate findings/groups: 36/23

## Detector runs

### `ohscanner.cpp.bounds` 0.2.9 (blocked)

- `components/nstackx/nstackx_core/dfile/core/nstackx_file_list.c:249:9` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `memcpy_s` destination size `userDataStrLen + 1` is not proven <= allocation capacity `userDataStrLen + 1 * 1` for `validUserData`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_core/dfile/core/nstackx_file_list.c:249:9` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `memcpy_s` copy length `userDataStrLen` is not proven <= allocation capacity `userDataStrLen + 1 * 1` for `validUserData`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:170:13` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `memcpy_s` destination size `size + 1` is not proven <= allocation capacity `size + 1 * 1U` for `newBuf`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:170:13` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `memcpy_s` copy length `size` is not proven <= allocation capacity `size + 1 * 1U` for `newBuf`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:203:13` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `memcpy_s` destination size `size + 1` is not proven <= allocation capacity `size + 1 * 1U` for `newBuf`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:203:13` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `memcpy_s` copy length `size` is not proven <= allocation capacity `size + 1 * 1U` for `newBuf`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1068:9` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `strncpy_s` destination size `NSTACKX_MAX_DEVICE_NAME_LEN` is not proven <= allocation capacity `sizeof(char) * NSTACKX_MAX_DEVICE_NAME_LEN` for `dupDevName`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1068:9` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `strncpy_s` copy length `len` is not proven <= allocation capacity `sizeof(char) * NSTACKX_MAX_DEVICE_NAME_LEN` for `dupDevName`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1270:9` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `strcpy_s` destination size `maxLen` is not proven <= allocation capacity `1u * maxLen` for `out`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1340:11` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `memcpy_s` destination size `localDeviceInfo->ifNums * sizeof(NSTACKX_InterfaceInfo)` is not proven <= allocation capacity `1u * sizeof(struct ServiceDataInfo)` for `info`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1340:11` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `memcpy_s` copy length `localDeviceInfo->ifNums * sizeof(NSTACKX_InterfaceInfo)` is not proven <= allocation capacity `1u * sizeof(struct ServiceDataInfo)` for `info`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1690:9` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `strncpy_s` destination size `NSTACKX_MAX_SERVICE_DATA_LEN` is not proven <= allocation capacity `1U * NSTACKX_MAX_SERVICE_DATA_LEN` for `serviceDataTmp`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1690:9` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `strncpy_s` copy length `len` is not proven <= allocation capacity `1U * NSTACKX_MAX_SERVICE_DATA_LEN` for `serviceDataTmp`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1739:9` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `strncpy_s` destination size `NSTACKX_MAX_BUSINESS_DATA_LEN` is not proven <= allocation capacity `1 * NSTACKX_MAX_BUSINESS_DATA_LEN` for `businessDataTmp`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1739:9` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `strncpy_s` copy length `len` is not proven <= allocation capacity `1 * NSTACKX_MAX_BUSINESS_DATA_LEN` for `businessDataTmp`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1791:9` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `strncpy_s` destination size `NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN` is not proven <= allocation capacity `1 * NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN` for `extendServiceDataTmp`; aliases, guards and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1791:9` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `strncpy_s` copy length `len` is not proven <= allocation capacity `1 * NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN` for `extendServiceDataTmp`; aliases, guards and reachability remain unknown.

### `ohscanner.cpp.integer_bounds` 0.2.2 (blocked)

- `components/nstackx/nstackx_core/dfile/core/nstackx_file_list.c:124:5` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: `calloc` multiplies count `fileListInfo->fileNum` by element size `sizeof(FileListEntry)` for `entryList` without a modeled checked multiplication; overflow may undersize the allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_core/dfile/core/nstackx_file_list.c:175:15` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: `calloc` multiplies count `fileNum` by element size `sizeof(FileListEntry)` for `list` without a modeled checked multiplication; overflow may undersize the allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_core/dfile/core/nstackx_file_list.c:269:30` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: allocation size expression `userDataLength + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_core/dfile/core/nstackx_file_list.c:579:19` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: `calloc` multiplies count `fileNum` by element size `sizeof(char *)` for `remotePath` without a modeled checked multiplication; overflow may undersize the allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_core/dfile/core/nstackx_file_list.c:624:19` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: `calloc` multiplies count `fileListPara->fileNum` by element size `sizeof(char *)` for `files` without a modeled checked multiplication; overflow may undersize the allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:165:29` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: allocation size expression `size + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:198:29` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: allocation size expression `size + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:1608:33` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: `calloc` multiplies count `cnt` by element size `sizeof(struct NSTACKX_ServiceData)` for `data` without a modeled checked multiplication; overflow may undersize the allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:2070:26` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: `calloc` multiplies count `(responseSettings->length + 1)` by element size `sizeof(char)` for `businessData` without a modeled checked multiplication; overflow may undersize the allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:2389:16` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: `calloc` multiplies count `(config->msgLen + 1)` by element size `sizeof(char)` for `msg` without a modeled checked multiplication; overflow may undersize the allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:2395:16` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: `calloc` multiplies count `config->intervalLen` by element size `sizeof(uint16_t)` for `intervalsMs` without a modeled checked multiplication; overflow may undersize the allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_dfinder_hidump.c:102:11` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: `calloc` multiplies count `size` by element size `sizeof(char)` for `buf` without a modeled checked multiplication; overflow may undersize the allocation. Allocator semantics and reachability remain unknown.
- `components/nstackx/nstackx_util/core/nstackx_util.c:153:19` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: allocation size expression `len + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation. Allocator semantics and reachability remain unknown.

### `ohscanner.cpp.resource_lifetime` 0.1.3 (blocked)

- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:189:9` `ohcpp-resource-lifetime-double-free-candidate-001` `CWE-415` Candidate only: conditional path releases `newBuf`, then `free(newBuf)` uses or releases it on a falling-through path. Path feasibility, aliases, ownership transfer and guard dominance remain unknown.
- `components/nstackx/nstackx_ctrl/core/nstackx_common.c:222:9` `ohcpp-resource-lifetime-double-free-candidate-001` `CWE-415` Candidate only: conditional path releases `newBuf`, then `free(newBuf)` uses or releases it on a falling-through path. Path feasibility, aliases, ownership transfer and guard dominance remain unknown.
- `sdk/napi/link_enhance/src/napi_link_enhance_connection.cpp:181:9` `ohcpp-resource-lifetime-double-free-candidate-001` `CWE-415` Candidate only: conditional path releases `connection`, then `delete connection;` uses or releases it on a falling-through path. Path feasibility, aliases, ownership transfer and guard dominance remain unknown.

### `ohscanner.cpp.unsafe_memory_call` 0.1.2 (blocked)

- `components/nstackx/nstackx_util/core/nstackx_log.c:31:5` `ohcpp-format-string-candidate-002` `CWE-134` Candidate only: `vprintf` receives a non-literal format expression `format`. Control, intended format ownership and concrete impact remain unknown.
- `components/nstackx/nstackx_util/platform/liteos/sys_log.c:29:5` `ohcpp-format-string-candidate-002` `CWE-134` Candidate only: `vprintf` receives a non-literal format expression `format`. Control, intended format ownership and concrete impact remain unknown.
- `components/nstackx/nstackx_util/platform/unix/sys_log.c:29:5` `ohcpp-format-string-candidate-002` `CWE-134` Candidate only: `vprintf` receives a non-literal format expression `format`. Control, intended format ownership and concrete impact remain unknown.

## Limitations

- Candidate-only lexical analysis; no confirmed/reportable vulnerability is claimed.
- No product build, permission boundary, attacker control, trigger trace or CIA impact is established.
- Pointer aliases, wrappers, macro expansion, templates, interprocedural range facts and complete CFG dominance remain unknown.
- This run uses local pinned Git objects only; no fetch, checkout or external scanner is invoked.
