# A memory-safety pinned scan: distributeddatamgr_kv_store

> Candidate-only report; `validated_vulnerability=0`.

- Repository: `openharmony/distributeddatamgr_kv_store`
- Commit: `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`
- Git tree: `3b92c53fde616d5a3f9487b0c295670a42c63023`
- Snapshot SHA-256: `a7917342d0733f226781468dab51d85f793f27213ba4ff7a1c5db708af4a1ff3`
- Scope manifest SHA-256: `0a2c104fdcfc6c1c617ca312569f923102c6bb9a433079097315b5f37f51417d`
- Selected files/bytes: 1446/11765303
- Wall seconds: 14.129252
- Candidate findings/groups: 11/8

## Detector runs

### `ohscanner.cpp.bounds` 0.2.0 (blocked)

- No candidate emitted in the analyzed lexical scope.

### `ohscanner.cpp.integer_bounds` 0.1.0 (blocked)

- `frameworks/jskitsimpl/distributeddata/src/js_util.cpp:118:17` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `maxLen + STR_TAIL_LENGTH` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.
- `frameworks/jskitsimpl/distributedkvstore/src/js_util.cpp:140:17` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `maxLen + STR_TAIL_LENGTH` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.
- `frameworks/libs/distributeddb/communicator/src/serial_buffer.cpp:59:23` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `totalLen_ + extendHeadLen_` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.
- `frameworks/libs/distributeddb/gaussdb_rd/src/common/src/os_api.cpp:49:22` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `maxPathLength + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.
- `frameworks/native/dbm_kv_store/src/kv_store_impl_hal/dbm_kv_store.c:928:34` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: allocation size expression `len + KV_SUM_BLOCK_SIZE` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation. Allocator semantics and reachability remain unknown.
- `frameworks/native/dbm_kv_store/src/kv_store_impl_hal/dbm_kv_store.c:964:34` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: allocation size expression `len + KV_SUM_BLOCK_SIZE` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation. Allocator semantics and reachability remain unknown.
- `kvstoremock/external_inner_kit/ipc/mock_ipc.cpp:270:35` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `rawDataSize_ + size` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.
- `kvstoremock/frameworks/jskitsimpl/distributeddata/src/js_util.cpp:128:17` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `maxLen + STR_TAIL_LENGTH` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.

### `ohscanner.cpp.resource_lifetime` 0.1.0 (blocked)

- `frameworks/libs/distributeddb/communicator/src/serial_buffer.cpp:132:22` `ohcpp-resource-lifetime-use-after-free-candidate-002` `CWE-416` Candidate only: `twinBuffer->` uses `twinBuffer` after a modeled release. Reallocation, alias recovery, destructor timing and path feasibility remain unknown.
- `frameworks/libs/distributeddb/communicator/src/serial_buffer.cpp:134:13` `ohcpp-resource-lifetime-double-free-candidate-001` `CWE-415` Candidate only: `delete twinBuffer` releases `twinBuffer` again after a modeled release. Aliases, ownership transfer and conditional paths remain unknown.
- `frameworks/libs/distributeddb/storage/src/sqlite/sqlite_multi_ver_data_storage.cpp:314:20` `ohcpp-resource-lifetime-use-after-free-candidate-002` `CWE-416` Candidate only: `iter->` uses `iter` after a modeled release. Reallocation, alias recovery, destructor timing and path feasibility remain unknown.

## Limitations

- Candidate-only lexical analysis; no confirmed/reportable vulnerability is claimed.
- No product build, permission boundary, attacker control, trigger trace or CIA impact is established.
- Pointer aliases, wrappers, macro expansion, templates, interprocedural range facts and complete CFG dominance remain unknown.
- This run uses local pinned Git objects only; no fetch, checkout or external scanner is invoked.
