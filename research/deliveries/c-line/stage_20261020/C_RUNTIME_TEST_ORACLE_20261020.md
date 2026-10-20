# C 线 TypedArray Runtime 测试线独立核验（2026-10-20）

## 快照和范围

- 测试线 worktree：`D:\openHarmonyScanner\worktrees\c-runtime-test-closeout-20261020`
- 测试线 branch 起点与当前基础 SHA：`codex/c-runtime-test-closeout-20261020` / `61434e9b7e867d165f6031b986b23ff83a2f8a46`
- Ark Runtime source：`openharmony/arkcompiler_ets_runtime@a65a2853ccae13da167d9aa4720ab8b11ec16656`
- Ark Runtime tree：`8781f036a3e7e04d8e0b34970d5f623b42875016`
- 核验限定在现有官方测试 `test/moduletest/typedarrayset`、其 GN 入口/测试 harness、测试输入 provenance，以及可访问上游 refs 中是否存在真实改变相关实现的修复版本。本 worktree 未修改 production detector/model/runner。

## 官方 case 与 test oracle

官方 GN target 定义于 `test/moduletest/typedarrayset/BUILD.gn`：

```gn
host_moduletest_action("typedarrayset") {
  deps = []
}
```

核对 `test/moduletest/BUILD.gn` 后发现 `module_test_list` **没有** `typedarrayset`，所以此 case 不属于 `ark_js_moduletest` 聚合 group。应直接请求 case label `//arkcompiler/ets_runtime/test/moduletest/typedarrayset:typedarrayset`。共享定义在 `test/test_helper.gni` 的 `host_moduletest_action`：生成 case 的 `.abc`，依赖 host `//arkcompiler/ets_runtime/ecmascript/js_vm:ark_js_vm`，通过 `script/run_ark_executable.py` 运行，并将 stdout 与 case 的 `expect_output.txt` 对照。因此，真正的官方 case 通过必须有该直接 GN target 的 action 成功完成且期望输出匹配；仅编译源码、生成 `.abc`、运行整个 `ark_js_moduletest` group（它没有此 case）或用通用 Node.js 执行 JS 都不算此测试通过。

`typedarrayset.js` 断言形状和输出 oracle：

1. 对 `Float64Array`、`Float32Array`、`Int32Array`、`Int16Array`、`Int8Array`、`Uint32Array`、`Uint16Array`、`Uint8Array`、`Uint8ClampedArray` 各执行一次：`new ctor(8).set(new ctor(6), 2)`，打印结果。期望前八个输出行均为 8 个零（source 默认元素值为零，写入位置 2–7 仍为零）。
2. 用 `[1,1,1,1,1,1,1,1]` 的 `Int32Array` 目标执行 `set(Uint16Array([2,2,2]), 2)`；期望 `[1,1,2,2,2,1,1,1]`。
3. 同样目标执行 `set([2,2,2], 2)`；期望 `[1,1,2,2,2,1,1,1]`。
4. 对 hole 数组 `[2,,2]` 执行 set；期望 `[1,1,2,0,2,1,1,1]`。
5. 对 `[2, undefined, 2]` 执行 set；期望 `[1,1,2,0,2,1,1,1]`。

以上合计 12 行输出。这里验证的是典型 typed-array source、ordinary array-like source、hole/undefined 转换和常规 offset 写入行为。case 没有超大 offset、整数溢出边界或 sibling-view 断言；所以它是相关语义的官方 smoke/regression oracle，不直接触发或证明静态候选中的 offset-wrap/跨视图写入效果。除非另有独立定向 PoC/测试，此 case 的成功不能推导候选已修复或产品无影响。

## 目标来源绑定

对象库 `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git` 中复核：commit 完整 SHA 与 tree 为上述值。以下文件从 commit object 读取的 SHA-256 与本机 `D:\openHarmonyScanner\openharmony\arkcompiler\ets_runtime` 对应工作树字节逐一相同：

| 路径（相对 Ark Runtime 根） | Git blob | SHA-256 |
|---|---|---|
| `test/moduletest/typedarrayset/BUILD.gn` | `05cafccad3022f21b4f2164c10450526038a94b7` | `246725e9b9f2e3a1b7557ecde21a529326231246a7cbe17220c13504bf9d149b` |
| `test/moduletest/typedarrayset/typedarrayset.js` | `8ecfb752bf705bc73a8fc4968b0f44997ef62bea` | `e665af2413099b5bc143f67a30f8d97abe5215efc1c57b8dc529cddfff0de492` |
| `test/moduletest/typedarrayset/expect_output.txt` | `208b31b6bb00c73dd508a5fbb75580577ff500dd` | `eae881fa3768a24c3e72edd5b6e345822a1bde63a869cf5935327005a661b039` |
| `test/test_helper.gni` | `2915a7de1460120e010c8ece04cc8f1da43c0b8c` | `b0522075abe828c1858f57dd4d9e407f633215ddd0d2bb77af9f2681515a1504` |
| `test/moduletest/BUILD.gn` | `44676cf3fc8f2bc377c2b78b2016226ed8ca25d1` | `dda0af5013c47d08b9f9586e1b747bef42defc76dd826a0ab8f4d4a6025715be` |

The same five test/harness files above were checked as raw Git object bytes, not inferred from path names or a manifest revision alone.

## Real fixed-source availability

The canonical manifest remote is `https://gitcode.com/openharmony/arkcompiler_ets_runtime`. Its current `master` ref was independently resolved and fetched into a separate temporary bare repository at `D:\openHarmonyScanner\tmp\c-runtime-test-fixcheck-20261020.git`:

- GitCode master commit `25863269ac05c2f4d6ab84631f2de58b9aa9cf18`, tree `b86d3c98ec250c42130835386a56ee9b32c26fda`, dated 2026-10-20, subject `!15313 merge other_codesync20261012 into master`.
- Pinned `a65` is an ancestor of that master.
- `ecmascript/builtins/builtins_typedarray.cpp` blob remains `0fc27c213e1ea80d93e1e3807eec11baf2634832`.
- `ecmascript/builtins/builtins_arraybuffer.cpp` blob remains `2aa22c58803df690a5a2b326451e02297dc5e2f6`.
- `ecmascript/builtins/builtins_typedarray.h` blob remains `b291181c949c7038b7030a216f5bdc0e7474a1c2`.
- `git log --ancestry-path a65..master -- <typedarray implementation and sink>` contains no commit changing either implementation file.
- The case JS, BUILD, expected output, helper and module group BUILD blobs also remain byte-identical.

The accessible Gitee `master` resolved to `d1a58d59166777e16574ceed64c15f0b2f44a76c`, dated 2025-09-12. It is an ancestor of `a65`, not a later fixed revision. No actual source version or repair commit changing the relevant implementation was found in these checked upstream refs. Thus fixed-version comparison is **not_run / unavailable**. No fixture or synthetic patch is treated as a real repair.

## Independent runtime replay status

At this report snapshot, no developer-provided immutable binary, test output directory, build manifest, or raw log had been received. The existing product build attempt in the static-stage report stopped before GN/Ninja and created no Ark VM binary, so there is no output artifact to replay independently. This worktree did not run the official test and reports it as **not_run**, not passed.

To complete the independent leg, development must provide:

1. Immutable Ark source revision/tree and Linux-native source/build paths; binary hash and build configuration for host `ark_js_vm` plus compiler/frontend dependencies.
2. Exact generated output directory and target invocation/build log demonstrating GN target `//arkcompiler/ets_runtime/test/moduletest/typedarrayset:typedarrayset` ran, including `run_ark_executable.py` result and expected-output comparison.
3. The untouched test input/oracle hashes above, or an explicit explanation if the build used another source revision. A repair comparison still requires a real commit whose relevant implementation blob changes.

When these artifacts are available, this lane will verify their provenance and rerun the same official target in an isolated output directory; a binary alone is insufficient if it cannot be tied to the exact build/source inputs and test harness.

## 当前结论

- Official typedarrayset test oracle and source provenance: verified.
- Case target is standalone and not included in `ark_js_moduletest` group; direct target invocation is required.
- Current canonical and alternate accessible upstream refs: no matching fixed source found.
- Static candidate trigger in this case: not covered directly.
- Runtime execution and independent same-build replay: **not_run** pending immutable developer artifact.
