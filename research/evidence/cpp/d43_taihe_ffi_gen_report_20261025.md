# D43 — Taihe FFI generator `shared_ptr_race` source audit (CR-0197–CR-0213)

## 结论

CR-0197–CR-0213 均绑定到 A0 固定对象 `openharmony/arkcompiler_taihe_ffi_gen` commit `d91f43e80d892bca694c6b0fce8ea27cd644919f` / tree `8c5eecdad09e2fe960ce5f3728959a4726f0a91d`。当前生产 CLI `ohscanner.cpp.shared_ptr_race` 0.5.1 对两个 A0 文件均完整解析，scope 为 2 文件 / 316 LOC，输出 16 个候选：CR-0197–CR-0212 的行位置全部精确匹配，CR-0213 未在其 A0 行产生当前 finding。

结论为 **PARTIAL**。CR-0197–CR-0212 对应 `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp` 中 `PixelMapImpl::m_pdata` 与 `ImageSourceImpl::m_pdata` 的构造、读取和 reset/release 访问。文件明确注释为 test file。CR-0213 是 `test/ra_napi_image/author/include/image_source_taihe.h:57` 中 `GetIncrementalPixelMap()` 返回 `navIncPixelMap_` 的 accessor；相邻实现文件也明确标记为 test file，异步 worker helper 会调用 accessor。该 header 中没有该指针的初始化/写入路径。

该固定仓库只含根 `BUILD.gn`，没有两个 author 目录的 `BUILD.gn`，根目标中也没有对这两个源文件的引用；根 build 定义是 Taihe 编译器/runtime 工具打包目标。相关 `image_source_taihe.cpp` 声明了 `imageSourceCrossThreadMutex_`，但固定源码中只有这一处声明，没有可见使用。当前证据不能证明这些 author 源进入产品构建，也不能证明同一个 wrapper/成员在可达线程间发生重叠且未同步的访问。构建系统外部集成、完整生产调用链、对象生命周期、线程调度和实际影响仍未知；没有可信修复对象或安全控制。

不改 detector：现有候选准确复现了语法观察，但尚未证明生产根因漏检或确认的数据竞争。未命中 CR-0213 也不构成安全结论。17 行 A0 状态均保持 `not_testable / paused_pending_evidence`。

## 来源、命令与验证

- 来源 commit/tree/blob/SHA、逐 ID 候选映射、scope、解析状态、规则版本、耗时和结构化 vibe coding 提示词见 [机器可读回放](d43_taihe_ffi_gen_replay_20261025.json)。
- 原始 CLI 报告见 [JSON](d43_taihe_ffi_gen_cli_20261025.json) 与 [Markdown](d43_taihe_ffi_gen_cli_20261025.md)。
- Verifier：`python research/evidence/cpp/verify_d43_taihe_ffi_gen_20261025.py --source-repo D:/openHarmonyScanner/openharmony/.repo/project-objects/arkcompiler_taihe_ffi_gen.git`
- CLI：`python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/arkcompiler_taihe_ffi_gen.git --repository openharmony/arkcompiler_taihe_ffi_gen --commit d91f43e80d892bca694c6b0fce8ea27cd644919f --include test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp --include test/ra_napi_image/author/include/image_source_taihe.h --detector ohscanner.cpp.shared_ptr_race`
- DetectorRun completed，0.0130 秒；parse complete 2/2。完整语法解析不补足线程/构建语义。

## 逐 ID 回放

| A0 ID | 源码位置 | 当前 CLI | 根因观察 |
|---|---|---|---|
| CR-0197 | `ohos.multimedia.image.image.impl.cpp:71` | exact finding | `PixelMapImpl` 从参数初始化 `m_pdata` |
| CR-0198 | `...image.impl.cpp:77` | exact finding | destructor 空值读取 |
| CR-0199 | `...image.impl.cpp:78` | exact finding | destructor 将 `m_pdata` 置空 |
| CR-0200 | `...image.impl.cpp:93` | exact finding | `GetImageInfo` 调用 |
| CR-0201 | `...image.impl.cpp:100` | exact finding | `IsHdr` 调用 |
| CR-0202 | `...image.impl.cpp:105` | exact finding | `GetRowBytes` 调用 |
| CR-0203 | `...image.impl.cpp:110` | exact finding | `GetByteCount` 调用 |
| CR-0204 | `...image.impl.cpp:115` | exact finding | `ReadPixels` 调用 |
| CR-0205 | `...image.impl.cpp:121` | exact finding | `scale` 调用 |
| CR-0206 | `...image.impl.cpp:127` | exact finding | `scale` 重载调用 |
| CR-0207 | `...image.impl.cpp:135` | exact finding | `crop` 调用 |
| CR-0208 | `...image.impl.cpp:141` | exact finding | `flip` 调用 |
| CR-0209 | `...image.impl.cpp:147` | exact finding | `m_pdata.reset()` |
| CR-0210 | `...image.impl.cpp:172` | exact finding | `ImageSourceImpl` 构造时赋值 |
| CR-0211 | `...image.impl.cpp:180` | exact finding | `ImageSourceImpl` fd 构造时赋值 |
| CR-0212 | `...image.impl.cpp:232` | exact finding | `ImageSourceImpl::release()` reset |
| CR-0213 | `image_source_taihe.h:57` | no current finding | getter 返回 `navIncPixelMap_`；缺少同文件写入路径 |

## 持续目标与最小补证

继续追踪 A0 shared_ptr 家族的 target registration、author→product 代码关系、同对象所有权和跨线程 overlap。对本组至少需要组件 owner 提供外部 harness/构建入口和实际产品调用绑定；若能绑定产品对象，再补充写入/释放与读取的线程时序及同步契约。获得可信 fixed source 后才做 fixed differential。若后续证据证明是 test-only，仍需明确外部执行边界后再调整候选状态；当前不把路径命名、无 target 或单个 accessor 当作安全证明。
