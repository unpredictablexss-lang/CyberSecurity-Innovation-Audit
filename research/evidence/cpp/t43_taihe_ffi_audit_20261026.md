# T43 独立测试线：Taihe FFI shared_ptr_race CR-0197–CR-0213

- 源码身份：`openharmony/arkcompiler_taihe_ffi_gen` commit `d91f43e80d892bca694c6b0fce8ea27cd644919f`，tree `8c5eecdad09e2fe960ce5f3728959a4726f0a91d`。
- 当前 CLI：`ohscanner.cpp.shared_ptr_race 0.5.1`；两文件解析完整，16 条诊断对应 17 条 A0 记录，耗时 0.0123s。
- 16 条位于 `ani_image` 实现文件的记录逐条对应 CLI finding；CR-0213 位于 header 的 getter return，没有当前 finding。该差异不是安全结论。
- 构建证据：根目录 BUILD.gn 构建 Taihe 工具且不引用这两个源文件；测试目录仅找到无关的 integer BUILD.gn。header 自述为 test file；产品目标未绑定。
- 同一对象的无同步并发读写、线程重叠、有效产品调用路径及安全影响均未证明。无可信修复源/安全真值。
- 结论：全部保留 `PARTIAL/BLOCK`；17 条 A0 状态保持 `not_testable / paused_pending_evidence`。不修改 detector、测试、fixtures 或 A0。

| A0 ID | 源位置 | 当前 CLI 映射 | 源码行 |
|---|---|---|---|
| CR-0197 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:71` | exact_cli_match `ohscanner.cpp.shared_ptr_race:8d6286e5eafb34fd` | `PixelMapImpl(std::shared_ptr<OHOS::Media::PixelMap> ptr) : m_pdata(ptr)` |
| CR-0198 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:77` | exact_cli_match `ohscanner.cpp.shared_ptr_race:880bc0ba329b194d` | `if (this->m_pdata != nullptr) {` |
| CR-0199 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:78` | exact_cli_match `ohscanner.cpp.shared_ptr_race:3ad2d1d372fafff8` | `this->m_pdata = nullptr;` |
| CR-0200 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:93` | exact_cli_match `ohscanner.cpp.shared_ptr_race:26c9c90f2b13cc18` | `this->m_pdata->GetImageInfo(imgInfo);` |
| CR-0201 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:100` | exact_cli_match `ohscanner.cpp.shared_ptr_race:bf85e66d6de6c9b6` | `this->m_pdata->IsHdr()};` |
| CR-0202 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:105` | exact_cli_match `ohscanner.cpp.shared_ptr_race:fd51492cdc79af3b` | `return this->m_pdata->GetRowBytes();` |
| CR-0203 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:110` | exact_cli_match `ohscanner.cpp.shared_ptr_race:624d7032e82ec827` | `return this->m_pdata->GetByteCount();` |
| CR-0204 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:115` | exact_cli_match `ohscanner.cpp.shared_ptr_race:c4b7b7f2942f8f07` | `this->m_pdata->ReadPixels(buff.size(), buff.data());` |
| CR-0205 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:121` | exact_cli_match `ohscanner.cpp.shared_ptr_race:1ea1fecb0e6dc1fb` | `this->m_pdata->scale(static_cast<float>(x), static_cast<float>(y), OHOS::Media::AntiAliasingOption::NONE);` |
| CR-0206 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:127` | exact_cli_match `ohscanner.cpp.shared_ptr_race:5d42d40f86152d59` | `this->m_pdata->scale(static_cast<float>(x), static_cast<float>(y),` |
| CR-0207 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:135` | exact_cli_match `ohscanner.cpp.shared_ptr_race:6bb80129cb32948f` | `this->m_pdata->crop(rect);` |
| CR-0208 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:141` | exact_cli_match `ohscanner.cpp.shared_ptr_race:150c0d2b5aa5e7d8` | `this->m_pdata->flip(horizontal, vertical);` |
| CR-0209 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:147` | exact_cli_match `ohscanner.cpp.shared_ptr_race:90e903ce531fb54a` | `this->m_pdata.reset();` |
| CR-0210 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:172` | exact_cli_match `ohscanner.cpp.shared_ptr_race:14c582e97324b03b` | `this->m_pdata = OHOS::Media::ImageSource::CreateImageSource(this->filePath_, opts, errorCode);` |
| CR-0211 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:180` | exact_cli_match `ohscanner.cpp.shared_ptr_race:dc40f6c2ce9e21a6` | `this->m_pdata = OHOS::Media::ImageSource::CreateImageSource(fd, opts, errorCode);` |
| CR-0212 | `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp:232` | exact_cli_match `ohscanner.cpp.shared_ptr_race:f12d5f19f8387b31` | `this->m_pdata.reset();` |
| CR-0213 | `test/ra_napi_image/author/include/image_source_taihe.h:57` | no_current_cli_diagnostic_at_A0_location | `return navIncPixelMap_;` |

机器记录：`t43_taihe_ffi_audit_20261026.json`；原始 CLI：`t43_taihe_ffi_cli_20261026.json` / `.md`；验证器：`verify_t43_taihe_ffi_audit_20261026.py`。
