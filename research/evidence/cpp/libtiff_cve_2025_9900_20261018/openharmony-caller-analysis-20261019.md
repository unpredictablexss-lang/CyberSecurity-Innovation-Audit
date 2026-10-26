# OpenHarmony libtiff caller-path analysis — CVE-2025-9900

Verification date: 2026-10-19. This note assesses local source reachability and trigger conditions; it is not a product vulnerability confirmation.

## Source identity

OpenHarmony project-heads records these checkout commits and object stores. Hashes were recomputed from those exact Git blobs and match the working-tree source examined.

- `third_party/libtiff`: commit `d4a0516c477dfbaf1153ae295893ab75aadd63d4`, tree `33beab3b3b50fe6678b1a74ed48ac3b69084c6ec`. `BUILD.gn` blob `c506360c4d767b8331c352894bdf16c023327daa`, SHA-256 `23fe746dc2f2e1bfe6972e078238ce46c296f252cf8f5ac80f75e9538aa70f25`; `libtiff/tif_getimage.c` blob `5121e85b9eb2bc734b557892c0968f629d370b82`, SHA-256 `4b664c80e2e208c2a9cd33042419f69e590ff088c1a3befe99581d1b1df5471a`.
- `foundation/multimedia/image_framework`: checkout commit `5fbe952024f16cb518a5a7cec24063cffcc038bd`, tree `33cb49524a6f2fdce502b74c1e6bc3e9f61193a9`. `tiff_decoder.cpp` blob `952e20b050d5b2298017e99463f90ebf25892ed4`, SHA-256 `844e37b83a24da27a3e41104d6f265395e39a5ca356ec393be873dbc2d69c643`; `frameworks/innerkitsimpl/codec/src/image_source.cpp` blob `fa7cc17ea8fc0052ac13f38bd42c967434302fe9`, SHA-256 `d24f7fdeb133ab6b2f2e24351faa1926e63cda24eeaf83f4859c381810aa6b6b`; public `interfaces/innerkits/include/image_source.h` blob `2e9ccbb988c06ca7e6f05c1ca9197c69ceb3b424`, SHA-256 `79763cb76fca37c4fe92ff8d8f2200b274ba88056766f611fa15ec4d108e5e15`; plugin `BUILD.gn` blob `40a881036dbbf3994ad70b2cc02f8fa601dc40dc`, SHA-256 `60d4eaf82a29587457a2d511d10db4f2e3473804417fa0ae23cf20523a7931c1`; `image_decode_config.gni` blob `47250f382baf1a44c966a619552995663e0d2cbd`, SHA-256 `32fa92d118f5ea1098106cbac6ab9b2cb7462de682ab9eff0788aec01279d369`.
- `third_party/backends`: checkout commit `d0621aa49910a02e8bd6876a22987bfa351818dd`, tree `2dfa719111170881dd7aad1a670959b9faf1ee50`. `backend/dell1600n_net.c` blob `45b0d2c76f0f25932440bd62d92460c6cb42334e`, SHA-256 `17ce3441cf235f9aaaa0fc9b7ec1c3d01dec266ff552d0a3f3bee8b1350c8f3e`; BUILD blob `278fd502243b5a14c3afe16f74f42a50966d3427`, SHA-256 `aaf73392cb8c709c0a5bc9201f7d4130731dfdca9abb99d43002c9a3fba4c479`.

The checked-out image framework commit differs from the separate `openharmony-manifest-current-20261018.xml` revision (`c9647acc...`); current checkout identity above is taken from the pinned project-heads inventory/object store, not silently replaced with that manifest revision. The selected product `args.gn`/`global_parts_info` is unavailable.

## Call paths and dimension relationship

1. `foundation/multimedia/image_framework/plugins/common/libs/image/libtiffplugin/src/tiff_decoder.cpp`:
   - Public `ImageSource::CreateImageSource` overloads accept an `istream`, byte buffer (`data,size`), pathname or file descriptor; `DoCreateDecoder` creates the selected plugin and calls `decoder->SetSource(sourceData)` (image_source.cpp lines 414-525, 3074-3091). This shows the decoder can receive caller-supplied image bytes; which callers pass attacker-controlled data and their permissions are unknown.
   - `SetSource` opens input bytes through `TIFFClientOpenExt` and applies libtiff allocation caps.
   - `GetImageSize` (lines 244-253) reads `TIFFTAG_IMAGEWIDTH` into `size.width` and `TIFFTAG_IMAGELENGTH` into `size.height`.
   - `SetDecodeOptions` stores that `tiffSize_`; the shown decode path allocates a buffer using `tiffSize_.width * tiffSize_.height * sizeof(uint32_t)` after overflow checking, then calls `TIFFReadRGBAImageOriented` with exactly `tiffSize_.width` and `tiffSize_.height` (line 215).
   - Thus this known caller passes the dimensions read from the same TIFF handle as both image metadata and output dimensions. The specific vulnerable condition `rheight < img.height` is not evidenced on this path. Input bytes may be supplied through a decoder stream, but upstream caller/trust context is not established here.
2. `third_party/backends/backend/dell1600n_net.c`:
   - The network backend reads `m_pixelWidth`/`m_pixelHeight`, writes those same values as TIFF width/height tags, and calls `TIFFReadRGBAImageOriented` with the same `width`/`height` values (around lines 1910-1956).
   - The inspected call therefore also keeps output height equal to the image height. It constructs a temporary TIFF from scanner data rather than accepting an arbitrary TIFF file at that point; transport attacker control and target inclusion are not assessed.
3. `third_party/libtiff/tools/tiff2rgba.c` and `tiff2pdf.c` also call the API, but the OpenHarmony `third_party/libtiff/BUILD.gn` library source list includes libtiff library sources and not these tools. No GN product inclusion of those tools was found in this component build file.

The local `out/ohos_config.json` identifies product/board `rk3568` (SHA-256 `872f8c20aee965d2d792623d381288f0f4e839f3368c19b1900c3fa34ccf4a58`). Its pinned product source `vendor/hihope/rk3568/config.json`, commit `b40eabbe69943126c65df1f9ff28057f56e93e46`, tree `aa95785ef84ddde8d1c3622e2c2d80d6b388caeb`, blob `fc7fed801d07f19f05a752878e738d8d40f1bc01`, SHA-256 `46dc640a6ca988687245de967f4e2ec3aebd20ed3423472c48b89bc845c28408`, lists both `image_framework` and `libtiff` components. The plugin is declared as `ohos_shared_library("tiffplugin")` and links `libtiff:libtiff` under `if (has_libtiff)`. `image_decode_config.gni` defaults `has_libtiff = true`, then disables it if generated `global_parts_info` lacks `thirdparty_libtiff`. Thus product source configuration includes both parts and the GN path conditionally links them, but the final inclusion is not confirmed: `out/rk3568`, `args.gn`, `build.ninja` and generated `global_parts_info` are absent. This is source/product-config association, not a verified shipped binary.

## Product interpretation

The upstream component bug and isolated API reproduction are verified. The known OpenHarmony image-framework caller appears to pass equal image/output heights, which avoids the measured trigger condition. This lowers evidence for the known caller path but does not prove the whole product unaffected: target selection is unknown, source-level cross-component behavior is not dynamically verified, and other callers or binary backports are not excluded. Keep product vulnerability confirmation `unknown` and static result `candidate/partial`.
