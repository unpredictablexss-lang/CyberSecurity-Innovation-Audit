# OpenHarmony curl MIME consumer call-site precheck

Date: 2026-10-19. This is a source-call-site inventory, not a complete product reachability or security verdict.

## Scope and method

Searched OpenHarmony source trees `foundation`, `applications`, `base`, and `interfaces` for C/C++ calls to `curl_mime_subparts`. No matches were found in those trees. The whole checkout search finds references in `third_party/curl` implementation, command-line tooling, tests and examples. These repository-wide searches are incomplete where Windows reported unreadable symlink/dangling paths; the positive consumer sites below were readable.

## Observed flat MIME consumers

- `foundation/communication/netstack/frameworks/native/http/http_client/http_client_task.cpp`: `SetMultiPartOption` initializes one MIME root (line 567), adds each `multiFormDataList` item directly as a part (line 581), and frees the root (line 590). No nested subparts call appears in the checked consumer tree.
- `foundation/communication/netstack/frameworks/js/napi/http/http_exec/src/http_exec.cpp`: `SetMultiPartOption` initializes one root (line 3204) and adds list entries directly (line 3219); async request context owns/frees `multipart_` at `frameworks/js/napi/http/async_context/src/request_context.cpp:956`.
- Cangjie HTTP code has analogous root initialization/flat part insertion in `frameworks/cj/http/src/net_http_client_exec.cpp:750,765`; request context cleanup at `frameworks/cj/http/src/net_http_request_context.cpp:133`.

The advisory trigger requires a deeply nested tree. The scanned OpenHarmony consumers construct flat forms and no in-scope `curl_mime_subparts` call was found; this weakens evidence for the specific nested-tree trigger in those call paths. It does not prove all product consumers/builds are covered, nor rule out another route or lower-level caller. No final product build graph, runtime call instrumentation, app trust boundary, or attacker-control evidence is available. Product vulnerability status remains unknown.

## Evidence commands

```powershell
rg -n --glob '*.{c,cc,cpp,h,hpp}' '\bcurl_mime_subparts\s*\(' D:\openHarmonyScanner\openharmony\foundation D:\openHarmonyScanner\openharmony\applications D:\openHarmonyScanner\openharmony\base D:\openHarmonyScanner\openharmony\interfaces
rg -n --no-messages --glob '*.{c,cc,cpp,h,hpp}' '\bcurl_mime_(init|addpart|free)\s*\(' D:\openHarmonyScanner\openharmony
```

`curl_mime_subparts` matches within `third_party/curl` include the library implementation, command-line form parser/tooling, tests and examples. Those are not proof that the shipped OpenHarmony netstack consumer builds a nested MIME graph.


## Current-turn focused consumer recheck (2026-10-19)

The C/C++ call search was repeated only in `foundation`, `applications`, `base`, and `interfaces` to avoid the unreadable symlink noise from the full checkout sweep. No `curl_mime_subparts(...)` calls were found there. A broader MIME API search found four flat builders: `base/request/.../curl_adp.cpp:205-217`, native netstack `http_client_task.cpp:567-581`, JS NAPI `http_exec.cpp:3204-3219`, and Cangjie `net_http_client_exec.cpp:750-765`. These create one root and append data/file parts; none establishes nested MIME construction. The root MIME data/part counts may be caller-influenced but the recursive depth stays one in these observed callsites.

The four source files are byte-bound by SHA-256:

- `base/request/request/frameworks/js/napi/request/src/upload/curl_adp.cpp`: `d0257d85b4a450dcc265ca799566a1319e9cfbec384d72a4b2a4353a86a72f5b`
- `foundation/communication/netstack/frameworks/native/http/http_client/http_client_task.cpp`: `6d311900537e5ad3968a2a70fd452f05a91918e7b771e233fb4b9b38cbcc5d55`
- `foundation/communication/netstack/frameworks/js/napi/http/http_exec/src/http_exec.cpp`: `165568b3bc4c6dcc810bb52d7374202eb17724ce6b9dc06989c78087ace49bf2`
- `foundation/communication/netstack/frameworks/cj/http/src/net_http_client_exec.cpp`: `ce29a393681420d1a53b6b51fa4844141b372e0e1921b9396033735e186ff72c`

The full checkout search still reports inaccessible paths, and product target selection/linkage, possible unscanned external consumers, other source languages, runtime call instrumentation, and attacker control remain unknown. This scoped negative evidence weakens known netstack path exposure; it is not a product safe verdict.


## Request upload API input and cleanup trace (2026-10-19)

Traced the request upload NAPI path from `UploadTaskNapiV5::JsUpload` through `JSUtil::ParseUploadConfig` / `ToUploadOption` to `CUrlAdp::SetMimePost` and cleanup:

1. The public ETS `UploadConfig` declares `files: Array<File>` and `data: Array<RequestData>`; each `RequestData` is only `{name, value}`. It has no nested MIME-part or subparts field. Source file `base/request/request/frameworks/ets/ani/request/ets/@ohos.request.ets`, 45,123 bytes, SHA-256 `c6c1e4fa8c8fb1e21ecd935c827f4d0276e65e803deca522d0e2cf4a609890bd`.
2. NAPI `JsUpload` obtains a `Context`, parses the config, then creates `UploadTask`; `JSUtil::SetData` converts the JS data array to `vector<RequestData>` and `SetFiles` converts files to `vector<File>`. `UploadConfig` stores only those flat vectors (`upload_config.h`, SHA-256 `b072b94e05a3fdfab9a24a0729ff7ddb6b100f071f5beffd2162c4697f3d58d3`). `js_util.cpp` SHA-256 `1b26cbf217ba8d3da51c644c6d492229ebb25a62d8cdacb51a915380316998cd`; `upload_task_napiV5.cpp` SHA-256 `92db18246705a40c5a43395bd51066aafd36119a7a2b78915499182211fbe1d4`.
3. `SetMimePost` initializes a single `curl_mime` root and calls `curl_mime_addpart` once per data entry, then adds one file part with `curl_mime_addpart`; it never calls `curl_mime_subparts`. The adapter sets `CURLOPT_MIMEPOST`. During each upload, `DoUpload` calls `ClearCurlResource`; `curl_easy_cleanup`/`curl_multi_cleanup` then release the easy/multi handles. Adapter source SHA-256 is `d0257d85b4a450dcc265ca799566a1319e9cfbec384d72a4b2a4353a86a72f5b`; task source SHA-256 is `476fb2e5fc557a809c4b861bc645c961fb9bf2c2ba7eb536127e38baa7d98672`.

For this API path, JS-controlled file/data count and values do not translate into MIME nesting depth: the public schema and adapter construct one-level parts only. This is source-level evidence that the checked upload API path cannot create the advisory's deep nested tree through its config. Caller permissions, whether this module is selected into a given product, any other lower-level caller, and runtime behavior remain unverified. Do not convert this path-specific result into a product-wide safe verdict. The earlier focused search found no `curl_mime_subparts` token in any source language under `foundation`, `applications`, `base`, or `interfaces`; the broader whole-checkout search remains incomplete because some paths are unreadable on this mount.


## Netstack request-schema and cleanup trace (2026-10-19)

The native, JS NAPI and Cangjie multipart call paths were traced to their request representation and cleanup owner:

- **JS NAPI:** public `@ohos.net.http.d.ts` `MultiFormData` is a flat record of name/contentType/remoteFileName/data/filePath; the source hash is `46a2287a467afb38ab97d814d73f2b6d0d70f1c5d5f533a7f9b97b08b7a99fa5`. Internal `http_request_options.h` repeats the flat fields (SHA-256 `f21a0ed82042bcb51940b94adba69934f8235e92fc837ee935a76cd9b63b3152`). `HttpExec::SetMultiPartOption` creates one root and appends each record; `RequestContext` owns the root and calls `curl_mime_free` in its destructor (`request_context.cpp` SHA-256 `6e25e91bfa3130ca5ec14d0adaea9b3db5d79fe3f00b640740614f7f3ff27cc2`).
- **Native C++ API:** innerkit `HttpMultiFormData` is a flat record of the same fields (header SHA-256 `8f106ad1d38295a897aabc8d6d3e4cb5cb9168d5b8df10763cdcddca181ac20b`). `HttpClientTask::SetMultiPartOption` adds each record under one MIME root; `SetFormDataOption` only sets name/type/filename/data/filedata. No nested tree field or `curl_mime_subparts` call appears.
- **Cangjie FFI:** `CMultiFormData` likewise carries name/contentType/remoteFileName/data/filePath fields, and `CArrMultiFormData` is an array of those records (header SHA-256 `28912389d01c38d72a478fc946dc9ae25a7862fa13da5557516b117a76113636`). `ParseMultiFormData` maps each flat record to `MultiFormData`; `NetHttpClientExec::SetMultiPartOption` appends each to one root. `RequestContext` frees the root with `curl_mime_free` at destruction (context SHA-256 `432f2450272f8b0d777781982d7b656d82d8efba314f002cd4bbefe03511c3d0`). `net_http_request.h` record hash is `409b43a29de81235e43bcbd52fbd721feb65634a20eaa1da37f593e944b57b05`.
- The producer implementation hashes from the previous section apply: `http_exec.cpp` `165568b3bc4c6dcc810bb52d7374202eb17724ce6b9dc06989c78087ace49bf2`, native task `6d311900537e5ad3968a2a70fd452f05a91918e7b771e233fb4b9b38cbcc5d55`, Cangjie producer `ce29a393681420d1a53b6b51fa4844141b372e0e1921b9396033735e186ff72c`.

These checked request schemas cannot express recursively nested MIME subparts: they expose only arrays of flat form records. Thus these four specific API producers reach curl cleanup with flat trees as constructed in source. We did not verify whether other raw libcurl APIs, private code, generated bindings or product-specific consumers exist outside the searched trees. Module/product selection, caller permissions/trust, and runtime-built object graphs remain unknown. Treat this as a path-specific non-triggering source result, not product-wide clearance.
