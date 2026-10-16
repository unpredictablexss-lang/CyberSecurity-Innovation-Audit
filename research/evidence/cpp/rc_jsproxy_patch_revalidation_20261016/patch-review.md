# RC-JSPROXY minimal patch review

## Scope

- Candidate remains `candidate/unknown`; this patch does not promote it to confirmed/reportable.
- Target: `openharmony/distributeddatamgr_kv_store` at the manifest-bound commit/tree.
- File: `frameworks/common/js_proxy.h`.
- Patch SHA-256: `3b04fd4e5575e224df35f77be487f3cd90d0a40501b1ff65f5d01886037124c9`.

## Root cause and why the patch removes it

The real source path copies and assigns `std::shared_ptr<T> instance_` from different threads: a NAPI execute path can replace/clear the owner while a synchronous result-set path copies it. The owner operations are not protected by a repository-local mutex or atomic API, so the read and write may overlap. That is a `CWE-362` synchronization defect candidate. The minimal patch routes both owner operations through C++17 `std::atomic_load` / `std::atomic_store` free functions specialized for `std::shared_ptr`, making each owner access atomic instead of merely narrowing the timing window.

## Patch

```diff
--- a/frameworks/common/js_proxy.h
+++ b/frameworks/common/js_proxy.h
@@ -16,6 +16,7 @@
 #ifndef OHOS_DISTRIBUTED_DATA_FRAMEWORKS_COMMON_JS_PROXY_H
 #define OHOS_DISTRIBUTED_DATA_FRAMEWORKS_COMMON_JS_PROXY_H
 #include <memory>
+#include <atomic>
 namespace OHOS::JSProxy {
 template<typename T>
 class JSCreator {
@@ -34,12 +35,12 @@
 public:
     void SetInstance(std::shared_ptr<T> instance)
     {
-        instance_ = std::move(instance);
+        std::atomic_store(&instance_, std::move(instance));
     }
 
     std::shared_ptr<T> GetInstance() const
     {
-        return instance_;
+        return std::atomic_load(&instance_);
     }
 
 protected:
```

- Vulnerable source SHA-256: `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`.
- Independent fixed-control source SHA-256: `9044ccaac42cefdd2c153c01b07c0893634aa0aee8ad54093e1065740329a902`.
- Patched source SHA-256: `4d57f286602e15af636c40158e8cdabc6f617fda89d8276128c674b4ab633b6f`.

## Functional impact

The public `SetInstance` / `GetInstance` signatures and ownership-return semantics are unchanged. The controlled `single` workload still creates, returns, touches and clears the owner on all variants. This is component-Harness functional evidence only; product API behavior and performance were not built or measured.

## Narrow-scope boundary

The patch only synchronizes `JSProxy::instance_` owner access. It does not repair or prove the underlying `KvStoreResultSet` close/getEntry protocol, NAPI queue lifetime, product permission enforcement, package resolution or cross-module behavior. It is a proposed local patch, not an upstream fix or a complete product remediation.

## Revalidation stability

- `fixed_control_mutex` / `close_get_entry`: `clean, clean, clean` (3/3 expected within this run).
- `fixed_control_mutex` / `race`: `clean, clean, clean` (3/3 expected within this run).
- `patched_atomic_minimal` / `close_get_entry`: `clean, clean, clean` (3/3 expected within this run).
- `patched_atomic_minimal` / `race`: `clean, clean, clean` (3/3 expected within this run).
- `vulnerable` / `close_get_entry`: `sanitizer_triggered, sanitizer_triggered, sanitizer_triggered` (3/3 expected within this run).
- `vulnerable` / `race`: `sanitizer_triggered, sanitizer_triggered, sanitizer_triggered` (3/3 expected within this run).

The replay is stable at three repetitions per mode, but three repetitions do not establish a statistical failure rate or product-level exploitability. TSan proves the controlled owner race; it does not prove UAF, corruption, disclosure, privilege escalation or availability impact in OpenHarmony.

