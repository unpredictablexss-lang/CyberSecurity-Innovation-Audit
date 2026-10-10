# Harness: AUTH-01 descriptor bypass (cve-2023-0036)

Proof-of-concept harness for the missing interface-descriptor check in
`PlatformCallbackStub::OnRemoteRequest` (`openharmony/inputmethod_imf`, PR !228).
How to run it and what it measured: `docs/testing/ipc_poc_auth01_descriptor_bypass.md`.

## What is real and what is stubbed

Compiled **unchanged**, at the pinned commits recorded in `manifest.json`
(digests verified before every build, see `src/ohscanner/poc/sources.py`):

- `services/src/platform_callback_stub.cpp` — the target, vulnerable and fixed revisions
- `services/include/{platform_callback_stub,i_platform_callback,message_handler,message,global}.h`
- `commonlibrary_c_utils` `base/src/{parcel,refbase,string_ex,unicode_ex}.cpp` — the **real**
  `Parcel`. Using the real one is what makes an observation attributable to the
  component instead of to a hand-written shim.

Supplied by this harness:

| File | Why |
|---|---|
| `harness.cpp` | writes the request, calls `OnRemoteRequest`, prints the observable |
| `stubs.cpp` | definitions of `Message` and `MessageHandler`; `SendMessage` records instead of dispatching |
| `observations.h` | the recording itself |
| `poc_compat.h` | see "Compatibility shim" below |
| `stub/hilog/log.h` | hilog leaves, no-ops |
| `stub/ipc_types.h` | `FIRST_CALL_TRANSACTION` and `ErrCode` |
| `stub/iremote_broker.h` | `IRemoteBroker`; the `DECLARE_INTERFACE_DESCRIPTOR` macro is copied verbatim because it is what supplies `GetDescriptor()` |
| `stub/iremote_stub.h` | `IRemoteStub<T>` with a default `OnRemoteRequest`; the exercised path goes through the component's own override |
| `stub/ipc_object_stub.h` | declares no `GetDescriptor()`, so the only one in scope is the interface's |
| `stub/message_parcel.h` | `MessageParcel` shim over the real `Parcel`, adding `WriteInterfaceToken`/`ReadInterfaceToken` (forwarded to `WriteString16`/`ReadString16`) |
| `stub/message_option.h` | `MessageOption`, forwarded only |
| `stub/securec.h` | `memcpy_s`/`strcpy_s` for the c_utils sources; same shim as the project's existing c_utils recipe |

## Compatibility shim

`poc_compat.h` is force-included with `-include`. The historical header set at
the vulnerable commit declares `ErrorCode` as a namespace holding an unscoped
enum, while the component writes `return NO_ERROR;` unqualified; no using
directive exists in those headers, so the translation unit does not compile in
isolation. The shim supplies exactly that using directive. It does not touch the
component source and does not change behaviour: the symbol it makes visible is
the one the code already names.

## Reachability, and what it does not show

`manifest.json` carries a `reachability` block: the pinned source relations that
establish how the target is reached, each with what it does and does not
establish. Every relation is checked twice at run time — the file digest against
the pinned commit, and the quoted line against the recorded line number — so a
moved file or a stale quote fails the run instead of quietly describing different
code.

The recorded chain is: the service constructs the stub (`platform.cpp:25`), passes
it to `IPlatformApi::registerCallback` (`platform.cpp:26`), which is a pure virtual
on an `IRemoteBroker` interface (`i_platform_api.h:48`), and the proxy marshals the
object with `WriteRemoteObject` (`platform_api_proxy.cpp:47`), so a peer holding
the handle can send transactions to it.

What is **not** established: that an unprivileged or unrelated process can obtain
that handle, what identity the peer has, or whether the peer forwards the handle
onward. The status stays `partial`, and `validated_vulnerability` stays 0.

## Provenance and licence

`stub/iremote_broker.h` reproduces the `DECLARE_INTERFACE_DESCRIPTOR` macro from
the OpenHarmony `ipc_core` public header (Apache-2.0, Copyright (C) 2021 Huawei
Device Co., Ltd.). The referenced component sources are **not** committed here:
the manifest pins them by commit and SHA-256 and they are read from a local git
object store at run time.
