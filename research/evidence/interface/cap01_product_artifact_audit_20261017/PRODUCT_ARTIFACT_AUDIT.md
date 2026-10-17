# CAP-01 official product artifact audit, 2026-10-17

## Conclusion

Official Huawei Cloud OpenHarmony product artifacts were verified, but **no public release artifact contains the exact CAP-01 source blob** `26df3196683976a9f175292fcbf54efef262eaa0`.

- OpenHarmony 5.0.2 uses window commit `04768649...`, tree `d8a04cae...`, and a different `screen_session_manager_stub.cpp` blob. The shipped and unstripped binaries contain no `GetRenderSession` implementation/string for the candidate transaction.
- OpenHarmony 7.0 uses window commit `811b5668...`, tree `fd7b5a78...`; the exact candidate blob also has zero occurrences. Its library references `ScreenSession::GetRenderSession` but not the candidate direct manager/stub method.
- The candidate commit `8b0d8fe1...` is dated 2026-10-08 and postdates the public 5.0/6.0/6.1/7.0 release lines inspected.

Therefore the official-product branch of the plan is complete as a negative exact-blob search. The required fallback is a minimal exact-source product build; that build is not yet complete and no component harness is substituted for it.

## Verified product facts

The 5.0.2 archive is 14,063,472,015 bytes with SHA-256 `6b099129...02f2`. The 7.0 ROM archive is 3,982,172,873 bytes with SHA-256 `649e41c4...eced`. The extracted `manifest_tag.xml` files pin exact component revisions.

The 5.0.2 `ScreenSessionManager` constructor loads SA ID **4607**. Product `service_contexts` maps 4607 to `u:object_r:sa_foundation_dms:s0`. The shipped product contains SAMGR, AccessToken `atm`, RenderService and platform libraries.

## SAMGR / SELinux / API policy

Exact product policy contains:

```text
allow normal_hap_attr       sa_foundation_dms:samgr_class get;
allow system_basic_hap_attr sa_foundation_dms:samgr_class get;
allow system_core_hap_attr  sa_foundation_dms:samgr_class get;
allow foundation            sa_foundation_dms:samgr_class { add get };
```

This means a normal HAP SELinux domain is allowed to **get** the SA 4607 object from the service-manager layer. It is not allowed to register (`add`) it. The result was independently read with `sesearch` from both the 5.0.2 and 7.0 binary policies.

The candidate `TRANS_ID_GET_RENDER_SESSION` handler performs interface-token equality, reads caller-selected `screenId`, calls `GetRenderSession`, and writes the remote object; it does not call `SessionPermission`. The method is not exposed by the public `interfaces/kits` tree. `ScreenSessionManagerClient::GetRenderSessionToken` is an internal client API. Thus:

- binder/SAMGR lookup policy: normal HAP allowed;
- public SDK/API reachability: not demonstrated;
- malicious native caller holding or constructing the internal proxy: plausible but not product-executed;
- exact deployed candidate implementation: absent from public product releases.

## Render-session capability surface

The object is typed as `sptr<IRemoteObject>` in window manager, but graphic_2d source resolves it to `RSIConnectToRenderProcess` and then `RSIClientToRenderConnection`. The latter exposes transaction, node, bitmap/pixelmap, capture and lifecycle operations. See `RENDER_CAPABILITY_ANALYSIS.md`; concrete cross-screen effects still require product runtime.

Confidentiality and integrity are candidate-supported by the concrete pixel/command surface, while availability remains candidate-unknown. The candidate proves capability handoff, not successful cross-screen disclosure, target-state modification, crash or denial of service.

## Runtime attempts

- Product SELinux policy queries were executed and retained as evidence.
- The product `selinux_check_access` wrapper was run under `proot`/`qemu-arm-static`; it returned zero even for impossible type/permission inputs and is therefore inconclusive.
- `samgr` under `qemu-user` exits before readiness because the guest `PR_SET_VMA` call receives an untranslated guest address; `proot` reports SIGSEGV.
- An isolated `qemu-system-aarch64` boot of the official kernel/rootfs did not emit serial output because the RK3568-specific boot path is not represented by QEMU `virt`.

No runtime result is promoted to product reachability or exploitability.

## Required closure

1. Build the exact `8b0d8fe1...` window module and its pinned dependencies with the official toolchain.
2. Put the exact-blob build into a minimal image that also contains SAMGR, AccessToken and RenderService.
3. Run four variants (vulnerable, fixed control, patched, harmless) three times in a local isolated image/emulator.
4. Record caller UID/token, SAMGR lookup, SELinux decision, binder trace and returned remote-object interface.
5. Measure concrete C/I/A effects or retain them as unknown.

Until those steps complete, CAP-01 remains `candidate/unknown`, `validated_vulnerability=0`.
