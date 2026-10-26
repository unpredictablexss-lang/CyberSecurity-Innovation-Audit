#!/usr/bin/env python3
"""Read-only verification of the C1 product-pin TypedArray source chain."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
GIT_DIR = "/mnt/d/openHarmonyScanner/openharmony/.repo/projects/arkcompiler/ets_runtime.git"
COMMIT = "a65a2853ccae13da167d9aa4720ab8b11ec16656"
TREE = "8781f036a3e7e04d8e0b34970d5f623b42875016"
CHECKOUT = ROOT.parent / "openharmony/arkcompiler/ets_runtime"
OUTPUT = ROOT / "research/deliveries/cpp/C_LINE_C1_SINK_BINDING_20261019.json"
EXPECTED = {
    "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp": ("68fb3b0adc4f9062889a861be51b7be90362e37a", "76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c"),
    "ecmascript/compiler/new_object_stub_builder.cpp": ("991ac5ac034a1a027e3200787ec25c55b3f15b69", "3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0"),
    "ecmascript/js_typed_array.cpp": ("098c2a22cae3152af3a59063dda25e145f03bbd7", "e67c0ce082885efb6fa5894f7a1998a41eb4cddfa2e381c8335497e10e2b9bbe"),
    "ecmascript/stubs/runtime_stubs.cpp": ("14dc06350881b1fa0fdabeeb8465ae9063224d6c", "0c390fb329387ff75943089da0e7eecab4bc1df21da1be4f33db969b2bf79a46"),
    "ecmascript/stubs/runtime_stub_list.h": ("b570a0b2a016fd808e005eb23e16f80896d0c6fd", "fcf0b1daa2660dbbae359ea5a88ee0743d69db994539fc11342e05b394b08e22"),
    "ecmascript/base/typed_array_helper.cpp": ("bcb422fe67f4e670adcca31fffd4da7e2b3b0b21", "3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d"),
    "ecmascript/builtins/builtins_typedarray.cpp": ("0fc27c213e1ea80d93e1e3807eec11baf2634832", "14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c"),
    "ecmascript/builtins/builtins_typedarray.h": ("b291181c949c7038b7030a216f5bdc0e7474a1c2", "651d426c00c1d8bc6503c1d717decf42b28c61c57336e9418ad422604a6a1be7"),
    "ecmascript/builtins/builtins_arraybuffer.cpp": ("2aa22c58803df690a5a2b326451e02297dc5e2f6", "4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9"),
    "ecmascript/builtins/builtins_arraybuffer.h": ("c938b4263bdae62c1418dc8ca159b2ba8bc0a493", "c2a4fb1a18e785d1f105eee52ac71a38386b93a6ac80b685c438edf48e3fe9e6"),
    "ecmascript/object_operator.cpp": ("d885881517adb4a892ec9968cfd3e457e2bc2afd", "05f1eed11c34f0dd178b35515ca7b7fbbe737a5468fdb8abb2727d8e1abfe21b"),
    "ecmascript/global_env.h": ("715a0c316fd7bb52fe382eec85adb450c8ce7628", "c3bbff0a1f911ea620f7bceb5e58ab6899204bed3da0aa38ecb48bf8f029da3f"),
    "ecmascript/compiler/BUILD.gn": ("e6f28ab0562deea4a0ece18851e1ea927b806c1d", "34f23416b2983f5635c00f881b444c4b15975e7ff8d9657b03ae65847ada103a"),
    # Direct declaration, registration macro, inheritance, creator, IR type and
    # TypedArray type sources used to review C1 method applicability.
    "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.h": ("017286724e4cd6df1a369589293efe920660c4c6", "f5b25eed46bfe6e951c6ad8b79ff76bfee8d402868839d21e6d41cd84ef3f8e3"),
    "ecmascript/compiler/builtins/builtins_call_signature_list.h": ("694d77ca7f92656b13650c4b115b3cbeee5917f0", "d54119de6af7ccf12268409af9ec053ebbf44f404956e216394da1499e197958"),
    "ecmascript/compiler/builtins/builtins_call_signature.h": ("1ad9f2cc2203c7c4d64aa3a41c818452425c2491", "9701044182b36129d9bd5b0d24e8cd8dcee81b8a03327e2d397f0d5f208372e9"),
    "ecmascript/compiler/builtins/builtins_stubs.h": ("5edb8446151cb3b21f43bcbaceeb9d777dd89801", "6dfb74b71c999d063a4391ebd5f848769b11df518c7b8fd88cc794a70e92e4a7"),
    "ecmascript/compiler/builtins/builtins_array_stub_builder.h": ("c9b5a66c12c657533047286ec79406a639fb8232", "1804426bca64803a2a7b70c63004eb5236718daa075c67d74c68fd5f21ef151c"),
    "ecmascript/compiler/builtins/builtins_arraybuffer_stub_builder.h": ("89167b4a2160f153a9445c19e3488756bbde8576", "85e68db5ae84bffba1247d8ce186edd7e562c6560a0b82cfe3422e7669d906aa"),
    "ecmascript/compiler/call_stub_builder.h": ("d1fb1b9ef28ff8c928a6e8dfdd9aed67e42ef6aa", "18af6653e22c36dc1fce30d9b7b7eda9d616084add2b1c6d1faa6d89c6c895ae"),
    "ecmascript/compiler/stub_builder.h": ("9e2fbd3ede1da91133dcd936018285e597944515", "a11ca83c0a8bbe16ea4ce9dabb2ab3aca2ee9c680a95433371e79494e2a92cb0"),
    "ecmascript/compiler/stub_builder-inl.h": ("c0521ab7a55cd63850736c2db8a290115965373c", "e3e840771be228a2c5e6c15576ecdf3f06175622b5840525520345f1d22d76be"),
    "ecmascript/compiler/circuit_builder_helper.h": ("d990380aff718b31de4cafa35663cb2d70f10300", "7b3c9dd0934e9edbed1d4774e0bb92ef01ed32fbf05f8138cefcaa4e49ce0f18"),
    "ecmascript/compiler/gate.h": ("e1f47a40708012e5d42995fe82e4be097cc2cd19", "85330dc30f41373d97864afe5289990f14c56198b07cec6c1fac7ce50e8f09f5"),
    "ecmascript/compiler/variable_type.h": ("72008694c6a16f6532b261d0d9d2493273e383ce", "7269b2111d2be7464b38ccf7029786e83a34b4159a16fa1d1759f18c7a5aca55"),
    "ecmascript/compiler/new_object_stub_builder.h": ("ecdf871b20e884e013ce0f26877ef404e4950cb0", "d84a72bb1a252fb9ea2b8ff01e702c3a0c952681e211d8f1a850f1880217778b"),
    "ecmascript/js_dataview.h": ("070c89334ccfd102f02153863176e05295113bfd", "4ad3254492a91ee9f22e61eefa1fd98932fdeea5becdb29b79339306d79da802"),
    "ecmascript/js_hclass.h": ("fca61941b181d1796d485e387054221d6f136337", "36d38fd0d12b05c21069a663418b569063e96912f6758b9611b832a78477d4e3"),
    "ecmascript/js_typed_array.h": ("d59bc3138542afa22bfe2a2f42f5fa756a6dae1a", "a22084f1746bbfe86656a92d4847bebfab3057e667b25bcb0853cc648c29e669"),
    "ecmascript/js_arraybuffer.h": ("a6da193e8a91fe42706aab71ce71d92c00bb8adf", "fe09165a245f519938012ad9deab67635cc0d52953fb26151771504fb23fe863"),
    "ecmascript/base/typed_array_helper-inl.h": ("172fa188b64ed23d0714c4f4cd0ef66bcbb8e1cf", "ecad66a6acb1a19f4eed9b84ce9f86f565348ad0be8c3411643ebace7a8ee559"),
    # Runtime-level GN gates and their imported feature/config declarations.
    "BUILD.gn": ("b3c8effde42ae810e825437b7cfcaabf1a3fdbdf", "8e5f0d4d829578200b75175ea81e8ef2c8370fe4c331ab6a3b255cad95988a89"),
    "js_runtime_config.gni": ("c8d1de004c93829a5236f497b911d268647a8761", "c088d81878bd6b3c38244e8e1ee9ab90252f64029d85e68a6c23163725c3bbb1"),
}


def git(*args: str) -> bytes:
    result = subprocess.run(
        ["wsl.exe", "env", "GIT_NO_LAZY_FETCH=1", "git", "-C", GIT_DIR, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git failed ({result.returncode}) for {args!r}: {detail}")
    return result.stdout


def main() -> int:
    try:
        tree = git("show", "-s", "--format=%T", COMMIT).decode().strip()
        rows = []
        pinned_contents = {}
        for path, (expected_oid, expected_sha) in EXPECTED.items():
            raw = git("show", f"{COMMIT}:{path}")
            pinned_contents[path] = raw.decode("utf-8")
            oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
            resolved = git("rev-parse", f"{COMMIT}:{path}").decode().strip()
            sha = hashlib.sha256(raw).hexdigest()
            checkout_path = CHECKOUT / path
            checkout_sha = hashlib.sha256(checkout_path.read_bytes()).hexdigest() if checkout_path.is_file() else None
            rows.append({
                "path": path,
                "expected_blob": expected_oid,
                "resolved_blob": resolved,
                "recomputed_blob": oid,
                "expected_sha256": expected_sha,
                "sha256": sha,
                "checkout_sha256": checkout_sha,
                "checkout_matches": checkout_sha == expected_sha,
                "bytes": len(raw),
                "matches": resolved == oid == expected_oid and sha == expected_sha,
            })

        def locate(path: str, needle: str, *, after: int = 0) -> dict:
            lines = pinned_contents[path].splitlines()
            for index in range(after, len(lines)):
                if needle in lines[index]:
                    return {"path": path, "line": index + 1, "source_line": lines[index].strip()}
            raise RuntimeError(f"pinned GN evidence not found: {path}:{needle}")

        def capture_block(path: str, start_needle: str, end_needle: str, *, after: int = 0) -> dict:
            lines = pinned_contents[path].splitlines()
            start = next((i for i in range(after, len(lines)) if start_needle in lines[i]), None)
            if start is None:
                raise RuntimeError(f"pinned GN block start not found: {path}:{start_needle}")
            end = next((i for i in range(start, len(lines)) if end_needle in lines[i]), None)
            if end is None:
                raise RuntimeError(f"pinned GN block end not found: {path}:{end_needle}")
            captured = [line.strip() for line in lines[start:end + 1]]
            return {"path": path, "line": start + 1, "source_line": "\n".join(captured),
                    "source_lines": captured}

        compiler_gn = "ecmascript/compiler/BUILD.gn"
        root_gn = "BUILD.gn"
        optimizer_list = locate(compiler_gn, '"builtins/builtins_typedarray_stub_builder.cpp"')
        optimizer_set = locate(compiler_gn, 'ohos_source_set("libark_jsoptimizer_set")')
        optimizer_sources = locate(compiler_gn, "sources = libark_jsoptimizer_sources", after=optimizer_set["line"])
        stub_compiler = locate(compiler_gn, 'ohos_executable("ark_stub_compiler")')
        stub_compiler_dep = locate(compiler_gn, '":libark_jsoptimizer_set"', after=stub_compiler["line"])
        gen_stub_action = locate(compiler_gn, 'action("gen_stub_file")')
        gen_stub_host_dep = locate(compiler_gn, "ark_stub_compiler(${host_toolchain})", after=gen_stub_action["line"])
        stub_an_output = locate(compiler_gn, 'outputs = [ "$stub_file_gen_dir/stub.an" ]', after=gen_stub_action["line"])
        package_group = locate(root_gn, 'group("ark_js_packages")')
        package_runtime_dep = locate(root_gn, '":libark_jsruntime"', after=package_group["line"])
        package_stub_dep = locate(root_gn, '"ecmascript/compiler:stub.an"', after=package_group["line"])
        optimizer_gate = capture_block(
            root_gn,
            'if (is_clang && clang_version != "9.0.3" && current_cpu == "arm64" &&',
            '"ecmascript/compiler:libark_jsoptimizer",',
            after=package_group["line"],
        )
        optimizer_package_dep = locate(root_gn, '"ecmascript/compiler:libark_jsoptimizer"', after=optimizer_gate["line"])
    except (RuntimeError, OSError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    manifest = {
        "schema": "ark-runtime-c1-typedarray-sink-bindings-v3",
        "repository": "openharmony/arkcompiler_ets_runtime",
        "commit": COMMIT,
        "expected_tree": TREE,
        "resolved_tree": tree,
        "tree_matches": tree == TREE,
        "object_store": GIT_DIR,
        "checkout_root": str(CHECKOUT),
        "checkout_matches_pinned_objects": all(row["checkout_matches"] for row in rows),
        "git_lazy_fetch_disabled": True,
        "scope": "exact source identity for sink chain and selected method/macro/type declarations; not full dependency closure, compiler macro expansion, a build, runtime, or security-impact proof",
        "reviewed_contract_sources": {
            "method_registration_and_class_macro": [
                "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.h",
                "ecmascript/compiler/builtins/builtins_call_signature_list.h",
                "ecmascript/compiler/builtins/builtins_call_signature.h"
            ],
            "inheritance_and_builder_contract": [
                "ecmascript/compiler/builtins/builtins_stubs.h",
                "ecmascript/compiler/stub_builder.h",
                "ecmascript/compiler/stub_builder-inl.h"
            ],
            "target_creator_method_dependencies": [
                "ecmascript/compiler/builtins/builtins_array_stub_builder.h",
                "ecmascript/compiler/builtins/builtins_arraybuffer_stub_builder.h",
                "ecmascript/compiler/call_stub_builder.h",
                "ecmascript/compiler/new_object_stub_builder.h",
                "ecmascript/base/typed_array_helper-inl.h"
            ],
            "ir_and_element_type_declarations": [
                "ecmascript/compiler/circuit_builder_helper.h",
                "ecmascript/compiler/gate.h",
                "ecmascript/compiler/variable_type.h",
                "ecmascript/js_dataview.h",
                "ecmascript/js_hclass.h",
                "ecmascript/js_typed_array.h",
                "ecmascript/js_arraybuffer.h"
            ],
            "runtime_build_gate_sources": ["BUILD.gn", "js_runtime_config.gni",
                                           "ecmascript/compiler/BUILD.gn"],
            "interpretation": "These pinned files support source-level declarations and registration review only. No preprocessor/compiler expansion, overload resolution, or full active include closure was captured."
        },
        "static_runtime_build_graph": {
            "observations": [
                {"id": "typedarray_source_in_optimizer_list", **optimizer_list},
                {"id": "optimizer_source_set_declared", **optimizer_set},
                {"id": "optimizer_source_set_consumes_list", **optimizer_sources},
                {"id": "host_stub_compiler_declared", **stub_compiler},
                {"id": "host_stub_compiler_depends_on_optimizer_set", **stub_compiler_dep},
                {"id": "gen_stub_file_action_declared", **gen_stub_action},
                {"id": "gen_stub_file_uses_host_compiler", **gen_stub_host_dep},
                {"id": "gen_stub_file_emits_stub_an", **stub_an_output},
                {"id": "package_group_declared", **package_group},
                {"id": "package_group_depends_on_runtime", **package_runtime_dep},
                {"id": "package_group_depends_on_stub_an", **package_stub_dep},
                {"id": "optimizer_shared_library_arch_gate", **optimizer_gate},
                {"id": "optimizer_shared_library_package_dep", **optimizer_package_dep}
            ],
            "interpretation": "Text-level GN graph only. Conditions are not evaluated; package selection, generated outputs and product runtime use remain unverified."
        },
        "bindings": rows,
        "all_bindings_match": all(row["matches"] for row in rows),
    }
    payload = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    OUTPUT.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    OUTPUT.with_suffix(OUTPUT.suffix + ".sha256").write_text(
        f"{digest}  {OUTPUT.name}\n", encoding="ascii", newline="\n"
    )
    print(f"tree_matches={str(manifest['tree_matches']).lower()}")
    print(f"all_bindings_match={str(manifest['all_bindings_match']).lower()}")
    print(f"checkout_matches_pinned_objects={str(manifest['checkout_matches_pinned_objects']).lower()}")
    print(f"bindings={len(rows)}")
    print(f"manifest={OUTPUT}")
    print(f"sha256={digest}")
    return 0 if (manifest["tree_matches"] and manifest["all_bindings_match"]
                 and manifest["checkout_matches_pinned_objects"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
