import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(r"D:/OpenHarmony807")
HERE = Path(__file__).resolve().parents[2]
D53_JSON = HERE / "research/data_sensitive/D53_PASTEBOARD_PRODUCT_PROFILE_20261021.json"
OUT = HERE / "research/data_sensitive/D81_LOCAL_PRODUCT_BUILD_INVENTORY_20261020.json"
T53_COMMIT = "92844f7becbbd6dbf41584e1ce21a4c885352bb8"
D53_COMMIT = "3f1c9aa72f245d7d7c6312970f2c3bdd11c3b8f2"


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def raw_blob(repo: Path, oid: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), "cat-file", "blob", oid])


def git_file(repo: Path, commit: str, rel: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{rel}"])


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    d53 = json.loads(D53_JSON.read_text(encoding="utf-8"))
    assert sha(git_file(HERE, D53_COMMIT, "research/data_sensitive/D53_PASTEBOARD_PRODUCT_PROFILE_20261021.json")) == sha(D53_JSON.read_bytes())
    repo_paths = {name: Path(value["path"]) for name, value in d53["repos"].items()}
    checked_files = 0
    for name, entry in d53["files"].items():
        repo_name, rel = name.split("/", 1)
        repo = repo_paths[repo_name]
        pinned = d53["repos"][repo_name]["head"]
        actual_oid = git(repo, "rev-parse", f"{pinned}:{rel}")
        data = raw_blob(repo, actual_oid)
        assert actual_oid == entry["blob"], (name, actual_oid, entry["blob"])
        assert len(data) == entry["bytes"], (name, len(data), entry["bytes"])
        assert sha(data) == entry["sha256"], (name, sha(data), entry["sha256"])
        checked_files += 1

    repo_inventory = {}
    for name, expected in d53["repos"].items():
        repo = repo_paths[name]
        actual_head = git(repo, "rev-parse", "HEAD")
        actual_tree = git(repo, "rev-parse", "HEAD^{tree}")
        assert actual_head == expected["head"], (name, actual_head, expected["head"])
        assert actual_tree == expected["tree"], (name, actual_tree, expected["tree"])
        repo_inventory[name] = {
            "head": actual_head,
            "tree": actual_tree,
            "branch": expected["branch"],
            "worktree_clean_at_d53_freeze": expected["worktree_clean"],
            "role": {
                "pasteboard": "current component source and product config",
                "productdefine_common": "shared product inheritance templates",
                "vendor_hihope": "HiHope product config definitions",
                "build": "component and compilation allowlists",
            }[name],
        }

    def artifact_ref(repo_key: str, path: str) -> dict:
        key = f"{repo_key}/{path}"
        item = d53["files"][key]
        return {"path": path, "blob": item["blob"], "sha256": item["sha256"], "bytes": item["bytes"]}

    selected_names = {
        "2in1_core_system", "dayu210", "default_core_system", "ipcamera_core_system",
        "nearlink_dk_3863", "nearlink_dk_3863_xts", "nearlink_dk_3863_xts_minimal",
        "neptune_iotlink_demo", "rk3568", "rk3568_mini_system", "tablet_core_system", "tv", "wearable",
    }
    products = []
    for product in d53["hihope_products"]:
        if product["name"] not in selected_names:
            continue
        inherited_profiles = []
        for profile in product["inherited_profile_evidence"]:
            profile_oid = git(
                repo_paths["productdefine_common"],
                "rev-parse",
                f"{d53['repos']['productdefine_common']['head']}:{profile['profile']}",
            )
            profile_bytes = raw_blob(repo_paths["productdefine_common"], profile_oid)
            assert profile_oid == profile["blob"], (product["name"], profile_oid, profile["blob"])
            inherited_profiles.append({
                "path": profile["profile"],
                "blob": profile_oid,
                "includes_pasteboard": profile["direct_pasteboard_component"],
                "sha256": sha(profile_bytes),
                "bytes": len(profile_bytes),
            })
        products.append({
            "name": product["name"],
            "product_type": product["product_type"],
            "board": product["board"],
            "config": artifact_ref("vendor_hihope", product["config"]),
            "inherit": product["inherit"],
            "inherited_profiles": inherited_profiles,
            "product_definition_includes_pasteboard": product["direct_includes_pasteboard"],
            "status": "source_configuration_only",
        })

    root_entries = sorted(p.name for p in ROOT.iterdir())
    build_output_names = {"out", "output", "outputs", "images", "image", "device", "flash"}
    root_build_output_candidates = sorted(
        p.name for p in ROOT.iterdir() if p.is_dir() and p.name.lower() in build_output_names
    )
    d53_file_hash = sha(D53_JSON.read_bytes())
    t53_repo = HERE.parent / "t51-pasteboard-independent-20261020"
    t53_json = git_file(t53_repo, T53_COMMIT, "research/evidence/cpp/T53_PASTEBOARD_PRODUCT_PROFILE_20261021.json")
    t53_md = git_file(t53_repo, T53_COMMIT, "research/evidence/cpp/T53_PASTEBOARD_PRODUCT_PROFILE_20261021.md")
    historical_repo = ROOT / "t56-miscservices-official.git"
    historical_commit = "dd22c7cb5e5f207a6c38c50f45b7369ee8575840"
    historical_tree = git(historical_repo, "rev-parse", f"{historical_commit}^{{tree}}")
    historical_blob = git(historical_repo, "rev-parse", f"{historical_commit}:services/zidl/src/pasteboard_service_stub.cpp")
    historical_bytes = raw_blob(historical_repo, historical_blob)
    assert historical_tree == "e374a0d61c9ec664ddd29fc17002797828c480ee"
    assert historical_blob == "3dbc3150ada27a765938f06ea6e8cfd0a2d7146b"
    assert len(historical_bytes) == 6288
    assert sha(historical_bytes) == "d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868"
    report_path = ROOT / "scan-results/build/report.md"
    build_report = {
        "path": str(report_path),
        "sha256": sha(report_path.read_bytes()),
        "classification": "research_scan_admission_not_product_build_evidence",
    }
    inventory = {
        "schema": "ohscanner.d81.local_product_build_inventory/v1",
        "created_local_date": "2026-10-20",
        "decision": "product_definition_found_concrete_build_unknown",
        "scope": {
            "D53_T53_source_config_evidence": True,
            "OpenHarmony807_root": str(ROOT),
            "top_level_entries_observed": root_entries,
            "build_output_directory_at_root": bool(root_build_output_candidates),
            "build_output_directory_candidates": root_build_output_candidates,
            "searched_for_concrete_artifacts": [
                "product image or OTA package",
                "product build output manifest",
                "build fingerprint / build.prop",
                "installed-device record",
                "product args.gn, build.ninja, compile database or successful build log",
            ],
            "search_boundary": "OpenHarmony807 top-level structure plus frozen D53/T53 source/config evidence; no claim about arbitrary devices or external stores",
        },
        "frozen_evidence": {
            "D53_developer_commit": D53_COMMIT,
            "D53_developer_tree": git(HERE, "rev-parse", f"{D53_COMMIT}^{{tree}}"),
            "D53_json_path": "research/data_sensitive/D53_PASTEBOARD_PRODUCT_PROFILE_20261021.json",
            "D53_json_sha256_in_worktree": d53_file_hash,
            "D53_raw_git_file_sha256": sha(git_file(HERE, D53_COMMIT, "research/data_sensitive/D53_PASTEBOARD_PRODUCT_PROFILE_20261021.json")),
            "T53_acceptance_commit": T53_COMMIT,
            "T53_acceptance_tree": git(t53_repo, "rev-parse", f"{T53_COMMIT}^{{tree}}"),
            "T53_json_sha256": sha(t53_json),
            "T53_markdown_sha256": sha(t53_md),
            "D53_files_independently_recomputed": checked_files,
            "D53_files_mismatch_count": 0,
        },
        "source_repositories": repo_inventory,
        "HiHope_product_definitions": products,
        "build_metadata": {
            "pasteboard_related_allowlist_objects": [
                artifact_ref("build", "indep_component_whitelist.json"),
                artifact_ref("build", "component_compilation_whitelist.json"),
            ],
            "meaning": "repository allowlist/target metadata; does not prove a product target was built",
        },
        "historical_D52_candidate": {
            "repository": "openharmony/miscservices_pasteboard",
            "commit": historical_commit,
            "tree": historical_tree,
            "source_file": "services/zidl/src/pasteboard_service_stub.cpp",
            "source_blob": historical_blob,
            "source_sha256": sha(historical_bytes),
            "relation_to_current_repo": "migration_or_ancestry_not_verified",
        },
        "concrete_product_evidence": {
            "fingerprint": None,
            "product_build_id": None,
            "locked_product_manifest": None,
            "compiled_image_or_ota": None,
            "product_output_manifest": None,
            "successful_product_build_log": None,
            "installed_device_record": None,
            "status": "not_found_in_scoped_local_evidence",
            "research_scan_report": build_report,
        },
        "strongest_supported_conclusion": "Several pinned HiHope product definitions/configuration inheritance paths and build allowlist objects contain or recognize the current Pasteboard component; none identifies one concrete executed or installed product build. D52 target product applicability and historical-source inclusion remain unknown.",
        "source_only_target_proposal": {
            "label": "SOURCE_ONLY; not a device, release, or built product",
            "product_definition": "vendor_hihope@b40eabbe69943126c65df1f9ff28057f56e93e46:rk3568/config.json",
            "shared_template": "productdefine_common@c9317af4074bf0e445fe3fc3979e53c470687153:inherit/rich.json",
            "component_source_for_config_study": "distributeddatamgr_pasteboard@e73747b227104e6743e957ce31040edf58507221",
            "purpose": "reproducible source/config study only; cannot establish D52 historical code presence, build inclusion, or product vulnerability",
            "configuration_tuple_is_unified_manifest": False,
        },
        "reproduction": {
            "command": "python scripts/research/build_d81_product_inventory.py",
            "verifies": "four repo HEAD/tree pins and all 31 D53 raw Git blob OID/size/SHA-256 entries before writing this inventory",
        },
    }
    OUT.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT}; verified {checked_files} D53 raw Git objects")


if __name__ == "__main__":
    main()
