"""Container-side dispatcher for the two fixed C++ reproduction packages."""
import argparse
import json
import os
from pathlib import Path

from .validation_catalog import HARNESS_ROOT, LIFETIME_ID, SHARED_PTR_ID


def main():
    if os.environ.get("OHSCANNER_VALIDATION_CONTAINER") != "1":
        raise RuntimeError("C++ reproduction tests may run only inside the validation container")
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness-id", choices=(LIFETIME_ID, SHARED_PTR_ID), required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    if args.harness_id == LIFETIME_ID:
        from src.ohscanner.poc.cpp_lifetime_uaf import load_manifest, run_poc, write_reports
        harness_dir = HARNESS_ROOT / LIFETIME_ID
        manifest = load_manifest(harness_dir / "manifest.json")
        result = run_poc(manifest_path=harness_dir / "manifest.json",
                         harness=harness_dir / "harness.cpp", output=args.work,
                         compiler="clang++", repeats=3, build_timeout=120, run_timeout=60)
        write_reports(result, args.work / "poc.json", args.work / "poc.md")
        payload = result.to_dict()
        payload["result_file"] = "poc.json"
        payload["report_file"] = "poc.md"
        payload["scope_explanation"] = "自编最小样例的 ASan 组件行为，不绑定扫描案例的产品源码。"
        payload["source_manifest"] = manifest["package_id"]
        payload["report_markdown"] = (args.work / "poc.md").read_text(encoding="utf-8")
    else:
        from src.ohscanner.poc.cpp_shared_ptr_race import load_manifest, run_poc, write_reports
        harness_dir = HARNESS_ROOT / SHARED_PTR_ID
        source_root = args.inputs / "source"
        manifest = load_manifest(harness_dir / "manifest.json")
        result = run_poc(manifest_path=harness_dir / "manifest.json",
                         harness=harness_dir / "harness.cpp", output=args.work,
                         root=source_root, compiler="clang++", repeats=3,
                         readers=4, iterations=20000, build_timeout=120, run_timeout=120)
        write_reports(result, args.work / "poc.json", args.work / "poc.md")
        payload = result.to_dict()
        payload["result_file"] = "poc.json"
        payload["report_file"] = "poc.md"
        payload["scope_explanation"] = "固定留存源码上的 TSAN 组件级并发测试；Git 对象来源和产品入口保持未知。"
        payload["source_manifest"] = manifest["package_id"]
        payload["report_markdown"] = (args.work / "poc.md").read_text(encoding="utf-8")
    args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
