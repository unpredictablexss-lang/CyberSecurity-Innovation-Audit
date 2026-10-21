"""Pinned source + arithmetic replay for Ark Runtime TypedArray.set candidate.

This validates exact Git objects and parser coverage, then runs a bounded
32/64-bit arithmetic model of the reviewed source statements. It does not run
Ark Runtime or claim a product result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from src.parser.ast import parse_source


COMMIT = "d1a58d59166777e16574ceed64c15f0b2f44a76c"
TREE = "2cd854aa7d9f987de89d31a6a512e735779e75b6"
FILES = {
    "ecmascript/builtins/builtins_typedarray.cpp": ("a98d6c5f38a4a8fc8a0f1615d17bad166cbf7696", "8bd0fe16b7dc4ba8283fb240183998d47f2f9784bb243dcf3780a1a8c869bea1", "complete"),
    "ecmascript/builtins/builtins_typedarray.h": ("317918d0d570227dea9a09495906e3bdbe10bb8f", "628074bf5770b8fa4a5bfae6dd0aced7be07d241bede9b69d1393fd42fd784ef", "partial"),
    "ecmascript/builtins/builtins_arraybuffer.cpp": ("577475549ff11ccf8ca446a14727db55549b385d", "002c842843edb973546e3e5205d4bf0bed0da2dabb884f3138d789991eec599a", "complete"),
    "ecmascript/base/typed_array_helper.cpp": ("715584f3724382d589bfc070e9375f44ad0c10e7", "472485421cacf57a2eb75228a432eea6568ee7ae3b3682a9f0d5be6b3d0ef9e7", "complete"),
    "ecmascript/base/typed_array_helper.h": ("fe6fa766f8fbe5e694f8b64434a7cd99f6ffe36d", "68bff535d1ec17e1060d8ed3d27af9af4a93153f4b4214321a458621da4a1bc4", "partial"),
    "ecmascript/js_tagged_value.cpp": ("135f78c665afb23904fec2978444a781758354c7", "82eb03a9c0a48249be58f449c2f9fec1346209de86410c89b846f78cfdedb66b", "complete"),
    "ecmascript/base/number_helper.cpp": ("3caeaa1c0f63791ea7e362ef997f245c5a010ae4", "71d6fd6f0af4d3896daedf4b745a950ce12a7ce8773dddd1b3e3c11fd1e71ec8", "partial"),
}


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def blob_oid(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def model_witness(offset: int, src_len: int, target_length: int,
                  target_byte_offset: int, element_size: int = 1,
                  fixed: bool = False) -> dict:
    mask64, mask32 = (1 << 64) - 1, (1 << 32) - 1
    # Guard behavior modeled from the reviewed source and proposed remediation.
    if fixed:
        accepted = not (offset > target_length or src_len > target_length - offset)
    else:
        accepted = ((offset + src_len) & mask64) <= target_length
    first = (offset * element_size + target_byte_offset) & mask32
    end = (first + element_size * src_len) & mask32
    return {"accepted": accepted, "first_backing_index": first,
            "end_backing_index_exclusive": end,
            "write_count_mod32": (end - first) & mask32}


def replay(repo: Path) -> dict:
    actual_commit = git(repo, "rev-parse", "HEAD")
    actual_tree = git(repo, "rev-parse", "HEAD^{tree}")
    if (actual_commit, actual_tree) != (COMMIT, TREE):
        raise SystemExit(f"source pin mismatch: {actual_commit} {actual_tree}")
    evidence = []
    sources = {}
    for rel, (expected_blob, expected_sha, expected_status) in FILES.items():
        raw = (repo / rel).read_bytes()
        text = raw.decode("utf-8")
        parsed = parse_source(text, "cpp")
        got_blob, got_sha = blob_oid(raw), hashlib.sha256(raw).hexdigest()
        if (got_blob, got_sha, parsed.parse_status) != (expected_blob, expected_sha, expected_status):
            raise SystemExit(f"source evidence mismatch: {rel}")
        sources[rel] = text
        evidence.append({"path": rel, "blob": got_blob, "sha256": got_sha,
                         "bytes": len(raw), "ast": parsed.parse_status,
                         "ast_issue_count": len(parsed.parse_issues)})

    target = sources["ecmascript/builtins/builtins_typedarray.cpp"]
    target_lines = target.splitlines()
    method = "\n".join(target_lines[1145:1392])
    required = (
        "if (srcLen + targetOffset > targetLength)",
        "uint32_t targetByteIndex = static_cast<uint32_t>(targetOffset * targetElementSize + targetByteOffset)",
        "uint32_t limit = targetByteIndex + targetElementSize * srcLen",
        "BuiltinsArrayBuffer::SetValueInBuffer",
    )
    if not all(token in method for token in required):
        raise SystemExit("reviewed Set path shape changed")
    if "srcLen > targetLength - targetOffset" in method:
        raise SystemExit("overflow-safe guard present; candidate was not reproduced")
    # Verify helper source contains the named conversion and backing write path.
    if "JSTaggedValue::ToInteger" not in method:
        raise SystemExit("offset conversion helper call missing")
    if "ToInteger" not in sources["ecmascript/js_tagged_value.cpp"]:
        raise SystemExit("ToInteger implementation dependency missing")
    buffer = sources["ecmascript/builtins/builtins_arraybuffer.cpp"]
    if "SetValueInBuffer" not in buffer or "GetDataPointFromBuffer" not in buffer:
        raise SystemExit("buffer sink/base helper dependency missing")

    offset = (1 << 64) - 2048
    # Binary64 exact value check for the public Number witness used by prior review.
    number_offset = float(offset)
    if int(number_offset) != offset:
        raise SystemExit("witness is not exactly representable as binary64")
    src_len, target_len, view_offset, backing_len = 4096, 4096, 4096, 8192
    old = model_witness(offset, src_len, target_len, view_offset)
    fixed = model_witness(offset, src_len, target_len, view_offset, fixed=True)
    controls = {
        "offset_zero_fits": model_witness(0, 4, 4, 0),
        "ordinary_one_past_rejected": model_witness(1, 4, 4, 0),
        "small_offset_too_large_rejected": model_witness(4097, 1, 4096, 4096),
    }
    if not old["accepted"] or (old["first_backing_index"], old["end_backing_index_exclusive"]) != (2048, 6144):
        raise SystemExit("candidate arithmetic did not reproduce expected cross-view interval")
    if fixed["accepted"]:
        raise SystemExit("subtraction guard control did not reject witness")
    if old["end_backing_index_exclusive"] > backing_len:
        raise SystemExit("witness exceeds backing allocation; review assumptions")
    return {
        "status": "candidate_source_replay_passed",
        "source": {"repository": "openharmony/arkcompiler_ets_runtime", "commit": actual_commit,
                   "tree": actual_tree, "files": evidence},
        "coverage": {"complete_translation_units": [e["path"] for e in evidence if e["ast"] == "complete"],
                     "partial_translation_units": [e["path"] for e in evidence if e["ast"] == "partial"],
                     "set_method_lines": [1146, 1392], "creator_dependency": "not_applicable_to_builtin_Set_entry"},
        "candidate": {"classification": "candidate", "offset_number": repr(number_offset),
                      "offset_integer": str(offset), "source_length": src_len,
                      "target_view": {"byte_offset": view_offset, "byte_length": target_len},
                      "backing_length": backing_len, "old_guard_model": old,
                      "fixed_guard_control": fixed, "cross_view_prefix_bytes": 2048,
                      "backing_store_oob": False, "runtime_execution": "not_run",
                      "product_impact": "unknown"},
        "controls": controls,
        "limitations": ["arithmetic model only; does not execute Ark Runtime", "no product/build profile bound",
                        "TypedArray declaration and Number helper translation units parse partial"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = replay(args.source_repo.resolve())
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(payload, encoding="utf-8")
    print(payload, end="")
