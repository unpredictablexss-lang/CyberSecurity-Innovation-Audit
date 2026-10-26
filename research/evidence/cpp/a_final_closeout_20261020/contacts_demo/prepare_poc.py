"""Prepare an isolated Contacts path traversal harness from a pinned Git object."""
from __future__ import annotations

import hashlib
import argparse
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = Path(__file__).resolve().parents[5]
POC_SRC = REPO / "research/deliveries/cpp/a0_original_20261018/sample30/poc/ohscanner-contacts-path-traversal"
COMMIT = "b02aadfc2d801ee30573fcb2d13490298e146fea"
SOURCE_PATH = "dataBusiness/contacts/src/contacts_data_ability.cpp"
EXPECTED_SOURCE_SHA256 = "70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383"
EXPECTED_SOURCE_BLOB = "32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6"
EXPECTED_SOURCE_TREE = "ef183625ccbc842f47b076eb75e68b665d7c21c6"
ROOT = "/tmp/ohscanner_contacts_demo_20261021/data/storage"


def function_body(text: str, needle: str) -> tuple[str, int, int]:
    start = text.index(needle)
    brace = text.index("{", start)
    depth = 0
    state = "code"
    i = brace
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line"; i += 1
            elif ch == "/" and nxt == "*":
                state = "block"; i += 1
            elif ch == '"': state = "string"
            elif ch == "'": state = "char"
            elif ch == "{": depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    return text[start:end], text.count("\n", 0, start) + 1, text.count("\n", 0, i) + 1
        elif state == "line":
            if ch == "\n": state = "code"
        elif state == "block":
            if ch == "*" and nxt == "/": state = "code"; i += 1
        else:
            quote = '"' if state == "string" else "'"
            if ch == "\\": i += 1
            elif ch == quote: state = "code"
        i += 1
    raise ValueError("unclosed function body")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-repo", required=True, type=Path, help="local contacts_data Git clone containing the pinned object")
    args = parser.parse_args()
    tree = subprocess.run(
        ["git", "-C", str(args.git_repo), "rev-parse", f"{COMMIT}^{{tree}}"],
        check=True, stdout=subprocess.PIPE, text=True,
    ).stdout.strip()
    blob = subprocess.run(
        ["git", "-C", str(args.git_repo), "rev-parse", f"{COMMIT}:{SOURCE_PATH}"],
        check=True, stdout=subprocess.PIPE, text=True,
    ).stdout.strip()
    if tree != EXPECTED_SOURCE_TREE or blob != EXPECTED_SOURCE_BLOB:
        raise SystemExit(f"pinned Git object mismatch: tree={tree}, blob={blob}")
    raw = subprocess.run(
        ["git", "-C", str(args.git_repo), "show", f"{COMMIT}:{SOURCE_PATH}"],
        check=True, stdout=subprocess.PIPE,
    ).stdout
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_SOURCE_SHA256:
        raise SystemExit(f"pinned source hash mismatch: {digest}")
    src = HERE / "source"
    gen = src / "generated"
    gen.mkdir(parents=True, exist_ok=True)
    for name in ("target_adapter.cpp", "patched_target_adapter.cpp", "target_adapter_common.hpp"):
        data = (POC_SRC / name).read_text(encoding="utf-8")
        data = data.replace("/data/storage", ROOT)
        data = data.replace(
            "    auto extension = std::make_shared<AbilityRuntime::ContactsDataAbility>();",
            "    bool victimBefore = exists(victim);\n"
            "    auto extension = std::make_shared<AbilityRuntime::ContactsDataAbility>();",
        )
        data = data.replace("    bool victimBefore = true;", "")
        data = data.replace("    bool victimBefore = exists(victim);\n    bool victimAfter", "    bool victimAfter")
        (src / name).write_text(data, encoding="utf-8", newline="\n")
    for file in (POC_SRC / "generated").glob("*.inc"):
        if file.name != "handle_contact_portrait.inc":
            (gen / file.name).write_bytes(file.read_bytes())
    fn, first, last = function_body(
        raw.decode("utf-8"),
        "int ContactsDataAbility::HandleContactPortrait(DataShare::DataShareValuesBucket &value)",
    )
    (gen / "handle_contact_portrait.inc").write_text(fn + "\n", encoding="utf-8", newline="\n")
    manifest = {
        "commit": COMMIT,
        "source_path": SOURCE_PATH,
        "source_sha256": digest,
        "source_blob_oid": blob,
        "function": "ContactsDataAbility::HandleContactPortrait",
        "source_line_start": first,
        "source_line_end": last,
        "extracted_function_sha256": hashlib.sha256((fn + "\n").encode()).hexdigest(),
        "poc_only_fixed_guard": "Reject slash/backslash and dot/dot-dot components for PortraitFileName, contactId and rawContactId before path construction.",
        "filesystem_root": ROOT,
        "limitations": [
            "Harness compiles the pinned vulnerable function with lightweight local dependency stubs; it is not an OpenHarmony product build.",
            "Fixed behavior is a PoC-only guard comparison because no trusted upstream fixed Contacts commit was found.",
            "DataShare IPC caller and product permission boundary are not exercised; applicability and product impact remain unknown.",
        ],
    }
    (HERE / "source_binding.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "prepared", "tree": tree, "blob": blob, "source_sha256": digest, "line_start": first, "line_end": last}))


if __name__ == "__main__":
    main()
