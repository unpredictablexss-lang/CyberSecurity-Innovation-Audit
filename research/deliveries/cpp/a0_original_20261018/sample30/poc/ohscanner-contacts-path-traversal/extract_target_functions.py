from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = [
    {
        "id": "contacts_batch_insert",
        "file": "dataBusiness/contacts/src/contacts_data_ability.cpp",
        "needle": "int ContactsDataAbility::BatchInsert(const Uri &uri,",
    },
    {
        "id": "batch_insert_one_by_one",
        "file": "dataBusiness/contacts/src/contacts_data_ability.cpp",
        "needle": "int ContactsDataAbility::batchInsertHandleOneByOne(const Uri &uri, std::string isSyncFromCloud,",
    },
    {
        "id": "process_single_insert",
        "file": "dataBusiness/contacts/src/contacts_data_ability.cpp",
        "needle": "int ContactsDataAbility::ProcessSingleInsert(DataShare::DataShareValuesBucket &rawContactValues,",
    },
    {
        "id": "handle_contact_portrait",
        "file": "dataBusiness/contacts/src/contacts_data_ability.cpp",
        "needle": "int ContactsDataAbility::HandleContactPortrait(DataShare::DataShareValuesBucket &value)",
    },
    {
        "id": "save_portrait_file_and_blob",
        "file": "dataBusiness/contacts/src/contacts_data_ability.cpp",
        "needle": "int ContactsDataAbility::SavePortraitFileAndBlob(const std::string &srcFilePath, const std::string &filePath,",
    },
    {
        "id": "build_portrait_value",
        "file": "dataBusiness/contacts/src/contacts_data_ability.cpp",
        "needle": "void ContactsDataAbility::BuildPortraitValue(DataShare::DataShareValuesBucket &value, const std::string &contactId,",
    },
    {
        "id": "get_portrait_value",
        "file": "dataBusiness/contacts/src/contacts_data_ability.cpp",
        "needle": "void ContactsDataAbility::GetPortraitValue(const DataShare::DataShareValuesBucket &dataShareValue,",
    },
    {
        "id": "get_string_value",
        "file": "dataBusiness/contacts/src/contacts_data_ability.cpp",
        "needle": "std::string ContactsDataAbility::GetStringValueFromDataShareValue(",
    },
    {
        "id": "datashare_stub_batch_insert",
        "file": "dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp",
        "needle": "int ContactsDataShareStubImpl::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)",
    },
    {
        "id": "file_utils_get_group_path",
        "file": "ability/common/utils/src/file_utils.cpp",
        "needle": "bool FileUtils::GetGroupPath(std::string &groupPath)",
    },
    {
        "id": "file_utils_delete_file",
        "file": "ability/common/utils/src/file_utils.cpp",
        "needle": "bool FileUtils::DeleteFile(const std::string &filePath)",
    },
]

EXPECTED_FILES = {
    "dataBusiness/contacts/src/contacts_data_ability.cpp": "c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6",
    "dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp": "a913de9c273ef055de9203f83e890067a8594f1028dce6526844228585aa87a4",
    "ability/common/utils/src/file_utils.cpp": "4de09b2a9de7ad538044e1e0b9f2ea84cc8acf9bf6a5cd1b7431c861a59d181f",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def matching_brace(text: str, open_index: int) -> int:
    depth = 0
    state = "code"
    i = open_index
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 1
            elif ch == "/" and nxt == "*":
                state = "block_comment"
                i += 1
            elif ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        elif state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 1
        elif state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if ch == "\\":
                i += 1
            elif ch == quote:
                state = "code"
        i += 1
    raise ValueError("unbalanced braces")


def extract(text: str, needle: str) -> tuple[str, int, int]:
    start = text.find(needle)
    if start < 0:
        raise ValueError(f"needle not found: {needle}")
    open_index = text.find("{", start)
    if open_index < 0:
        raise ValueError(f"opening brace not found: {needle}")
    end = matching_brace(text, open_index)
    snippet = text[start : end + 1]
    line_start = text.count("\n", 0, start) + 1
    line_end = text.count("\n", 0, end) + 1
    return snippet, line_start, line_end


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    files = {}
    for rel, expected in EXPECTED_FILES.items():
        data = (args.source_root / rel).read_bytes()
        actual = sha256_bytes(data)
        if actual != expected:
            raise SystemExit(f"source hash mismatch for {rel}: expected {expected}, got {actual}")
        files[rel] = {
            "sha256": actual,
            "size_bytes": len(data),
        }

    functions = []
    for spec in SPECS:
        source = args.source_root / spec["file"]
        text = source.read_text(encoding="utf-8")
        snippet, line_start, line_end = extract(text, spec["needle"])
        output = args.output_dir / f"{spec['id']}.inc"
        output.write_text(snippet + "\n", encoding="utf-8", newline="\n")
        functions.append({
            **spec,
            "line_start": line_start,
            "line_end": line_end,
            "snippet_sha256": sha256_bytes((snippet + "\n").encode("utf-8")),
            "snippet_bytes": len((snippet + "\n").encode("utf-8")),
            "output": output.name,
        })

    manifest = {
        "schema_version": "source-extraction-v1",
        "source_root": str(args.source_root),
        "files": files,
        "functions": functions,
    }
    manifest_path = args.output_dir / "extraction_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "extracted", "files": len(files), "functions": len(functions)}))


if __name__ == "__main__":
    main()
