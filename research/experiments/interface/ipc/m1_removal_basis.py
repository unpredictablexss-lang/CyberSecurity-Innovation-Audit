"""The basis for every candidate M1 removed, taken from the pinned source.

A file can hold several stub classes, each with its own entry and its own guard, so
the guard that counts is the one inside the definition that reports the candidate.
For each removal this records:

  * the candidate's own symbol and the definition it belongs to (checked against
    that symbol, so a citation cannot silently come from a neighbouring class),
  * the `ReadInterfaceToken` read and the `GetDescriptor()` comparison inside that
    definition, with the interface the comparison names,
  * whether the mismatch branch leaves the transaction,
  * the class's own base clause, with the interface it claims to implement,
  * whether the two identities agree.

Every record carries the file checksum the candidate was bound to, verified
against the bytes on disk.
"""
import hashlib
import json
import pathlib
import re
import sys

HEADER = re.compile(r"^\s*[\w:<>,\s&*~]+::\w+\s*\(")
CLASS = re.compile(r"\bclass\s+(\w+)\s*:\s*([^{]+)\{")


def definitions(lines):
    """(qualified name, first body line, last body line) for each definition."""
    found = []
    for index, text in enumerate(lines):
        if not HEADER.match(text):
            continue
        name = re.search(r"([\w~]+::\w+)\s*\(", text)
        if not name:
            continue
        body = None
        for scan in range(index, min(index + 12, len(lines))):
            if "{" in lines[scan]:
                body = scan
                break
        if body is None:
            continue
        depth, end = 0, len(lines) - 1
        for scan in range(body, len(lines)):
            for token in re.sub(r"[^{}]", "", lines[scan]):
                depth += 1 if token == "{" else -1
            if depth == 0:
                end = scan
                break
        found.append((name.group(1), body + 1, end + 1))
    return found


def owner_of(symbol):
    """`A::B::C::Method` -> `C`, the class the candidate's symbol belongs to."""
    parts = symbol.split("::")
    return parts[-2] if len(parts) >= 2 else symbol


def main():
    baseline_dir = pathlib.Path(sys.argv[1])
    delta = json.loads(pathlib.Path(sys.argv[2]).read_text())
    cache = {}
    records = []
    for component in delta:
        if not component["removed_detail"]:
            continue
        manifest = json.loads(
            (baseline_dir / (component["component"] + ".manifest.json")).read_text())
        repo = pathlib.Path(manifest["source_repo_path"])
        for item in component["removed_detail"]:
            path = repo / item["file"]
            raw = path.read_bytes()
            lines = raw.decode("utf-8", "replace").splitlines()
            owner = owner_of(item["baseline_symbol"])
            enclosing = [d for d in definitions(lines) if d[1] <= item["line"] <= d[2]]
            entry = enclosing[0] if enclosing else None
            # the definition must be the one the candidate's symbol names
            named = [d for d in enclosing if d[0].rsplit("::", 1)[0].endswith(owner)]
            # the guard that removed this candidate sits in the entry the candidate
            # was reported under -- not necessarily in the candidate's own function
            entry_symbol = (re.search(r"Entry=([\w:]+)", item["baseline_message"])
                            or [None, ""])[1]
            entry_def = [d for d in definitions(lines) if d[0] == entry_symbol]
            guard, guard_container = None, None
            if entry_def:
                guard_container = entry_def[0]
                for index in range(guard_container[1] - 1, guard_container[2]):
                    if "GetDescriptor" in lines[index]:
                        guard = index
                        break
            # how the entry reaches the candidate: the call to its own function
            reached_at = None
            if guard_container and item["line"] > guard_container[2]:
                handler = item["baseline_symbol"].rsplit("::", 1)[-1]
                for index in range(guard_container[1] - 1, guard_container[2]):
                    if handler + "(" in lines[index].replace(" ", ""):
                        reached_at = index + 1
                        break
            compared = re.search(r"([\w:]+)::GetDescriptor", lines[guard]) if guard else None
            statement = ""
            if guard is not None:
                statement = " ".join(lines[max(0, guard - 2):guard]).strip()
            # identity: the class's own base clause, wherever the scope states it
            key = (str(repo), owner)
            if key not in cache:
                cache[key] = []
                for candidate in sorted(repo.rglob("*.h")) + sorted(repo.rglob("*.cpp")):
                    try:
                        text = candidate.read_text(errors="replace")
                    except OSError:
                        continue
                    match = CLASS.search(text)
                    for match in CLASS.finditer(text):
                        if match.group(1) == owner:
                            line = text[:match.start()].count("\n") + 1
                            cache[key].append({
                                "file": str(candidate.relative_to(repo)), "line": line,
                                "bases": match.group(2).strip()})
            declarations = cache[key]
            stated = []
            for declaration in declarations:
                for base in declaration["bases"].split(","):
                    inner = re.search(r"IRemoteStub\s*<\s*([\w:]+)\s*>", base)
                    if inner:
                        stated.append(inner.group(1))
            consistent = bool(guard and compared and compared.group(1) in stated)
            records.append({
                "component": component["component"],
                "repository": component["repository"],
                "commit": component["commit"],
                "file": item["file"], "line": item["line"], "rule_id": item["rule_id"],
                "symbol": item["baseline_symbol"],
                "file_sha256": hashlib.sha256(raw).hexdigest(),
                "file_sha256_is_the_bound_one": hashlib.sha256(raw).hexdigest()
                == next((row[3] for row in component["removed"]
                         if row[0] == item["file"] and row[1] == item["line"]), ""),
                "definition": {"qualified": entry[0], "lines": [entry[1], entry[2]]}
                if entry else None,
                "definition_matches_the_candidate_symbol": bool(named),
                "reported_under_entry": entry_symbol,
                "entry_definition": {"qualified": guard_container[0],
                                     "lines": [guard_container[1], guard_container[2]]}
                if guard_container else None,
                "entry_def_matches_the_reported_entry": bool(guard_container),
                "entry_reaches_the_candidate_at_line": reached_at,
                "read_token_line": statement[:160],
                "guard_line": guard + 1 if guard is not None else None,
                "guard_text": lines[guard].strip() if guard is not None else "",
                "guard_is_an_if": bool(guard is not None and "if" in lines[guard]),
                "guard_precedes_the_candidate": bool(guard is not None and guard + 1 < item["line"]),
                "mismatch_branch": [text.strip() for text in
                                    lines[guard + 1:guard + 5]] if guard is not None else [],
                "compared_interface": compared.group(1) if compared else "",
                "class_states": [{"declared_at": d["file"] + ":" + str(d["line"]),
                                  "bases": d["bases"]} for d in declarations],
                "class_implements": stated,
                "identity_agrees_with_the_guard": consistent,
            })
    if len(sys.argv) > 3:
        pathlib.Path(sys.argv[3]).write_text(
            json.dumps(records, ensure_ascii=False, indent=2) + "\n")
    else:
        print(json.dumps(records, ensure_ascii=False, indent=2))
    # a single line per removal for reading
    for record in records:
        print("%-42s:%-4d %-30s entry=%-32s guard=%-4s via=%-5s agrees=%-5s "
              "precedes=%-5s rejects=%-5s sha_ok=%s"
              % (record["file"].split("/")[-1], record["line"],
                 record["symbol"].split("::")[-1],
                 record["reported_under_entry"].split("::")[-1],
                 record["guard_line"], record["entry_reaches_the_candidate_at_line"],
                 record["identity_agrees_with_the_guard"],
                 record["guard_precedes_the_candidate"],
                 "return" in " ".join(record["mismatch_branch"]),
                 record["file_sha256_is_the_bound_one"]))


if __name__ == "__main__":
    main()
