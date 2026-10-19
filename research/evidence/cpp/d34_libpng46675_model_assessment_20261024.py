"""Replay and assess the generic resource-lifetime model for libpng 46675.

The source Git mirror is read-only. This records production CLI and exact
function-fragment results without adding upstream source files to this repo.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.resource_lifetime_detector import CppResourceLifetimeDetector
from src.parser.ast import parse_source


EXPECTED = {
    "vulnerable": {
        "commit": "c3e304954a9cfd154bc0dfbfea2b01cd61d6546d",
        "tree": "e01f5780f93eaa6d74cca003bb39b427c8f1e910",
        "files": {
            "pngrutil.c": ("a4eda54c8cb3d36cf1651dba159067b65030e3aa", "b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e"),
            "pngread.c": ("af2f44c9ca8eaa40177b2ae5612c0eccc0f625a5", "feee8bdd4c553cc4f01bb288a868d4b83e1ce0f75014a96163a49eb32119cba6"),
            "pngstruct.h": ("fe5fa0415548d8dea33c7417b66a6dd07e3f6857", "3f3ee0f323c4ff02a82db945aafe31b738b31f81c8a4d765df6ed75ae8e205eb"),
            "pngpriv.h": ("f91666c700093f4d5db04eb4e4888671b39f28b8", "def8dd30f3ea2c59f811460a535ba6c8d51ca71bfb70e7f9ccf75b9c791eef2f"),
        },
    },
    "fixed": {
        "commit": "aa77ef38c17ab2fc1b41bec09fb973c6a386641d",
        "tree": "4c64b5f18cef7d129adee3b403fc4be93f82e30d",
        "files": {
            "pngrutil.c": ("482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a", "a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e"),
        },
    },
}
TARGETS = (
    "png_inflate_claim", "png_inflate", "png_decompress_chunk", "png_inflate_read",
    "png_handle_iCCP", "png_handle_zTXt", "png_read_IDAT_data",
)


def git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        env={**__import__("os").environ, "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""},
    )
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace")[:500])
    return result.stdout


def pinned_source(repo: Path, variant: str, path: str) -> tuple[bytes, dict]:
    expected = EXPECTED[variant]
    data = git(repo, "show", f"{expected['commit']}:{path}")
    oid = git(repo, "rev-parse", f"{expected['commit']}:{path}").decode().strip()
    digest = hashlib.sha256(data).hexdigest()
    want_oid, want_hash = expected["files"][path]
    if oid != want_oid or digest != want_hash:
        raise ValueError(f"source identity mismatch for {variant}/{path}")
    return data, {"path": path, "blob": oid, "sha256": digest, "bytes": len(data)}


def parse_summary(data: bytes) -> dict:
    parsed = parse_source(data.decode("utf-8"), language="c")
    return {
        "parse_status": parsed.parse_status,
        "parse_issue_count": len(parsed.parse_issues),
        "function_count": len(parsed.functions),
        "call_site_count": len(parsed.calls),
        "variable_declaration_count": len(parsed.variables),
        "call_site_has_enclosing_function": False,
        "call_site_has_resolved_callee_or_parameter_type": False,
    }


def run_fragment(data: bytes, variant: str, name: str) -> dict:
    source = data.decode("utf-8")
    index = parse_source(source, language="c")
    matches = [fn for fn in index.functions if fn.name == name]
    if len(matches) != 1:
        raise ValueError(f"expected one AST definition for {variant}/{name}, got {len(matches)}")
    function = matches[0]
    lines = source.splitlines(keepends=True)
    fragment_text = "".join(line if function.start_line <= number <= function.end_line else "\n"
                             for number, line in enumerate(lines, 1))
    fragment_hash = hashlib.sha256(fragment_text.encode("utf-8")).hexdigest()
    fragment_index = parse_source(fragment_text, language="c")
    unit = SourceUnit(
        path=f"{variant}/pngrutil.c#{name}", language="c", text=fragment_text,
        sha256=fragment_hash, parse_status=fragment_index.parse_status,
        parse_issues=tuple(json.dumps(issue, sort_keys=True) for issue in fragment_index.parse_issues),
    )
    request = ScanRequest(
        request_id=f"d34:46675:{variant}:{name}", repository="pnggroup/libpng",
        commit=EXPECTED[variant]["commit"], snapshot_sha256=fragment_hash,
        target_id="current-component:pnggroup/libpng", profile_id="exact-function-fragment-light-ast",
        provenance="fixture",
    )
    detector = CppResourceLifetimeDetector()
    result = detector.detect(ScanContext(request=request, units=(unit,)), (unit,))
    return {
        "function": name, "line_start": function.start_line, "line_end": function.end_line,
        "fragment_sha256": fragment_hash, "parent_parse_status": index.parse_status,
        "fragment_parse_status": fragment_index.parse_status,
        "fragment_parse_issue_count": len(fragment_index.parse_issues),
        "detector": detector.detector_id, "detector_version": detector.version,
        "run_status": result.status, "finding_count": len(result.findings),
        "finding_rule_ids": [finding.rule_id for finding in result.findings],
    }


def cli_replay(repo: Path, variant: str) -> dict:
    with tempfile.TemporaryDirectory(prefix=f"d34-{variant}-") as tmp:
        root = Path(tmp)
        command = [
            sys.executable, "-m", "src.cli.main", "ohscan-run", "--repo-dir", str(repo),
            "--repository", "pnggroup/libpng", "--commit", EXPECTED[variant]["commit"],
            "--include", "pngrutil.c", "--detector", "ohscanner.cpp.resource_lifetime",
            "--json-out", str(root / "report.json"), "--md-out", str(root / "report.md"),
        ]
        run = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        if run.returncode:
            raise RuntimeError(f"CLI failed ({run.returncode}): {run.stdout}\n{run.stderr}")
        report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    detector = report["detector_coverage"]["detectors"]["ohscanner.cpp.resource_lifetime"]
    tool = next(item for item in report["detector_runs"] if item["tool"] == "ohscanner.cpp.resource_lifetime")
    return {
        "command": "python -m src.cli.main ohscan-run --repo-dir <pinned-libpng-git> --repository pnggroup/libpng --commit <commit> --include pngrutil.c --detector ohscanner.cpp.resource_lifetime",
        "commit": report["commit"], "tree": report["git_tree"],
        "snapshot_sha256": report["snapshot_sha256"], "scope_files": report["scope"]["selected_source_files"],
        "scope_bytes": report["scope"]["selected_source_bytes"],
        "source_sha256": detector["source_sha256"]["pngrutil.c"],
        "parse_status": report["source_parsing"]["parsing_status"],
        "detector_version": tool["tool_version"], "detector_status": tool["status"],
        "finding_count": tool["diagnostic_count"], "coverage_status": detector["status"],
        "coverage_counts": detector["coverage_counts"],
        "limitations": detector["unexamined"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "research/evidence/cpp/d34_libpng46675_model_assessment_20261024.json")
    args = parser.parse_args()
    source_repo = args.source_git_dir.resolve()
    identities = {}
    parse = {}
    fragments = {}
    cli = {}
    for variant in ("vulnerable", "fixed"):
        commit = EXPECTED[variant]["commit"]
        tree = git(source_repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
        if tree != EXPECTED[variant]["tree"]:
            raise ValueError(f"tree mismatch for {variant}: {tree}")
        file_data = {}
        identities[variant] = {"commit": commit, "tree": tree, "files": {}}
        for path in EXPECTED[variant]["files"]:
            data, identity = pinned_source(source_repo, variant, path)
            file_data[path] = data
            identities[variant]["files"][path] = identity
        if variant == "vulnerable":
            for path in ("pngread.c", "pngstruct.h", "pngpriv.h"):
                if path in file_data:
                    parse[path] = parse_summary(file_data[path])
                else:
                    data, identity = pinned_source(source_repo, variant, path)
                    identities[variant]["files"][path] = identity
                    parse[path] = parse_summary(data)
        parse[f"{variant}/pngrutil.c"] = parse_summary(file_data["pngrutil.c"])
        fragments[variant] = [run_fragment(file_data["pngrutil.c"], variant, name) for name in TARGETS]
        cli[variant] = cli_replay(source_repo, variant)
    evidence = {
        "schema_version": 1,
        "experiment": "D34_generic_resource_lifetime_model_assessment",
        "baseline": "1cb2178c88715b6c8f908ac7826cb684a35730f7",
        "detector": "ohscanner.cpp.resource_lifetime",
        "detector_version": CppResourceLifetimeDetector.version,
        "source_repository": "pnggroup/libpng",
        "source_identities": identities,
        "production_cli": cli,
        "parser_summary": parse,
        "fragments": fragments,
        "source_model_assessment": {
            "source_level_same_object_evidence": [
                "Pinned pngstruct.h declares zowner and z_stream zstream as members of png_struct.",
                "png_inflate_claim, png_decompress_chunk and png_read_IDAT_data accept the library's png_structrp png_ptr parameter and access png_ptr->zstream fields.",
                "png_decompress_chunk transfers/frees its old read_buffer-derived buffer, then vulnerable source clears zowner without clearing zstream.next_in/avail_in; png_read_IDAT_data refills only when avail_in == 0 and otherwise reaches inflate with retained stream fields.",
                "png_read_info dispatches chunks through png_handle_chunk; png_read_end calls png_read_finish_IDAT; png_read_finish_IDAT calls png_read_IDAT_data. These source edges make the reported order plausible but do not prove an application-specific path or trigger.",
                "The exact fixed pngrutil.c adds png_inflate_detach_buffers and invokes it at ownership/release transitions, including the relevant chunk and IDAT paths.",
            ],
            "current_parser_proves_interprocedural_same_object_field_reuse": False,
            "reasons": [
                "The production scope contains only pngrutil.c; required caller/callee edges in pngread.c and zstream field declarations in pngstruct.h/pngpriv.h are outside the scanned scope.",
                "The full target translation unit and the relevant headers/caller file parse partial.",
                "AstIndex CallSite records callee spelling, argument text and location but not enclosing function, resolved function/type identity, field SSA/alias state, path feasibility, or call order across translation units.",
                "The standalone iCCP fragment is partial; six complete fragments omit declarations and do not constitute whole-program or interprocedural proof.",
                "A rule based only on repeated identifier spelling, known function names, CVE, repository or source hash would violate the generic evidence requirement and is not justified.",
            ],
            "decision": "NO_RULE_CHANGE_PARTIAL_BLOCK",
            "next_generic_capability": "A reviewed interprocedural resource-state model that binds parameter types and object identity, associates calls with enclosing functions, propagates field writes/clears and ownership transitions over bounded direct-call paths, and records parse/context unknowns. Validate it on multiple independently sourced lifecycle cases before enabling findings; keep this D34 exact pair as holdout after rule design.",
        },
        "limitations": [
            "Source-level structure is manually corroborated against pinned source objects, not a compiler-resolved call graph.",
            "No detector change means no positive/fixed differential is established; both zero-finding CLI outcomes are blocked/partial, not safe or fixed passes.",
            "Product build/configuration, malformed-chunk trigger feasibility, product reachability, runtime behavior and impact were not tested.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "detector_version": evidence["detector_version"],
                      "cli": {v: {"status": x["detector_status"], "coverage": x["coverage_status"], "findings": x["finding_count"]}
                              for v, x in cli.items()},
                      "fragments": {v: {"complete": sum(x["fragment_parse_status"] == "complete" for x in rows),
                                        "partial": sum(x["fragment_parse_status"] == "partial" for x in rows),
                                        "findings": sum(x["finding_count"] for x in rows)} for v, rows in fragments.items()},
                      "decision": evidence["source_model_assessment"]["decision"]}, indent=2))


if __name__ == "__main__":
    main()
