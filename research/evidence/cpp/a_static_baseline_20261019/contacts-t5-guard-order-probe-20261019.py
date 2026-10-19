"""Read-only T5 probe for path separator guard polarity and sink ordering."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from tests.detectors.test_cpp_path_traversal_detector import SOURCE_AND_FILE_FLOW, _context, _unit
from src.ohscanner.detectors.cpp.path_traversal_detector import CppPathTraversalDetector


BASE = (
    SOURCE_AND_FILE_FLOW
    .replace(
        "void OpenPath(const std::string &path) { open(path.c_str(), O_RDONLY); }",
        "void OpenPath(const std::string &path) { open(path.c_str(), O_RDONLY); unlink(path.c_str()); }",
    )
    .replace("void RemovePath(const std::string &path) { unlink(path.c_str()); }", "void RemovePath(const std::string &path) {}")
)


CASES = {
    "reject_found_before_both_sinks": (
        'if (path.find_first_of("/\\\\") != std::string::npos) return; '
        "open(path.c_str(), O_RDONLY); unlink(path.c_str());",
        0,
    ),
    "reject_found_between_sinks": (
        'open(path.c_str(), O_RDONLY); if (path.find_first_of("/\\\\") != std::string::npos) return; '
        "unlink(path.c_str());",
        1,
    ),
    "reject_found_after_both_sinks": (
        'open(path.c_str(), O_RDONLY); unlink(path.c_str()); '
        'if (path.find_first_of("/\\\\") != std::string::npos) return;',
        2,
    ),
    "reversed_guard_before_both_sinks": (
        'if (path.find_first_of("/\\\\") == std::string::npos) return; '
        "open(path.c_str(), O_RDONLY); unlink(path.c_str());",
        2,
    ),
}


def main() -> None:
    detector = CppPathTraversalDetector()
    for name, (body, expected) in CASES.items():
        source = BASE.replace(
            "void OpenPath(const std::string &path) { open(path.c_str(), O_RDONLY); unlink(path.c_str()); }",
            "void OpenPath(const std::string &path) { " + body + " }",
        )
        unit = _unit(source, name + ".cpp")
        run = detector.detect(_context(unit), (unit,))
        actual = len(run.findings)
        print(f"{name}: expected={expected} actual={actual} findings={[f.line for f in run.findings]}")

    different_parameter = BASE.replace(
        "void OpenPath(const std::string &path) { open(path.c_str(), O_RDONLY); unlink(path.c_str()); }",
        'void OpenPath(const std::string &path, const std::string &other) { '
        'if (other.find_first_of("/\\\\") != std::string::npos) return; '
        "open(path.c_str(), O_RDONLY); unlink(path.c_str()); }",
    ).replace("OpenPath(sourcePath);", "OpenPath(sourcePath, filename);")
    unit = _unit(different_parameter, "guard_other_tainted_parameter.cpp")
    run = detector.detect(_context(unit), (unit,))
    print(f"guard_other_tainted_parameter: expected=2 actual={len(run.findings)} findings={[(f.symbol, f.line) for f in run.findings]}")

    unrelated_receiver = BASE.replace(
        "void OpenPath(const std::string &path) { open(path.c_str(), O_RDONLY); unlink(path.c_str()); }",
        'void OpenPath(const std::string &path) { '
        'if (other.find_first_of("/\\\\") != std::string::npos || path.empty()) return; '
        "open(path.c_str(), O_RDONLY); unlink(path.c_str()); }",
    )
    unit = _unit(unrelated_receiver, "unrelated_receiver_boolean.cpp")
    run = detector.detect(_context(unit), (unit,))
    print(f"unrelated_receiver_boolean: expected=2 actual={len(run.findings)} findings={[(f.symbol, f.line) for f in run.findings]}")


if __name__ == "__main__":
    main()
