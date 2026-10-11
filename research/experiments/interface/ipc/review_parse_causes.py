"""Reproduce the partial-parse cause with the project's own parser settings."""
import subprocess
import sys

sys.path.insert(0, ".")
from src.parser.ast import _CPP_PARSER  # noqa: E402  (matches production settings)

CASES = [
    ("/tmp/newcomp/communication_dsoftbus", "652f88e0261ce4d0610f73cc451c26b84d2597af",
     "core/frame/standard/init/src/softbus_server_stub.cpp"),
    ("/home/audit/openharmony-audit/perf-corpus/window_window_manager",
     "8b0d8fe1b973d865904c942c286b3d2a3b9b08e7",
     "window_scene/screen_session_manager/src/zidl/screen_session_manager_stub.cpp"),
    ("/home/audit/openharmony-audit/perf-corpus/update_updateservice",
     "e4942a33cc5ed29040e5c720bea3b2a8e4a79221",
     "services/engine/src/update_service_stub.cpp"),
]

for repo, sha, path in CASES:
    blob = subprocess.run(["git", "-C", repo, "show", sha + ":" + path],
                          capture_output=True).stdout
    tree = _CPP_PARSER.parse(blob)
    lines = blob.decode("utf-8", "replace").splitlines()
    print("===", path)
    print("    has_error:", tree.root_node.has_error, "| bytes:", len(blob))

    def walk(node):
        if node.is_error or node.is_missing:
            text = ""
            try:
                text = blob[node.start_byte:node.end_byte].decode("utf-8", "replace")
            except Exception:
                pass
            yield node.start_point[0] + 1, " ".join(text.split())[:70]
        for child in node.children:
            yield from walk(child)

    seen = list(walk(tree.root_node))
    for line, text in seen[:12]:
        print("    ERROR line %-6d %s" % (line, text))
    print("    total error nodes:", len(seen))
